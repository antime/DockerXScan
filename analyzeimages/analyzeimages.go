package analyzeimages

import (
	"os/exec"
	"bytes"
	"errors"
	"log"
	"fmt"
	"os"
	"encoding/json"
	"strings"
	"bufio"
	"github.com/MXi4oyu/DockerXScan/tarutil"
	"github.com/MXi4oyu/DockerXScan/featurefmt"
	"github.com/MXi4oyu/DockerXScan/featurens"
	"github.com/MXi4oyu/DockerXScan/database"
	"github.com/MXi4oyu/DockerXScan/api/v1"
	"net/http"
	"io/ioutil"
	"github.com/kr/text"
	"time"
	"sort"
	"github.com/fatih/color"
	"strconv"
	"net"
)


const (

	postLayerURI = "/v1/layers"
	endpoint ="http://127.0.0.1:6060"
	getLayerFeaturesURI = "/v1/layers/%s?vulnerabilities"
	httpPort            = 9279
)


type vulnerabilityInfo struct {
	vulnerability v1.Vulnerability
	feature       v1.Feature
	severity      database.Severity
}


type By func(v1, v2 vulnerabilityInfo) bool

func (by By) Sort(vulnerabilities []vulnerabilityInfo) {
	ps := &sorter{
		vulnerabilities: vulnerabilities,
		by:              by,
	}
	sort.Sort(ps)
}

type sorter struct {
	vulnerabilities []vulnerabilityInfo
	by              func(v1, v2 vulnerabilityInfo) bool
}

func (s *sorter) Len() int {
	return len(s.vulnerabilities)
}

func (s *sorter) Swap(i, j int) {
	s.vulnerabilities[i], s.vulnerabilities[j] = s.vulnerabilities[j], s.vulnerabilities[i]
}

func (s *sorter) Less(i, j int) bool {
	return s.by(s.vulnerabilities[i], s.vulnerabilities[j])
}


func AnalyzeLocalImage(imageName string, minSeverity database.Severity, endpoint, myAddress, tmpPath string)error   {

	//先将镜像保存到本地临时文件
	log.Printf("Saving %s to local disk (this may take some time)", imageName)
	err := save(imageName, tmpPath)
	if err != nil {
		return fmt.Errorf("Could not save image: %s", err)
	}

	//读取镜像历史
	log.Println("Retrieving image history")
	layerIDs, err := historyFromManifest(tmpPath)

	if err != nil {
		layerIDs, err = historyFromCommand(imageName)
	}
	if err != nil || len(layerIDs) == 0 {
		return fmt.Errorf("Could not get image's history: %s", err)
	}


	// Setup a simple HTTP server if Clair is not local.
	if !strings.Contains(endpoint, "127.0.0.1") && !strings.Contains(endpoint, "localhost") {
		allowedHost := strings.TrimPrefix(endpoint, "http://")
		portIndex := strings.Index(allowedHost, ":")
		if portIndex >= 0 {
			allowedHost = allowedHost[:portIndex]
		}

		log.Printf("Setting up HTTP server (allowing: %s)\n", allowedHost)

		ch := make(chan error)
		go listenHTTP(tmpPath, allowedHost, ch)
		select {
		case err := <-ch:
			return fmt.Errorf("An error occured when starting HTTP server: %s", err)
		case <-time.After(100 * time.Millisecond):
			break
		}

		tmpPath = "http://" + myAddress + ":" + strconv.Itoa(httpPort)
	}



	//分析每一层镜像
	log.Printf("Analyzing %d layers... \n", len(layerIDs))
	for i := 0; i < len(layerIDs); i++ {
		log.Printf("Analyzing %s\n", layerIDs[i])

		if i > 0 {
			err = analyzeLayer(tmpPath+"/"+layerIDs[i]+"/layer.tar", layerIDs[i], layerIDs[i-1])
		} else {
			err = analyzeLayer(tmpPath+"/"+layerIDs[i]+"/layer.tar", layerIDs[i], "")
		}
		if err != nil {
			return fmt.Errorf("Could not analyze layer: %s", err)
		}
	}

	//获取漏洞信息

	log.Println("Retrieving image's vulnerabilities")
	layer, err := getLayer(endpoint, layerIDs[len(layerIDs)-1])
	if err != nil {
		fmt.Errorf("Could not get layer information: %s", err)
	}

	//打印报告

	fmt.Printf("Clair report for image %s (%s)\n", imageName, time.Now().UTC())

	if len(layer.Features) == 0 {
		fmt.Printf("%s No features have been detected in the image. This usually means that the image isn't supported by Clair.\n", color.YellowString("NOTE:"))

		return nil
	}

	isSafe := true
	hasVisibleVulnerabilities := false

	var vulnerabilities = make([]vulnerabilityInfo, 0)
	for _, feature := range layer.Features {
		if len(feature.Vulnerabilities) > 0 {
			for _, vulnerability := range feature.Vulnerabilities {
				severity := database.Severity(vulnerability.Severity)
				isSafe = false

				if minSeverity.Compare(severity) > 0 {
					continue
				}

				hasVisibleVulnerabilities = true
				vulnerabilities = append(vulnerabilities, vulnerabilityInfo{vulnerability, feature, severity})
			}
		}
	}

	// Sort vulnerabilitiy by severity.
	priority := func(v1, v2 vulnerabilityInfo) bool {
		return v1.severity.Compare(v2.severity) >= 0
	}

	By(priority).Sort(vulnerabilities)

	for _, vulnerabilityInfo := range vulnerabilities {
		vulnerability := vulnerabilityInfo.vulnerability
		feature := vulnerabilityInfo.feature
		severity := vulnerabilityInfo.severity

		fmt.Printf("%s (%s)\n", vulnerability.Name, coloredSeverity(severity))

		if vulnerability.Description != "" {
			fmt.Printf("%s\n\n", text.Indent(text.Wrap(vulnerability.Description, 80), "\t"))
		}

		fmt.Printf("\tPackage:       %s @ %s\n", feature.Name, feature.Version)

		if vulnerability.FixedBy != "" {
			fmt.Printf("\tFixed version: %s\n", vulnerability.FixedBy)
		}

		if vulnerability.Link != "" {
			fmt.Printf("\tLink:          %s\n", vulnerability.Link)
		}

		fmt.Printf("\tLayer:         %s\n", feature.AddedBy)
		fmt.Println("")
	}

	if isSafe {
		fmt.Printf("%s No vulnerabilities were detected in your image\n", color.GreenString("Success!"))
	} else if !hasVisibleVulnerabilities {
		fmt.Printf("%s No vulnerabilities matching the minimum severity level were detected in your image\n", color.YellowString("NOTE:"))
	} else {

		return fmt.Errorf("A total of %d vulnerabilities have been detected in your image", len(vulnerabilities))

	}

	return nil

}


func listenHTTP(path, allowedHost string, ch chan error) {
	restrictedFileServer := func(path, allowedHost string) http.Handler {
		fc := func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err == nil && strings.EqualFold(host, allowedHost) {
				http.FileServer(http.Dir(path)).ServeHTTP(w, r)
				return
			}
			w.WriteHeader(403)
		}
		return http.HandlerFunc(fc)
	}

	ch <- http.ListenAndServe(":"+strconv.Itoa(httpPort), restrictedFileServer(path, allowedHost))
}


func getLayer(endpoint, layerID string) (v1.Layer, error) {
	response, err := http.Get(endpoint + fmt.Sprintf(getLayerFeaturesURI, layerID))
	if err != nil {
		return v1.Layer{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		body, _ := ioutil.ReadAll(response.Body)
		err := fmt.Errorf("Got response %d with message %s", response.StatusCode, string(body))
		return v1.Layer{}, err
	}

	var apiResponse v1.LayerEnvelope
	if err = json.NewDecoder(response.Body).Decode(&apiResponse); err != nil {
		return v1.Layer{}, err
	} else if apiResponse.Error != nil {
		return v1.Layer{}, errors.New(apiResponse.Error.Message)
	}

	return *apiResponse.Layer, nil
}

//检测镜像内容
func DetectImageContent(imageFormat, name, path string,parent string) (tarutil.FilesMap, error)  {

	f,err:=os.Open(path)
	defer f.Close()
	if err!=nil{
		fmt.Println("open file error::",err.Error())
	}

	//特征文件
	totalRequiredFiles := append(featurefmt.RequiredFilenames(), featurens.RequiredFilenames()...)
	//var filelists [] string =[]string{"var/lib/dpkg/status","lib/apk/db/installed","var/lib/rpm/Packages"}

	files,err:=tarutil.ExtractFiles(f,totalRequiredFiles)
	if err!=nil{
		fmt.Println("tar file error::",err.Error())
	}
	/*
	for k,v:=range files{

		fmt.Println(k)
		fmt.Println(string(v))
	}
	*/

	return files,err

}

func DetectNamespace(files tarutil.FilesMap, parent *database.Layer)  (namespace *database.Namespace, err error){

	namespace, err = featurens.Detect(files)
	if err != nil {
		return
	}
	if namespace != nil {
		log.Println(namespace.Name)
		return
	}
	if parent != nil {
		namespace = parent.Namespace
		if namespace != nil {
			log.Println(namespace.Name)
			return
		}
		return
	}

	return
}

//分析每一层镜像
func analyzeLayer(path, layerName, parentLayerName string) error {

	//方案二：通过API进行解包

	//将layer.tar发送到服务端

	payload := v1.LayerEnvelope{
		Layer: &v1.Layer{
			Name:       layerName,
			Path:       path,
			ParentName: parentLayerName,
			Format:     "docker",
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	request, err := http.NewRequest("POST", endpoint+postLayerURI, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != 201 {
		body, _ := ioutil.ReadAll(response.Body)
		return fmt.Errorf("Got response %d with message %s", response.StatusCode, string(body))
	}

	//发送layer.tar结束


	/*

	方案一：本地进行解包

	//对layer进行分析
	files,err:=DetectImageContent("docker",layerName,path,parentLayerName)

	//列出namespace
	namespace,_:=featurens.Detect(files)

	if namespace !=nil{
		fmt.Println("namespace.Name:",namespace.Name)
		fmt.Println("namespace.VersionFormat:",namespace.VersionFormat)
		//将namespace信息发送到服务端
	}

	//列出特征版本
	featureversions,err:= featurefmt.ListFeatures(files)
	for i,v :=range featureversions{
		//发送特征到服务器
		//发送特征版本到服务器
		fmt.Println(i,v)


	}


	 */



	return err
}

func historyFromCommand(imageName string) ([]string, error) {
	var stderr bytes.Buffer
	cmd := exec.Command("docker", "history", "-q", "--no-trunc", imageName)
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return []string{}, err
	}

	err = cmd.Start()
	if err != nil {
		return []string{}, errors.New(stderr.String())
	}

	var layers []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		layers = append(layers, scanner.Text())
	}

	for i := len(layers)/2 - 1; i >= 0; i-- {
		opp := len(layers) - 1 - i
		layers[i], layers[opp] = layers[opp], layers[i]
	}

	return layers, nil
}

func historyFromManifest(path string) ([]string, error) {
	mf, err := os.Open(path + "/manifest.json")
	if err != nil {
		return nil, err
	}
	defer mf.Close()

	// https://github.com/docker/docker/blob/master/image/tarexport/tarexport.go#L17
	type manifestItem struct {
		Config   string
		RepoTags []string
		Layers   []string
	}

	var manifest []manifestItem
	if err = json.NewDecoder(mf).Decode(&manifest); err != nil {
		return nil, err
	} else if len(manifest) != 1 {
		return nil, err
	}
	var layers []string
	for _, layer := range manifest[0].Layers {
		layers = append(layers, strings.TrimSuffix(layer, "/layer.tar"))
	}
	return layers, nil
}

//保存镜像到本地
func save(imageName, path string) error {
	var stderr bytes.Buffer
	save := exec.Command("docker", "save", imageName)
	save.Stderr = &stderr
	extract := exec.Command("tar", "xf", "-", "-C"+path)
	extract.Stderr = &stderr
	pipe, err := extract.StdinPipe()
	if err != nil {
		return err
	}
	save.Stdout = pipe

	err = extract.Start()
	if err != nil {
		return errors.New(stderr.String())
	}
	err = save.Run()
	if err != nil {
		return errors.New(stderr.String())
	}
	err = pipe.Close()
	if err != nil {
		return err
	}
	err = extract.Wait()
	if err != nil {
		return errors.New(stderr.String())
	}

	return nil
}


func coloredSeverity(severity database.Severity) string {
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc()

	switch severity {
	case database.HighSeverity, database.CriticalSeverity:
		return red(severity)
	case database.MediumSeverity:
		return yellow(severity)
	default:
		return white(severity)
	}
}