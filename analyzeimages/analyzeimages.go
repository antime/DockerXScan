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
)


func AnalyzeLocalImage(imageName,tmpPath string)  {

	//先将镜像保存到本地临时文件
	log.Printf("Saving %s to local disk (this may take some time)", imageName)
	err := save(imageName, tmpPath)
	if err != nil {
		fmt.Errorf("Could not save image: %s", err)
	}

	//读取镜像历史
	log.Println("Retrieving image history")
	layerIDs, err := historyFromManifest(tmpPath)
	if err != nil {
		layerIDs, err = historyFromCommand(imageName)
	}
	if err != nil || len(layerIDs) == 0 {
		fmt.Errorf("Could not get image's history: %s", err)
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
			fmt.Errorf("Could not analyze layer: %s", err)
		}
	}

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