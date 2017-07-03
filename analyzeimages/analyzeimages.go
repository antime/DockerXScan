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
	"github.com/coreos/clair/ext/imagefmt"
	"io"
	"github.com/coreos/clair/pkg/tarutil"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/featurens"
)


//支持docker格式和aci格式
type format struct{}

func init() {
	imagefmt.RegisterExtractor("docker", &format{})
	imagefmt.RegisterExtractor("aci", &format{})
}
//提取镜像
func (f format) ExtractFiles(layerReader io.ReadCloser, toExtract []string) (tarutil.FilesMap, error) {
	return tarutil.ExtractFiles(layerReader, toExtract)
}

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
func DetectImageContent(imageFormat, name, path string, headers map[string]string,parent string)  {
	totalRequiredFiles := append(featurefmt.RequiredFilenames(), featurens.RequiredFilenames()...)
	files, err := imagefmt.Extract(imageFormat, path, headers, totalRequiredFiles)
	if err!=nil{
		fmt.Println("imagefmt.Extract Error::",err.Error())
	}

	fmt.Println(files)

}

//分析每一层镜像
func analyzeLayer(path, layerName, parentLayerName string) error {

	//对layer进行分析

	return nil
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