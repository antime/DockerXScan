package main

import(
	"io/ioutil"
	"log"
	"flag"
	"github.com/MXi4oyu/DockerXScan/analyzeimages"
	_ "github.com/MXi4oyu/DockerXScan/feature/apk"
	_ "github.com/MXi4oyu/DockerXScan/feature/rpm"
	_ "github.com/MXi4oyu/DockerXScan/feature/dpkg"
)

func main()  {

	// 创建临时目录
	tmpPath, err := ioutil.TempDir("", "docker-images-")
	if err != nil {
		log.Fatalf("Could not create temporary folder: %s", err)
	}
	//defer os.RemoveAll(tmpPath)

	// 解析命令行参数
	imageName:=flag.String("imageName","wordpress","wordpress")
	//分析镜像
	analyzeimages.AnalyzeLocalImage(*imageName,tmpPath)
}