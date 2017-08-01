package main

import (
	"fmt"
	"flag"
	"log"
	"math/rand"
	"time"
	"os"
	"os/signal"
	"syscall"
	"io/ioutil"
	"gopkg.in/yaml.v2"
	"errors"
	//注册数据库驱动
	_"github.com/MXi4oyu/DockerXScan/database/pgsql"
	"github.com/MXi4oyu/DockerXScan/database"
	"github.com/MXi4oyu/DockerXScan/common/stopper"
	"github.com/MXi4oyu/DockerXScan/api"
	"github.com/MXi4oyu/DockerXScan/updater"
	"github.com/MXi4oyu/DockerXScan/notifier"
	"github.com/MXi4oyu/DockerXScan/notification"
	//注册拓展
	_ "github.com/MXi4oyu/DockerXScan/featurefmt/dpkg"
	_ "github.com/MXi4oyu/DockerXScan/featurefmt/apk"
	_ "github.com/MXi4oyu/DockerXScan/featurefmt/rpm"
	_ "github.com/MXi4oyu/DockerXScan/featurens/alpinerelease"
	_ "github.com/MXi4oyu/DockerXScan/featurens/aptsources"
	_ "github.com/MXi4oyu/DockerXScan/featurens/lsbrelease"
	_ "github.com/MXi4oyu/DockerXScan/featurens/osrelease"
	_ "github.com/MXi4oyu/DockerXScan/featurens/redhatrelease"
	_ "github.com/MXi4oyu/DockerXScan/notification/webhook"
	_ "github.com/MXi4oyu/DockerXScan/vulnmdsrc/nvd"
	_ "github.com/MXi4oyu/DockerXScan/vulnsrc/alpine"
	_ "github.com/MXi4oyu/DockerXScan/vulnsrc/debian"
	_ "github.com/MXi4oyu/DockerXScan/vulnsrc/oracle"
	_ "github.com/MXi4oyu/DockerXScan/vulnsrc/rhel"
	_ "github.com/MXi4oyu/DockerXScan/vulnsrc/ubuntu"

)

var ErrDatasourceNotLoaded = errors.New("could not load configuration: no database source specified")

type File struct {
	Clair Config `yaml:"clair"`
}

type Config struct {
	Database database.RegistrableComponentConfig
	Updater  *updater.UpdaterConfig
	Notifier *notification.Config
	API      *api.Config
}

func DefaultConfig() Config  {

	return Config{
		Database:database.RegistrableComponentConfig{
			Type:"pgsql",
		},
	}
}

func LoadConfig(path string) (config *Config, err error) {

	var cfgFile File
	cfgFile.Clair = DefaultConfig()
	if path == "" {
		return &cfgFile.Clair, nil
	}

	f, err := os.Open(os.ExpandEnv(path))
	if err != nil {
		return
	}
	defer f.Close()

	d, err := ioutil.ReadAll(f)
	if err != nil {
		return
	}

	err = yaml.Unmarshal(d, &cfgFile)
	if err != nil {
		return
	}
	config = &cfgFile.Clair
	return
}

//中断
func waitForSignals(signals ...os.Signal) {
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, signals...)
	<-interrupts
}

func Boot(config *Config)  {

	rand.Seed(time.Now().UnixNano())
	st := stopper.NewStopper()

	//打开数据库
	db,err:=database.Open(config.Database)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Start notifier
	st.Begin()
	go notifier.RunNotifier(config.Notifier, db, st)

	// Start API
	st.Begin()
	go api.Run(config.API, db, st)
	st.Begin()
	go api.RunHealth(config.API, db, st)

	//漏洞更新
	st.Begin()
	go updater.RunUpdater(config.Updater,db,st)
	waitForSignals(syscall.SIGINT, syscall.SIGTERM)
	st.Stop()
}

func main()  {

	//解析命令行参数
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagConfigPath := flag.String("config", "/etc/clair/config.yaml", "Load configuration from the specified file.")

	//加载配置文件
	config,err:= LoadConfig(*flagConfigPath)
	if err !=nil{
		fmt.Println(err.Error())
	}

	Boot(config)

}
