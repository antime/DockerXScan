package main

import (
	"fmt"
	//注册数据库驱动
	_ "github.com/MXi4oyu/DockerXScan/database/pgsql"
	"flag"
	"github.com/MXi4oyu/DockerXScan/database"
	"github.com/MXi4oyu/DockerXScan/common/stopper"
	"log"
	"math/rand"
	"time"
	"os"
	"os/signal"
	"syscall"
)

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
	st.Begin()
	fmt.Println("testing...")
	waitForSignals(syscall.SIGINT, syscall.SIGTERM)
	st.Stop()
}

func main()  {

	//解析命令行参数
	flagConfigPath := flag.String("config", "/etc/clair/config.yaml", "Load configuration from the specified file.")

	//加载配置文件
	config,err:= LoadConfig(*flagConfigPath)
	if err !=nil{
		fmt.Println(err.Error())
	}

	Boot(config)

}
