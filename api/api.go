package api

import (
	"time"
	"github.com/MXi4oyu/DockerXScan/database"
	"github.com/MXi4oyu/DockerXScan/common/stopper"
	_"github.com/MXi4oyu/DockerXScan/versionfmt/dpkg"
	"fmt"
)


type Config struct {
	Port                      int
	HealthPort                int
	Timeout                   time.Duration
	PaginationKey             string
	CertFile, KeyFile, CAFile string
}

func Run(cfg *Config, store database.Datastore, st *stopper.Stopper)  {

	//查询一个layer
	layer,_:=store.FindLayer("77935dbf418a0abf8e9276ef3df3d79af1f3afded45e1d8a7f87ed6e09057df1",false,false)
	fmt.Println(layer)

	defer st.End()
}
