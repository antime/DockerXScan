package api

import (
	"time"
	"github.com/MXi4oyu/DockerXScan/database"
	"github.com/MXi4oyu/DockerXScan/common/stopper"
	"github.com/MXi4oyu/DockerXScan/versionfmt/dpkg"
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
	//插入一条namespace
	store.InsertNamespace(database.Namespace{
		Name:"debian:8",
		VersionFormat:dpkg.ParserName,
	})

	//列出所有的namespace

	namespaces,_:=store.ListNamespaces()
	fmt.Println(namespaces)
	
	//插入一条layer
	store.InsertLayer(database.Layer{
		Name:"77935dbf418a0abf8e9276ef3df3d79af1f3afded45e1d8a7f87ed6e09057df1",
		ParentID:1,
	})


	defer st.End()
}
