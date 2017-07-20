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
	//插入一个namespace
	store.InsertNamespace(database.Namespace{
		Name:"debian:8",
		VersionFormat:dpkg.ParserName,
	})

	//列出所有的namespace
	namespaces,_:=store.ListNamespaces()
	fmt.Println(namespaces)

	//插入一个layer
	store.InsertLayer(database.Layer{
		Name:"77935dbf418a0abf8e9276ef3df3d79af1f3afded45e1d8a7f87ed6e09057df1",
		ParentID:1,
	})

	//删除一个layer
	//store.DeleteLayer("77935dbf418a0abf8e9276ef3df3d79af1f3afded45e1d8a7f87ed6e09057df1")

	//查询一个layer
	layer,_:=store.FindLayer("77935dbf418a0abf8e9276ef3df3d79af1f3afded45e1d8a7f87ed6e09057df1",false,false)
	fmt.Println(layer)

	//插入一个特征
	feature := database.Feature{
		Namespace:database.Namespace{
			Name:"debian:8",
			VersionFormat:dpkg.ParserName,
		},
		Name:"nginx",
	}
	store.InsertFeature(feature)

	//插入特征版本
	featureVersion := database.FeatureVersion{
		Feature:database.Feature{
			Namespace:database.Namespace{
				Name:"debian:8",
				VersionFormat:dpkg.ParserName,
			},
			Name:"nginx",
		},
		Version:"2.3.0",
	}

	store.InsertFeatureVersion(featureVersion)


	defer st.End()
}
