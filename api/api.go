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

	fmt.Println("test api")

	defer st.End()
}
