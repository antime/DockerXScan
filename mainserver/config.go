package main

import (
	"errors"
	"github.com/MXi4oyu/DockerXScan/database"
	"os"
	"io/ioutil"
	"gopkg.in/yaml.v2"
)

var ErrDatasourceNotLoaded = errors.New("could not load configuration: no database source specified")

type File struct {
	Clair Config `yaml:"clair"`
}

type Config struct {
	Database database.RegistrableComponentConfig
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
