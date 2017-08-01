package api

import (
	"github.com/MXi4oyu/DockerXScan/database"
	"github.com/MXi4oyu/DockerXScan/api/v1"
	"fmt"
	log "github.com/sirupsen/logrus"
)

const (
	getLayerRoute            = "v1/getLayer"
)

type context struct {
	Store         database.Datastore
	PaginationKey string
}

func GetLayer(layerName string,ctx *context) (string, int) {

	dbLayer, err := ctx.Store.FindLayer(layerName, true, true)
	if err !=nil{
		return getLayerRoute,404
	}

	layer := v1.LayerFromDatabaseModel(dbLayer, true, true)
	fmt.Println(&layer)
	log.Info(&layer)
	return getLayerRoute,200
}
