package api

import (
	"github.com/MXi4oyu/DockerXScan/database"
	"github.com/MXi4oyu/DockerXScan/api/v1"
	"fmt"
	"github.com/prometheus/common/log"
)


type context struct {
	Store         database.Datastore
	PaginationKey string
}

func GetLayer(layerName string,ctx *context) (v1.Layer, error) {

	dbLayer, err := ctx.Store.FindLayer(layerName, true, true)
	if err !=nil{
		return v1.Layer{}, err
	}

	layer := v1.LayerFromDatabaseModel(dbLayer, true, true)
	return layer,nil
}

type vulnerabilityInfo struct {
	vulnerability v1.Vulnerability
	feature       v1.Feature
	severity      database.Severity
}

func ShowVuls(layer v1.Layer,minSeverity database.Severity)  {
	isSafe := true
	hasVisibleVulnerabilities := false
	var vulnerabilities = make([]vulnerabilityInfo, 0)

	for _, feature := range layer.Features {
		if len(feature.Vulnerabilities) > 0 {
			for _, vulnerability := range feature.Vulnerabilities {
				severity := database.Severity(vulnerability.Severity)
				isSafe = false

				if minSeverity.Compare(severity) > 0 {
					continue
				}

				hasVisibleVulnerabilities = true
				vulnerabilities = append(vulnerabilities, vulnerabilityInfo{vulnerability, feature, severity})
			}
		}
	}

	log.Info(vulnerabilities)

	if isSafe {
		fmt.Printf("%s No vulnerabilities were detected in your image\n", color.GreenString("Success!"))
	} else if !hasVisibleVulnerabilities {
		fmt.Printf("%s No vulnerabilities matching the minimum severity level were detected in your image\n", color.YellowString("NOTE:"))
	} else {
		fmt.Errorf("A total of %d vulnerabilities have been detected in your image", len(vulnerabilities))
	}

}
