package api

import (
	"github.com/MXi4oyu/DockerXScan/database"
	"github.com/MXi4oyu/DockerXScan/api/v1"
	"fmt"
	"github.com/fatih/color"
	"github.com/kr/text"
	"sort"
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

type By func(v1, v2 vulnerabilityInfo) bool

func (by By) Sort(vulnerabilities []vulnerabilityInfo) {
	ps := &sorter{
		vulnerabilities: vulnerabilities,
		by:              by,
	}
	sort.Sort(ps)
}

type sorter struct {
	vulnerabilities []vulnerabilityInfo
	by              func(v1, v2 vulnerabilityInfo) bool
}

func (s *sorter) Len() int {
	return len(s.vulnerabilities)
}

func (s *sorter) Swap(i, j int) {
	s.vulnerabilities[i], s.vulnerabilities[j] = s.vulnerabilities[j], s.vulnerabilities[i]
}

func (s *sorter) Less(i, j int) bool {
	return s.by(s.vulnerabilities[i], s.vulnerabilities[j])
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

	//log.Info(vulnerabilities)

	priority := func(v1, v2 vulnerabilityInfo) bool {
		return v1.severity.Compare(v2.severity) >= 0
	}

	By(priority).Sort(vulnerabilities)

	for _, vulnerabilityInfo := range vulnerabilities {
		vulnerability := vulnerabilityInfo.vulnerability
		feature := vulnerabilityInfo.feature
		severity := vulnerabilityInfo.severity

		fmt.Printf("%s (%s)\n", vulnerability.Name, coloredSeverity(severity))

		if vulnerability.Description != "" {
			fmt.Printf("%s\n\n", text.Indent(text.Wrap(vulnerability.Description, 80), "\t"))
		}

		fmt.Printf("\tPackage:       %s @ %s\n", feature.Name, feature.Version)

		if vulnerability.FixedBy != "" {
			fmt.Printf("\tFixed version: %s\n", vulnerability.FixedBy)
		}

		if vulnerability.Link != "" {
			fmt.Printf("\tLink:          %s\n", vulnerability.Link)
		}

		fmt.Printf("\tLayer:         %s\n", feature.AddedBy)
		fmt.Println("")
	}

	if isSafe {
		fmt.Printf("%s No vulnerabilities were detected in your image\n", color.GreenString("Success!"))
	} else if !hasVisibleVulnerabilities {
		fmt.Printf("%s No vulnerabilities matching the minimum severity level were detected in your image\n", color.YellowString("NOTE:"))
	} else {
		fmt.Errorf("A total of %d vulnerabilities have been detected in your image", len(vulnerabilities))
	}

}

func coloredSeverity(severity database.Severity) string {
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc()

	switch severity {
	case database.HighSeverity, database.CriticalSeverity:
		return red(severity)
	case database.MediumSeverity:
		return yellow(severity)
	default:
		return white(severity)
	}
}
