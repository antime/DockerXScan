package dpkg

import (
	"bufio"
	"regexp"
	"strings"
	//"github.com/MXi4oyu/DockerXScan/feature"
	"github.com/MXi4oyu/DockerXScan/tarutil"
	"errors"
	"log"
	"fmt"
	"reflect"
	"github.com/MXi4oyu/DockerXScan/feature"
)

var (
	dpkgSrcCaptureRegexp      = regexp.MustCompile(`Source: (?P<name>[^\s]*)( \((?P<version>.*)\))?`)
	dpkgSrcCaptureRegexpNames = dpkgSrcCaptureRegexp.SubexpNames()
)

//特征
type Feature struct {
	Name      string
	Namespace string
}

//特征版本
type FeatureVersion struct {
	Feature    Feature
	Version    string
}


type lister struct{}

func init() {
	feature.RegisterLister("dpkg", &lister{})
}

func TestLister()  {

	fmt.Println(reflect.TypeOf(&lister{}))
}

func (l lister) RequiredFilenames() []string {
	return []string{"var/lib/dpkg/status"}
}

func (l lister) ListFeatures(files tarutil.FilesMap) (features []FeatureVersion,errs error) {
	f, hasFile := files["var/lib/dpkg/status"]
	if !hasFile {
		return []FeatureVersion{}, nil
	}

	// Create a map to store packages and ensure their uniqueness
	packagesMap := make(map[string]FeatureVersion)

	var pkg FeatureVersion
	var err error
	scanner := bufio.NewScanner(strings.NewReader(string(f)))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "Package: ") {
			// Package line
			// Defines the name of the package

			pkg.Feature.Name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
			pkg.Version = ""
		} else if strings.HasPrefix(line, "Source: ") {
			// Source line (Optionnal)
			// Gives the name of the source package
			// May also specifies a version

			srcCapture := dpkgSrcCaptureRegexp.FindAllStringSubmatch(line, -1)[0]
			md := map[string]string{}
			for i, n := range srcCapture {
				md[dpkgSrcCaptureRegexpNames[i]] = strings.TrimSpace(n)
			}

			pkg.Feature.Name = md["name"]
			if md["version"] != "" {
				version := md["version"]
				err = errors.New("invalid version")
				if err != nil {
					log.Println("could not parse package version. skipping")
				} else {
					pkg.Version = version
				}
			}
		} else if strings.HasPrefix(line, "Version: ") && pkg.Version == "" {
			// Version line
			// Defines the version of the package
			// This version is less important than a version retrieved from a Source line
			// because the Debian vulnerabilities often skips the epoch from the Version field
			// which is not present in the Source version, and because +bX revisions don't matter
			version := strings.TrimPrefix(line, "Version: ")
			//验证版本
			err =nil
			if err != nil {
				log.Println("could not parse package version. skipping")
			} else {
				pkg.Version = version
			}
		} else if line == "" {
			pkg.Feature.Name = ""
			pkg.Version = ""
		}

		// Add the package to the result array if we have all the informations
		if pkg.Feature.Name != "" && pkg.Version != "" {
			packagesMap[pkg.Feature.Name+"#"+pkg.Version] = pkg
			pkg.Feature.Name = ""
			pkg.Version = ""
		}
	}

	// Convert the map to a slice
	packages := make([]FeatureVersion, 0, len(packagesMap))
	for _, pkg := range packagesMap {
		packages = append(packages, pkg)
	}

	return packages, nil
}


