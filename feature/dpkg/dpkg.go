package dpkg

import (
	"github.com/MXi4oyu/DockerXScan/tarutil"
	"github.com/MXi4oyu/DockerXScan/feature"
	"bufio"
	"strings"
	"regexp"
	"github.com/MXi4oyu/DockerXScan/versionfmt"
	"github.com/MXi4oyu/DockerXScan/versionfmt/dpkg"
	"log"
)

var (
	dpkgSrcCaptureRegexp      = regexp.MustCompile(`Source: (?P<name>[^\s]*)( \((?P<version>.*)\))?`)
	dpkgSrcCaptureRegexpNames = dpkgSrcCaptureRegexp.SubexpNames()
)
type lister struct{}

func init()  {
	feature.RegisterLister("dpkg",&lister{})
}

func (l lister) ListFeatures(files tarutil.FilesMap) (features []feature.FeatureVersion,errs error) {
	f, hasFile := files["var/lib/dpkg/status"]

	if !hasFile{
		return []feature.FeatureVersion{},nil
	}
	// Create a map to store packages and ensure their uniqueness
	packagesMap:=make(map[string]feature.FeatureVersion)

	var pkg feature.FeatureVersion
	var err error

	scanner := bufio.NewScanner(strings.NewReader(string(f)))

	for scanner.Scan(){
		line:=scanner.Text()

		if strings.HasPrefix(line,"Package: "){
			pkg.Feature.Name=strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
			pkg.Version=""
		}else if strings.HasPrefix(line,"Source: "){

			srcCapture := dpkgSrcCaptureRegexp.FindAllStringSubmatch(line, -1)[0]
			md := map[string]string{}
			for i, n := range srcCapture {
				md[dpkgSrcCaptureRegexpNames[i]] = strings.TrimSpace(n)
			}

			pkg.Feature.Name=md["name"]

			if md["version"] != ""{
				version := md["version"]
				err=versionfmt.Valid(dpkg.ParserName, version)
				if err !=nil{
					log.Println("could not parse package version. skipping")
				}else{
					pkg.Version=version
				}
			}
		}else if strings.HasPrefix(line, "Version: ") && pkg.Version == ""{
			version := strings.TrimPrefix(line, "Version: ")
			err = versionfmt.Valid(dpkg.ParserName, version)
			if err != nil {
				log.Println("could not parse package version. skipping")
			} else {
				pkg.Version = version
			}
		}else if line == "" {
			pkg.Feature.Name = ""
			pkg.Version = ""
		}

		if pkg.Feature.Name != "" && pkg.Version != "" {
			packagesMap[pkg.Feature.Name+"#"+pkg.Version] = pkg
			pkg.Feature.Name = ""
			pkg.Version = ""
		}
	}

	// Convert the map to a slice
	packages := make([]feature.FeatureVersion, 0, len(packagesMap))
	for _, pkg := range packagesMap {
		packages = append(packages, pkg)
	}
	return packages, nil
}