package dpkg

import (
	"bufio"
	"strings"
	"regexp"
	"log"
	"github.com/MXi4oyu/DockerXScan/tarutil"
	"github.com/MXi4oyu/DockerXScan/featurefmt"
	"github.com/MXi4oyu/DockerXScan/versionfmt"
	"github.com/MXi4oyu/DockerXScan/versionfmt/dpkg"
)

var (
	dpkgSrcCaptureRegexp      = regexp.MustCompile(`Source: (?P<name>[^\s]*)( \((?P<version>.*)\))?`)
	dpkgSrcCaptureRegexpNames = dpkgSrcCaptureRegexp.SubexpNames()
)
type lister struct{}

func init()  {
	featurefmt.RegisterLister("dpkg",&lister{})
}

func (l lister) ListFeatures(files tarutil.FilesMap) (features []featurefmt.FeatureVersion,errs error) {
	f, hasFile := files["var/lib/dpkg/status"]

	if !hasFile{
		return []featurefmt.FeatureVersion{},nil
	}
	// Create a map to store packages and ensure their uniqueness
	packagesMap:=make(map[string]featurefmt.FeatureVersion)

	var pkg featurefmt.FeatureVersion
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
	packages := make([]featurefmt.FeatureVersion, 0, len(packagesMap))
	for _, pkg := range packagesMap {
		packages = append(packages, pkg)
	}
	return packages, nil
}