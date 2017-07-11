package aptsources

import (
	"bufio"
	"strings"
	"github.com/MXi4oyu/DockerXScan/tarutil"
	"github.com/MXi4oyu/DockerXScan/versionfmt/dpkg"
	"github.com/MXi4oyu/DockerXScan/featurens"
	"github.com/MXi4oyu/DockerXScan/database"
)

type detector struct{}

func init() {
	featurens.RegisterDetector("apt-sources", &detector{})
}

func (d detector) Detect(files tarutil.FilesMap) (*database.Namespace, error) {
	f, hasFile := files["etc/apt/sources.list"]
	if !hasFile {
		return nil, nil
	}

	var OS, version string

	scanner := bufio.NewScanner(strings.NewReader(string(f)))
	for scanner.Scan() {
		// Format: man sources.list | https://wiki.debian.org/SourcesList)
		// deb uri distribution component1 component2 component3
		// deb-src uri distribution component1 component2 component3
		line := strings.Split(scanner.Text(), " ")
		if len(line) > 3 {
			// Only consider main component
			isMainComponent := false
			for _, component := range line[3:] {
				if component == "main" {
					isMainComponent = true
					break
				}
			}
			if !isMainComponent {
				continue
			}

			var found bool
			version, found = database.DebianReleasesMapping[line[2]]
			if found {
				OS = "debian"
				break
			}
			version, found = database.UbuntuReleasesMapping[line[2]]
			if found {
				OS = "ubuntu"
				break
			}
		}
	}

	if OS != "" && version != "" {
		return &database.Namespace{
			Name:          OS + ":" + version,
			VersionFormat: dpkg.ParserName,
		}, nil
	}
	return nil, nil
}

func (d detector) RequiredFilenames() []string {
	return []string{"etc/apt/sources.list"}
}