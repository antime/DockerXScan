package alpinerelease

import (
	"regexp"
	"bufio"
	"strings"
	"bytes"
	"github.com/MXi4oyu/DockerXScan/tarutil"
	"github.com/MXi4oyu/DockerXScan/versionfmt/dpkg"
	"github.com/MXi4oyu/DockerXScan/featurens"
	"github.com/MXi4oyu/DockerXScan/database"
)

const (
	osName            = "alpine"
	alpineReleasePath = "etc/alpine-release"
)

var versionRegexp = regexp.MustCompile(`^(\d)+\.(\d)+\.(\d)+$`)

func init() {
	featurens.RegisterDetector("alpine-release", &detector{})
}

type detector struct{}

func (d detector) Detect(files tarutil.FilesMap) (*database.Namespace, error) {
	file, exists := files[alpineReleasePath]
	if exists {
		scanner := bufio.NewScanner(bytes.NewBuffer(file))
		for scanner.Scan() {
			line := scanner.Text()
			match := versionRegexp.FindStringSubmatch(line)
			if len(match) > 0 {
				versionNumbers := strings.Split(match[0], ".")
				return &database.Namespace{
					Name:          osName + ":" + "v" + versionNumbers[0] + "." + versionNumbers[1],
					VersionFormat: dpkg.ParserName,
				}, nil
			}
		}
	}

	return nil, nil
}

func (d detector) RequiredFilenames() []string {
	return []string{alpineReleasePath}
}