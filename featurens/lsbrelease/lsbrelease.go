package lsbrelease

import (
	"bufio"
	"strings"
	"github.com/MXi4oyu/DockerXScan/tarutil"
	"github.com/MXi4oyu/DockerXScan/versionfmt/rpm"
	"github.com/MXi4oyu/DockerXScan/versionfmt/dpkg"
	"github.com/MXi4oyu/DockerXScan/featurens"
	"github.com/MXi4oyu/DockerXScan/database"
	"regexp"
)


var (
	lsbReleaseOSRegexp      = regexp.MustCompile(`^DISTRIB_ID=(.*)`)
	lsbReleaseVersionRegexp = regexp.MustCompile(`^DISTRIB_RELEASE=(.*)`)
)

type detector struct{}

func init() {
	featurens.RegisterDetector("lsb-release", &detector{})
}

func (d detector) Detect(files tarutil.FilesMap) (*database.Namespace, error) {
	f, hasFile := files["etc/lsb-release"]
	if !hasFile {
		return nil, nil
	}

	var OS, version string

	scanner := bufio.NewScanner(strings.NewReader(string(f)))
	for scanner.Scan() {
		line := scanner.Text()

		r := lsbReleaseOSRegexp.FindStringSubmatch(line)
		if len(r) == 2 {
			OS = strings.Replace(strings.ToLower(r[1]), "\"", "", -1)
		}

		r = lsbReleaseVersionRegexp.FindStringSubmatch(line)
		if len(r) == 2 {
			version = strings.Replace(strings.ToLower(r[1]), "\"", "", -1)

			// We care about the .04 for Ubuntu but not for Debian / CentOS
			if OS == "centos" || OS == "debian" {
				i := strings.Index(version, ".")
				if i >= 0 {
					version = version[:i]
				}
			}
		}
	}

	// Determine the VersionFormat.
	var versionFormat string
	switch OS {
	case "debian", "ubuntu":
		versionFormat = dpkg.ParserName
	case "centos", "rhel", "fedora", "amzn", "ol", "oracle":
		versionFormat = rpm.ParserName
	default:
		return nil, nil
	}

	if OS != "" && version != "" {
		return &database.Namespace{
			Name:          OS + ":" + version,
			VersionFormat: versionFormat,
		}, nil
	}

	return nil, nil
}

func (d *detector) RequiredFilenames() []string {
	return []string{"etc/lsb-release"}
}