package osrelease

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
	osReleaseOSRegexp      = regexp.MustCompile(`^ID=(.*)`)
	osReleaseVersionRegexp = regexp.MustCompile(`^VERSION_ID=(.*)`)

	// blacklistFilenames are files that should exclude this detector.
	blacklistFilenames = []string{
		"etc/oracle-release",
		"etc/redhat-release",
		"usr/lib/centos-release",
	}
)

type detector struct{}

func init() {
	featurens.RegisterDetector("os-release", &detector{})
}

func (d detector) Detect(files tarutil.FilesMap) (*database.Namespace, error) {
	var OS, version string

	for _, filePath := range blacklistFilenames {
		if _, hasFile := files[filePath]; hasFile {
			return nil, nil
		}
	}

	for _, filePath := range d.RequiredFilenames() {
		f, hasFile := files[filePath]
		if !hasFile {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(string(f)))
		for scanner.Scan() {
			line := scanner.Text()

			r := osReleaseOSRegexp.FindStringSubmatch(line)
			if len(r) == 2 {
				OS = strings.Replace(strings.ToLower(r[1]), "\"", "", -1)
			}

			r = osReleaseVersionRegexp.FindStringSubmatch(line)
			if len(r) == 2 {
				version = strings.Replace(strings.ToLower(r[1]), "\"", "", -1)
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

func (d detector) RequiredFilenames() []string {
	return []string{"etc/os-release", "usr/lib/os-release"}
}
