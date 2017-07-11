package redhatrelease

import (
	"strings"
	"github.com/MXi4oyu/DockerXScan/tarutil"
	"github.com/MXi4oyu/DockerXScan/versionfmt/rpm"
	"github.com/MXi4oyu/DockerXScan/featurens"
	"github.com/MXi4oyu/DockerXScan/database"
	"regexp"
)

var (
	oracleReleaseRegexp = regexp.MustCompile(`(?P<os>[^\s]*) (Linux Server release) (?P<version>[\d]+)`)
	centosReleaseRegexp = regexp.MustCompile(`(?P<os>[^\s]*) (Linux release|release) (?P<version>[\d]+)`)
	redhatReleaseRegexp = regexp.MustCompile(`(?P<os>Red Hat Enterprise Linux) (Client release|Server release|Workstation release) (?P<version>[\d]+)`)
)

type detector struct{}

func init() {
	featurens.RegisterDetector("redhat-release", &detector{})
}

func (d detector) Detect(files tarutil.FilesMap) (*database.Namespace, error) {
	for _, filePath := range d.RequiredFilenames() {
		f, hasFile := files[filePath]
		if !hasFile {
			continue
		}

		var r []string

		// Attempt to match Oracle Linux.
		r = oracleReleaseRegexp.FindStringSubmatch(string(f))
		if len(r) == 4 {
			return &database.Namespace{
				Name:          strings.ToLower(r[1]) + ":" + r[3],
				VersionFormat: rpm.ParserName,
			}, nil
		}

		// Attempt to match RHEL.
		r = redhatReleaseRegexp.FindStringSubmatch(string(f))
		if len(r) == 4 {
			// TODO(vbatts): this is a hack until https://github.com/coreos/clair/pull/193
			return &database.Namespace{
				Name:          "centos" + ":" + r[3],
				VersionFormat: rpm.ParserName,
			}, nil
		}

		// Atempt to match CentOS.
		r = centosReleaseRegexp.FindStringSubmatch(string(f))
		if len(r) == 4 {
			return &database.Namespace{
				Name:          strings.ToLower(r[1]) + ":" + r[3],
				VersionFormat: rpm.ParserName,
			}, nil
		}
	}

	return nil, nil
}

func (d detector) RequiredFilenames() []string {
	return []string{"etc/oracle-release", "etc/centos-release", "etc/redhat-release", "etc/system-release"}
}