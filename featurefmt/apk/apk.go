package apk

import (
	"bufio"
	"bytes"
	"log"
	"github.com/MXi4oyu/DockerXScan/tarutil"
	"github.com/MXi4oyu/DockerXScan/versionfmt"
	"github.com/MXi4oyu/DockerXScan/versionfmt/dpkg"
	"github.com/MXi4oyu/DockerXScan/featurefmt"
	"github.com/MXi4oyu/DockerXScan/database"
)

func init()  {

	featurefmt.RegisterLister("apk",&lister{})
}

type lister struct{}

func (l lister) ListFeatures(files tarutil.FilesMap) (features []database.FeatureVersion,errs error)  {

	file, exists := files["lib/apk/db/installed"]
	if !exists {
		return []database.FeatureVersion{},nil
	}

	pkgSet:=make(map[string]database.FeatureVersion)
	ipkg:= database.FeatureVersion{}

	scanner:=bufio.NewScanner(bytes.NewBuffer(file))

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			continue
		}

		// Parse the package name or version.
		switch {
		case line[:2] == "P:":
			ipkg.Feature.Name = line[2:]
		case line[:2] == "V:":
			version := string(line[2:])
			err := versionfmt.Valid(dpkg.ParserName, version)
			if err != nil {
				log.Println("could not parse package version. skipping")
			} else {
				ipkg.Version = version
			}
		case line == "":
			// Restart if the parser reaches another package definition before
			// creating a valid package.
			ipkg = database.FeatureVersion{}
		}

		// If we have a whole featurefmt, store it in the set and try to parse a new
		// one.
		if ipkg.Feature.Name != "" && ipkg.Version != "" {
			pkgSet[ipkg.Feature.Name+"#"+ipkg.Version] = ipkg
			ipkg = database.FeatureVersion{}
		}
	}

	// Convert the map into a slice.
	pkgs := make([]database.FeatureVersion, 0, len(pkgSet))
	for _, pkg := range pkgSet {
		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil
}

func (l lister) RequiredFilenames() []string {
	return []string{"lib/apk/db/installed"}
}
