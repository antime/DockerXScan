package aci

import (
	"io"
	"path/filepath"
	"github.com/MXi4oyu/DockerXScan/imagefmt"
	"github.com/MXi4oyu/DockerXScan/tarutil"
)

type format struct{}

func init() {
	imagefmt.RegisterExtractor("aci", &format{})
}

func (f format) ExtractFiles(layerReader io.ReadCloser, toExtract []string) (tarutil.FilesMap, error) {
	// All contents are inside a "rootfs" directory, so this needs to be
	// prepended to each filename.
	var filenames []string
	for _, filename := range toExtract {
		filenames = append(filenames, filepath.Join("rootfs/", filename))
	}

	return tarutil.ExtractFiles(layerReader, filenames)
}