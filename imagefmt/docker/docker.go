package docker

import (
	"io"

	"github.com/MXi4oyu/DockerXScan/imagefmt"
	"github.com/MXi4oyu/DockerXScan/tarutil"
)


type format struct{}

func init() {
	imagefmt.RegisterExtractor("docker", &format{})
}

func (f format) ExtractFiles(layerReader io.ReadCloser, toExtract []string) (tarutil.FilesMap, error) {
	return tarutil.ExtractFiles(layerReader, toExtract)
}