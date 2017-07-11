package featurens

import (
	"sync"
	"github.com/MXi4oyu/DockerXScan/database"
	"github.com/MXi4oyu/DockerXScan/tarutil"
	"log"
)

var (
	detectorsM sync.RWMutex
	detectors  = make(map[string]Detector)
)

type Detector interface {
	// Detect attempts to determine a Namespace from a FilesMap of an image
	// layer.
	Detect(tarutil.FilesMap) (*database.Namespace, error)

	// RequiredFilenames returns the list of files required to be in the FilesMap
	// provided to the Detect method.
	//
	// Filenames must not begin with "/".
	RequiredFilenames() []string
}

//注册
func RegisterDetector(name string, d Detector) {
	if name == "" {
		panic("namespace: could not register a Detector with an empty name")
	}
	if d == nil {
		panic("namespace: could not register a nil Detector")
	}

	detectorsM.Lock()
	defer detectorsM.Unlock()

	if _, dup := detectors[name]; dup {
		panic("namespace: RegisterDetector called twice for " + name)
	}

	detectors[name] = d
}

func Detect(files tarutil.FilesMap) (*database.Namespace, error) {
	detectorsM.RLock()
	defer detectorsM.RUnlock()

	for name, detector := range detectors {
		namespace, err := detector.Detect(files)
		if err != nil {
			log.Println("failed while attempting to detect namespace")
			return nil, err
		}

		if namespace != nil {
			log.Println("name:"+name)
			return namespace, nil
		}
	}

	return nil, nil
}

// RequiredFilenames returns the total list of files required for all
// registered Detectors.
func RequiredFilenames() (files []string) {
	detectorsM.RLock()
	defer detectorsM.RUnlock()

	for _, detector := range detectors {
		files = append(files, detector.RequiredFilenames()...)
	}

	return
}