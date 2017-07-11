package featurefmt

import (
	"sync"
	"github.com/MXi4oyu/DockerXScan/tarutil"
	"github.com/MXi4oyu/DockerXScan/database"
)

var (
	listersM sync.RWMutex
	listers  = make(map[string]Lister)
)

type Lister interface{
	ListFeatures(files tarutil.FilesMap) (features []database.FeatureVersion,errs error)
	RequiredFilenames() []string
}

func ListFeatures(files tarutil.FilesMap)(features []database.FeatureVersion,errs error){
	listersM.RLock()
	defer listersM.RUnlock()
	var totalFeatures []database.FeatureVersion
	for _, lister := range listers {
		features, err := lister.ListFeatures(files)
		if err != nil {
			return []database.FeatureVersion{}, err
		}
		totalFeatures = append(totalFeatures, features...)
	}

	return totalFeatures, nil
}

func RequiredFilenames() (files []string) {
	listersM.RLock()
	defer listersM.RUnlock()

	for _, lister := range listers {
		files = append(files, lister.RequiredFilenames()...)
	}

	return
}

func RegisterLister(name string, l Lister) {
	if name == "" {
		panic("featurefmt: could not register a Lister with an empty name")
	}
	if l == nil {
		panic("featurefmt: could not register a nil Lister")
	}

	listersM.Lock()
	defer listersM.Unlock()

	if _, dup := listers[name]; dup {
		panic("featurefmt: RegisterLister called twice for " + name)
	}

	listers[name] = l
}