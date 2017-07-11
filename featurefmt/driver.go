package featurefmt

import (
	"sync"
	"github.com/MXi4oyu/DockerXScan/tarutil"
)

var (
	listersM sync.RWMutex
	listers  = make(map[string]Lister)
)

type Lister interface{
	ListFeatures(files tarutil.FilesMap) (features []FeatureVersion,errs error)
}

func ListFeatures(files tarutil.FilesMap)(features []FeatureVersion,errs error){
	listersM.RLock()
	defer listersM.RUnlock()
	var totalFeatures []FeatureVersion
	for _, lister := range listers {
		features, err := lister.ListFeatures(files)
		if err != nil {
			return []FeatureVersion{}, err
		}
		totalFeatures = append(totalFeatures, features...)
	}

	return totalFeatures, nil
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