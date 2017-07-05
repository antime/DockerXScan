package feature

import (
	"sync"
	"github.com/MXi4oyu/DockerXScan/tarutil"
)

var (
	listersM sync.RWMutex
	listers  = make(map[string]Lister)
)

//特征
type Feature struct {
	Name      string
	Namespace string
}

//特征版本
type FeatureVersion struct {
	Feature    Feature
	Version    string
}

//特征列表
type Lister interface {
	// ListFeatures produces a list of FeatureVersions present in an image layer.
	ListFeatures(tarutil.FilesMap) (features []FeatureVersion,errs error)

	RequiredFilenames() []string
}


//注册lister
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


func ListFeatures(files tarutil.FilesMap) (features []FeatureVersion,errs error) {

	listersM.RLock()
	defer listersM.RUnlock()

	var totalFeatures []FeatureVersion

	for _,lister :=range listers{

		features,err:=lister.ListFeatures(files)
		if err != nil {
			return features,err
		}

		totalFeatures = append(totalFeatures, features...)
	}

	return totalFeatures,nil

}

func RequiredFilenames() (files []string) {
	listersM.RLock()
	defer listersM.RUnlock()

	for _, lister := range listers {
		files = append(files, lister.RequiredFilenames()...)
	}

	return
}

