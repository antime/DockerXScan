package vulnmdsrc

import (
	"sync"
	"github.com/MXi4oyu/DockerXScan/database"
)


var (
	appendersM sync.RWMutex
	appenders  = make(map[string]Appender)
)

// AppendFunc is the type of a callback provided to an Appender.
type AppendFunc func(metadataKey string, metadata interface{}, severity database.Severity)

// Appender represents anything that can fetch vulnerability metadata and
// append it to a Vulnerability.
type Appender interface {
	// BuildCache loads metadata into memory such that it can be quickly accessed
	// for future calls to Append.
	BuildCache(database.Datastore) error

	// AddMetadata adds metadata to the given database.Vulnerability.
	// It is expected that the fetcher uses .Lock.Lock() when manipulating the Metadata map.
	// Append
	Append(vulnName string, callback AppendFunc) error

	// PurgeCache deallocates metadata from memory after all calls to Append are
	// finished.
	PurgeCache()

	// Clean deletes any allocated resources.
	// It is invoked when Clair stops.
	Clean()
}

// RegisterAppender makes an Appender available by the provided name.
//
// If called twice with the same name, the name is blank, or if the provided
// Appender is nil, this function panics.
func RegisterAppender(name string, a Appender) {
	if name == "" {
		panic("vulnmdsrc: could not register an Appender with an empty name")
	}

	if a == nil {
		panic("vulnmdsrc: could not register a nil Appender")
	}

	appendersM.Lock()
	defer appendersM.Unlock()

	if _, dup := appenders[name]; dup {
		panic("vulnmdsrc: RegisterAppender called twice for " + name)
	}

	appenders[name] = a
}

// Appenders returns the list of the registered Appenders.
func Appenders() map[string]Appender {
	appendersM.RLock()
	defer appendersM.RUnlock()

	ret := make(map[string]Appender)
	for k, v := range appenders {
		ret[k] = v
	}

	return ret
}