package vulnsrc

import (
	"sync"
	"errors"
	"github.com/MXi4oyu/DockerXScan/database"
)

var (
	// ErrFilesystem is returned when a fetcher fails to interact with the local filesystem.
	ErrFilesystem = errors.New("vulnsrc: something went wrong when interacting with the fs")

	// ErrGitFailure is returned when a fetcher fails to interact with git.
	ErrGitFailure = errors.New("vulnsrc: something went wrong when interacting with git")

	updatersM sync.RWMutex
	updaters  = make(map[string]Updater)
)

// UpdateResponse represents the sum of results of an update.
type UpdateResponse struct {
	FlagName        string
	FlagValue       string
	Notes           []string
	Vulnerabilities []database.Vulnerability
}

// Updater represents anything that can fetch vulnerabilities and insert them
// into a Clair datastore.
type Updater interface {
	// Update gets vulnerability updates.
	Update(database.Datastore) (UpdateResponse, error)

	// Clean deletes any allocated resources.
	// It is invoked when Clair stops.
	Clean()
}

// RegisterUpdater makes an Updater available by the provided name.
//
// If called twice with the same name, the name is blank, or if the provided
// Updater is nil, this function panics.
func RegisterUpdater(name string, u Updater) {
	if name == "" {
		panic("vulnsrc: could not register an Updater with an empty name")
	}

	if u == nil {
		panic("vulnsrc: could not register a nil Updater")
	}

	updatersM.Lock()
	defer updatersM.Unlock()

	if _, dup := updaters[name]; dup {
		panic("vulnsrc: RegisterUpdater called twice for " + name)
	}

	updaters[name] = u
}

// Updaters returns the list of the registered Updaters.
func Updaters() map[string]Updater {
	updatersM.RLock()
	defer updatersM.RUnlock()

	ret := make(map[string]Updater)
	for k, v := range updaters {
		ret[k] = v
	}

	return ret
}

