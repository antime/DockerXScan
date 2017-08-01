package api

import (
	"net/http"
	"strings"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/MXi4oyu/DockerXScan/api/v1"
	"github.com/MXi4oyu/DockerXScan/database"
)

// router is an HTTP router that forwards requests to the appropriate sub-router
// depending on the API version specified in the request URI.
type router map[string]*httprouter.Router

// Let's hope we never have more than 99 API versions.
const apiVersionLength = len("v99")

func newAPIHandler(cfg *Config, store database.Datastore) http.Handler {
	router := make(router)
	router["/v1"] = v1.NewRouter(store, cfg.PaginationKey)
	return router
}

func (rtr router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	urlStr := r.URL.String()
	var version string
	if len(urlStr) >= apiVersionLength {
		version = urlStr[:apiVersionLength]
	}

	if router, _ := rtr[version]; router != nil {
		// Remove the version number from the request path to let the router do its
		// job but do not update the RequestURI
		r.URL.Path = strings.Replace(r.URL.Path, version, "", 1)
		router.ServeHTTP(w, r)
		return
	}

	log.WithFields(log.Fields{"status": http.StatusNotFound, "method": r.Method, "request uri": r.RequestURI, "remote addr": r.RemoteAddr}).Info("Served HTTP request")
	http.NotFound(w, r)
}

func newHealthHandler(store database.Datastore) http.Handler {
	router := httprouter.New()
	router.GET("/health", healthHandler(store))
	return router
}

func healthHandler(store database.Datastore) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		header := w.Header()
		header.Set("Server", "clair")

		status := http.StatusInternalServerError
		if store.Ping() {
			status = http.StatusOK
		}

		w.WriteHeader(status)
	}
}
