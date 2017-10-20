package v1

import (
	"net/http"
	"strconv"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/MXi4oyu/DockerXScan/database"
)

var (
	promResponseDurationMilliseconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "clair_api_response_duration_milliseconds",
		Help:    "The duration of time it takes to receieve and write a response to an API request",
		Buckets: prometheus.ExponentialBuckets(9.375, 2, 10),
	}, []string{"route", "code"})
)

func init() {
	prometheus.MustRegister(promResponseDurationMilliseconds)
}

type handler func(http.ResponseWriter, *http.Request, httprouter.Params, *context) (route string, status int)

func httpHandler(h handler, ctx *context) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		start := time.Now()
		route, status := h(w, r, p, ctx)
		statusStr := strconv.Itoa(status)
		if status == 0 {
			statusStr = "???"
		}

		promResponseDurationMilliseconds.
		WithLabelValues(route, statusStr).
			Observe(float64(time.Since(start).Nanoseconds()) / float64(time.Millisecond))

		log.WithFields(log.Fields{"remote addr": r.RemoteAddr, "method": r.Method, "request uri": r.RequestURI, "status": statusStr, "elapsed time": time.Since(start)}).Info("Handled HTTP request")
	}
}

type context struct {
	Store         database.Datastore
	PaginationKey string
}

// NewRouter creates an HTTP router for version 1 of the Clair API.
func NewRouter(store database.Datastore, paginationKey string) *httprouter.Router {
	router := httprouter.New()
	ctx := &context{store, paginationKey}

	// Layers
	router.POST("/layers", httpHandler(postLayer, ctx))
	router.GET("/layers/:layerName", httpHandler(getLayer, ctx))
	router.DELETE("/layers/:layerName", httpHandler(deleteLayer, ctx))

	// Namespaces
	router.GET("/namespaces", httpHandler(getNamespaces, ctx))
	router.POST("/namespaces",httpHandler(postNamespaces,ctx))

	// Vulnerabilities
	router.GET("/namespaces/:namespaceName/vulnerabilities", httpHandler(getVulnerabilities, ctx))
	router.POST("/namespaces/:namespaceName/vulnerabilities", httpHandler(postVulnerability, ctx))
	router.GET("/namespaces/:namespaceName/vulnerabilities/:vulnerabilityName", httpHandler(getVulnerability, ctx))
	router.PUT("/namespaces/:namespaceName/vulnerabilities/:vulnerabilityName", httpHandler(putVulnerability, ctx))
	router.DELETE("/namespaces/:namespaceName/vulnerabilities/:vulnerabilityName", httpHandler(deleteVulnerability, ctx))

	// Fixes
	router.GET("/namespaces/:namespaceName/vulnerabilities/:vulnerabilityName/fixes", httpHandler(getFixes, ctx))
	router.PUT("/namespaces/:namespaceName/vulnerabilities/:vulnerabilityName/fixes/:fixName", httpHandler(putFix, ctx))
	router.DELETE("/namespaces/:namespaceName/vulnerabilities/:vulnerabilityName/fixes/:fixName", httpHandler(deleteFix, ctx))

	// Notifications
	router.GET("/notifications/:notificationName", httpHandler(getNotification, ctx))
	router.DELETE("/notifications/:notificationName", httpHandler(deleteNotification, ctx))

	// Metrics
	router.GET("/metrics", httpHandler(getMetrics, ctx))

	//featureversion
	router.POST("/featureversion",httpHandler(postFeatureVersion,ctx))

	return router
}