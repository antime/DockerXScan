package api

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tylerb/graceful"
	"github.com/MXi4oyu/DockerXScan/database"
	"github.com/MXi4oyu/DockerXScan/common/stopper"
	"flag"
)


const timeoutResponse = `{"Error":{"Message":"Clair failed to respond within the configured timeout window.","Type":"Timeout"}}`

// Config is the configuration for the API service.
type Config struct {
	Port                      int
	HealthPort                int
	Timeout                   time.Duration
	PaginationKey             string
	CertFile, KeyFile, CAFile string
}

var(
	flagMinimumSeverity = flag.String("minimum-severity", "Negligible", "Minimum severity of vulnerabilities to show (Unknown, Negligible, Low, Medium, High, Critical, Defcon1)")
)

func Run(cfg *Config, store database.Datastore, st *stopper.Stopper) {
	defer st.End()
	//显示漏洞信息
	minSeverity, err := database.NewSeverity(*flagMinimumSeverity)

	ctx := &context{store, cfg.PaginationKey}
	layer,_:=GetLayer("52b4ea56b21260207dd64214cdd9703af24848972315ab2b0891e9ed8afd77e4",ctx)
	ShowVuls(layer,minSeverity)


	// Do not run the API service if there is no config.
	if cfg == nil {
		log.Info("main API service is disabled.")
		return
	}
	log.WithField("port", cfg.Port).Info("starting main API")

	tlsConfig, err := tlsClientConfig(cfg.CAFile)
	if err != nil {
		log.WithError(err).Fatal("could not initialize client cert authentication")
	}
	if tlsConfig != nil {
		log.Info("main API configured with client certificate authentication")
	}

	srv := &graceful.Server{
		Timeout:          0,    // Already handled by our TimeOut middleware
		NoSignalHandling: true, // We want to use our own Stopper
		Server: &http.Server{
			Addr:      ":" + strconv.Itoa(cfg.Port),
			TLSConfig: tlsConfig,
			Handler:   http.TimeoutHandler(newAPIHandler(cfg, store), cfg.Timeout, timeoutResponse),
		},
	}

	listenAndServeWithStopper(srv, st, cfg.CertFile, cfg.KeyFile)

	log.Info("main API stopped")
}

func RunHealth(cfg *Config, store database.Datastore, st *stopper.Stopper) {
	defer st.End()

	// Do not run the API service if there is no config.
	if cfg == nil {
		log.Info("health API service is disabled.")
		return
	}
	log.WithField("port", cfg.HealthPort).Info("starting health API")

	srv := &graceful.Server{
		Timeout:          10 * time.Second, // Interrupt health checks when stopping
		NoSignalHandling: true,             // We want to use our own Stopper
		Server: &http.Server{
			Addr:    ":" + strconv.Itoa(cfg.HealthPort),
			Handler: http.TimeoutHandler(newHealthHandler(store), cfg.Timeout, timeoutResponse),
		},
	}

	listenAndServeWithStopper(srv, st, "", "")

	log.Info("health API stopped")
}

// listenAndServeWithStopper wraps graceful.Server's
// ListenAndServe/ListenAndServeTLS and adds the ability to interrupt them with
// the provided stopper.Stopper.
func listenAndServeWithStopper(srv *graceful.Server, st *stopper.Stopper, certFile, keyFile string) {
	go func() {
		<-st.Chan()
		srv.Stop(0)
	}()

	var err error
	if certFile != "" && keyFile != "" {
		log.Info("API: TLS Enabled")
		err = srv.ListenAndServeTLS(certFile, keyFile)
	} else {
		err = srv.ListenAndServe()
	}

	if err != nil {
		if opErr, ok := err.(*net.OpError); !ok || (ok && opErr.Op != "accept") {
			log.Fatal(err)
		}
	}
}

// tlsClientConfig initializes a *tls.Config using the given CA. The resulting
// *tls.Config is meant to be used to configure an HTTP server to do client
// certificate authentication.
//
// If no CA is given, a nil *tls.Config is returned; no client certificate will
// be required and verified. In other words, authentication will be disabled.
func tlsClientConfig(caPath string) (*tls.Config, error) {
	if caPath == "" {
		return nil, nil
	}

	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	return tlsConfig, nil
}
