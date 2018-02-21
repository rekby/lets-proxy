package main

import (
	"net"
	"net/http"
	"strings"

	"sync"

	"github.com/Sirupsen/logrus"
)

const (
	Http01ValidationPrefix = "/.well-known/acme-challenge/"
)

var (
	canHttpValidationGlobalState bool
	http01Tokens                 = make(map[string]string)
	http01TokensMutex            sync.RWMutex
)

type HttpValidationHandler struct{}

func (HttpValidationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logrus.Debugf("Http-01-validation request: %v", r.URL.String())

	pathNormalization := r.URL.Path
	for len(pathNormalization) > 1 && pathNormalization[0] == '/' && pathNormalization[1] == '/' {
		pathNormalization = pathNormalization[1:]
	}
	if r.Method != http.MethodGet || !strings.HasPrefix(pathNormalization, Http01ValidationPrefix) {
		logrus.Infof("Received bad http validation connection from '%v' method '%v' uri '%v'",
			r.RemoteAddr, r.Method, r.RequestURI)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// http-01 validation
	w.Header().Set("Content-type", "text/plain")
	fileName := strings.TrimPrefix(r.URL.Path, Http01ValidationPrefix)
	w.Write([]byte(Http01TokenGet(fileName)))
}

func CanHttpValidation() bool {
	return canHttpValidationGlobalState
}

func Http01TokenDelete(key string) {
	http01TokensMutex.Lock()
	defer http01TokensMutex.Unlock()

	delete(http01Tokens, key)
}

func Http01TokenGet(key string) string {
	http01TokensMutex.RLock()
	defer http01TokensMutex.RUnlock()

	return http01Tokens[key]
}

func Http01TokenPut(key, val string) {
	http01TokensMutex.Lock()
	defer http01TokensMutex.Unlock()

	http01Tokens[key] = val
}

func acceptConnectionsHttpValidation(listeners []*net.TCPListener) {
	canHttpValidationGlobalState = len(listeners) > 0

	for _, listener := range listeners {
		httpServer := http.Server{}
		httpServer.Handler = HttpValidationHandler{}
		go httpServer.Serve(listener)
	}
}
