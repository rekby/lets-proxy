package main

import (
	"net/http"
	"net/http/pprof"

	"github.com/Sirupsen/logrus"
)

type CheckProfilerAccessHandler http.HandlerFunc

func startProfiler() {
	profilerMux := &http.ServeMux{}
	profilerMux.Handle("/debug/pprof/", CheckProfilerAccessHandler(pprof.Index))
	//profilerMux.Handle("/debug/pprof/cmdline", CheckProfilerAccessHandler(pprof.Cmdline))
	profilerMux.Handle("/debug/pprof/profile", CheckProfilerAccessHandler(pprof.Profile))
	profilerMux.Handle("/debug/pprof/symbol", CheckProfilerAccessHandler(pprof.Symbol))
	profilerMux.Handle("/debug/pprof/trace", CheckProfilerAccessHandler(pprof.Trace))
	profilerMux.HandleFunc("/robots.txt", func(resp http.ResponseWriter, r *http.Request) {
		//nolint:errcheck
		resp.Write([]byte(`User-agent: *
Disallow: /`))
	})
	profilerMux.Handle("/", CheckProfilerAccessHandler(http.NotFound))

	profilerServer := &http.Server{}
	profilerServer.Handler = profilerMux
	profilerServer.Addr = *profilerBindAddress
	logrus.Infof("Start profiler with bind to: '%v'", profilerServer.Addr)
	err := profilerServer.ListenAndServe()
	logrus.Errorf("Can't start profiler: %v", err)
}

func (h CheckProfilerAccessHandler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	password := req.FormValue("password")
	var cPassword string
	cookie, _ := req.Cookie("password")
	if cookie != nil {
		cPassword = cookie.Value
	}
	if password == *profilerPassword || cPassword == *profilerPassword {
		if cPassword == "" {
			cookie := &http.Cookie{}
			cookie.Path = "/debug/pprof/"
			cookie.Name = "password"
			cookie.Value = *profilerPassword
			http.SetCookie(resp, cookie)
		}
		h(resp, req)
	} else {
		resp.WriteHeader(403)
		resp.Header().Add("Content-length", "14") // "Access denied."
		//nolint:errcheck
		resp.Write([]byte("Access denied."))
	}
}
