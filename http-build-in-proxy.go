package main

import (
	"net"
	"net/http"
	"net/http/httputil"
	"crypto/tls"
	"github.com/Sirupsen/logrus"
	"net/url"
)

func acceptConnectionsBuiltinProxy(listeners []*net.TCPListener) {
	for index := range listeners {
		listener := listeners[index]

		tcpAddr, err := getTargetAddr(ConnectionID("none"), listener.Addr())
		if err != nil {
			logrus.Errorf("Can't map listener addr to target '%v': %v", listener.Addr(), err)
		}

		proxy := &httputil.ReverseProxy{}
		proxy.Director = func (req*http.Request){
			if req.URL == nil {
				req.URL = &url.URL{}
			}
			req.URL.Scheme = "http"
			req.URL.Host = tcpAddr.String()
		}


		tlsListener := tls.NewListener(listener, createTlsConfig())
		server := http.Server{}
		server.TLSConfig = createTlsConfig()
		server.Handler = proxy
		go server.Serve(tlsListener)
	}

	// block forever
	var ch chan bool
	<-ch
}