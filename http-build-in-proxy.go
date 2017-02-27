package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/Sirupsen/logrus"
)

func acceptConnectionsBuiltinProxy(listeners []*net.TCPListener) {
	for index := range listeners {
		listener := listeners[index]

		tcpAddr, err := getTargetAddr(ConnectionID("none"), listener.Addr())
		if err != nil {
			logrus.Errorf("Can't map listener addr to target '%v': %v", listener.Addr(), err)
		}

		proxy := &httputil.ReverseProxy{}
		proxy.Director = func(req *http.Request) {
			if req.URL == nil {
				req.URL = &url.URL{}
			}
			req.URL.Scheme = "http"
			req.URL.Host = tcpAddr.String()
		}

		tlsListener := tls.NewListener(tcpKeepAliveListener{listener}, createTlsConfig())
		server := http.Server{}
		server.TLSConfig = createTlsConfig()
		server.Handler = proxy
		go server.Serve(tlsListener)
	}

	// block forever
	var ch chan bool
	<-ch
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(*tcpKeepAliveInterval)
	return tc, nil
}
