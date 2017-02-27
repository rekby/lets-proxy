package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"time"

	"github.com/Sirupsen/logrus"
	"golang.org/x/net/idna"
)

func acceptConnectionsBuiltinProxy(listeners []*net.TCPListener) {
	for index := range listeners {
		listener := listeners[index]

		tcpAddr, err := getTargetAddr(ConnectionID("none"), listener.Addr())
		if err != nil {
			logrus.Errorf("Can't map listener addr to target '%v': %v", listener.Addr(), err)
		}

		proxy := &httputil.ReverseProxy{}
		targetAddrString := tcpAddr.String()
		proxy.Director = func(req *http.Request) {
			if req.URL == nil {
				req.URL = &url.URL{}
			}
			req.URL.Scheme = "http"
			req.URL.Host = targetAddrString

			if req.Header == nil {
				req.Header = make(http.Header)
			}
			for _, pair := range additionalHeadersStringPairs {
				req.Header.Set(pair[0], pair[1])
			}
			clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
			if err == nil {
				for _, realIpHeader := range realIPHeaderNamesStrings {
					req.Header.Set(realIpHeader, clientIP)
				}
			}

			if logrus.StandardLogger().Level >= logrus.InfoLevel {
				asciiDomain, err := idna.ToASCII(req.Host)
				if err != nil {
					logrus.Debugf("Can't convert domain to ascii '%v': %v", req.Host, err)
				}
				domainPresent := DomainPresent(asciiDomain)
				logrus.Infof("Start proxy from '%v' to '%v', %v", clientIP, targetAddrString, domainPresent)
			}

			if *connectionIdHeader != "" {
				req.Header.Set(*connectionIdHeader, "TODO")
			}

		}

		proxy.ModifyResponse = func(resp *http.Response) error {
			return nil
		}

		tlsListener := tls.NewListener(tcpKeepAliveListener{listener}, createTlsConfig())

		server := http.Server{}
		server.TLSConfig = createTlsConfig()
		server.Handler = proxy

		switch keepAliveMode {
		case KEEPALIVE_TRANSPARENT:
			// pass. Do native.
		case KEEPALIVE_NO_BACKEND:
			// copy default transport + disable keepalive
			proxy.Transport = &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
					DualStack: true,
				}).DialContext,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,

				// force disable keepalive
				DisableKeepAlives: true,
			}
		default:
			logrus.Errorf("Unknow keep alive mode for buil-in proxy: %v (%v)", *keepAliveModeS, keepAliveMode)
		}

		server.ReadTimeout = *maxRequestTime

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
