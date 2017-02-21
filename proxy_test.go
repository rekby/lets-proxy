package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/rekby/pair-connections"
)

func TestProxyHttpHeaders(t *testing.T) {
	testNum := 0
	test := func(keepalivemode int, in, outHead []byte, needRes proxyHTTPHeadersRes) {
		testNum++

		clientToProxy, proxyIn := pairconnections.CreateTCPPairConnections()
		defer clientToProxy.Close()
		defer proxyIn.Close()

		proxyToServer, proxyOut := pairconnections.CreateTCPPairConnections()
		defer proxyToServer.Close()
		defer proxyOut.Close()

		var proxyRes proxyHTTPHeadersRes
		go func() {
			clientToProxy.Write(in)
		}()

		go func() {
			proxyRes = proxyHTTPHeaders(ConnectionID(""), proxyOut, proxyIn, keepalivemode)
			proxyOut.Close()
		}()

		received, err := ioutil.ReadAll(proxyToServer)
		if err != nil {
			t.Error(testNum, err)
		}
		if !bytes.Equal(received, outHead) {
			t.Errorf("%v '%s' != '%s'\n\n'%v'\n'%v'", testNum, received, outHead, received, outHead)
		}

		if proxyRes.HasContentLength != needRes.HasContentLength {
			t.Error(testNum, proxyRes.HasContentLength, needRes.HasContentLength)
		}
		if proxyRes.ContentLength != needRes.ContentLength {
			t.Error(testNum, proxyRes.ContentLength, needRes.HasContentLength)
		}
		if proxyRes.KeepAlive != needRes.KeepAlive {
			t.Error(testNum, proxyRes.KeepAlive, needRes.KeepAlive)
		}
		errText := fmt.Sprint(proxyRes.Err)
		needErrText := fmt.Sprint(needRes.Err)
		if errText != needErrText {
			t.Error(testNum, proxyRes.Err, needRes.Err)
		}
	}

	buf := &bytes.Buffer{}
	buf.WriteString("GET /test HTTP/1.0\r\n")
	buf.WriteString("HOST: www.asd.com\r\n")
	buf.WriteString("\r\n")
	buf.WriteString("body")

	needBuf := &bytes.Buffer{}
	needBuf.WriteString("GET /test HTTP/1.0\r\n")
	needBuf.WriteString("HOST: www.asd.com\r\n")
	needBuf.WriteString("\r\n")
	test(PROXY_KEEPALIVE_NOTHING, buf.Bytes(), needBuf.Bytes(),
		proxyHTTPHeadersRes{KeepAlive: false, ContentLength: 0, HasContentLength: false, Err: nil})

	buf = &bytes.Buffer{}
	buf.WriteString("GET /test HTTP/1.0\r\n")
	buf.WriteString("HOST: www.asd.com\r\n")
	buf.WriteString("Connection: Keep-Alive\r\n")
	buf.WriteString("\r\n")
	buf.WriteString("body")

	needBuf = &bytes.Buffer{}
	needBuf.WriteString("GET /test HTTP/1.0\r\n")
	needBuf.WriteString("HOST: www.asd.com\r\n")
	needBuf.WriteString("Connection: Keep-Alive\r\n")
	needBuf.WriteString("\r\n")
	test(PROXY_KEEPALIVE_NOTHING, buf.Bytes(), needBuf.Bytes(),
		proxyHTTPHeadersRes{KeepAlive: true, ContentLength: 0, HasContentLength: false, Err: nil})

	buf = &bytes.Buffer{}
	buf.WriteString("GET /test HTTP/1.1\r\n")
	buf.WriteString("HOST: www.asd.com\r\n")
	buf.WriteString("\r\n")
	buf.WriteString("body")

	needBuf = &bytes.Buffer{}
	needBuf.WriteString("GET /test HTTP/1.1\r\n")
	needBuf.WriteString("HOST: www.asd.com\r\n")
	needBuf.WriteString("\r\n")
	test(PROXY_KEEPALIVE_NOTHING, buf.Bytes(), needBuf.Bytes(),
		proxyHTTPHeadersRes{KeepAlive: true, ContentLength: 0, HasContentLength: false, Err: nil})

	buf = &bytes.Buffer{}
	buf.WriteString("GET /test HTTP/1.1\r\n")
	buf.WriteString("HOST: www.asd.com\r\n")
	buf.WriteString("Connection: Close\r\n")
	buf.WriteString("\r\n")
	buf.WriteString("body")

	needBuf = &bytes.Buffer{}
	needBuf.WriteString("GET /test HTTP/1.1\r\n")
	needBuf.WriteString("HOST: www.asd.com\r\n")
	needBuf.WriteString("Connection: Close\r\n")
	needBuf.WriteString("\r\n")
	test(PROXY_KEEPALIVE_NOTHING, buf.Bytes(), needBuf.Bytes(),
		proxyHTTPHeadersRes{KeepAlive: false, ContentLength: 0, HasContentLength: false, Err: nil})

	buf = &bytes.Buffer{}
	buf.WriteString("GET /test HTTP/1.1\r\n")
	buf.WriteString("HOST: www.asd.com\r\n")
	buf.WriteString("Connection: Close\r\n")
	buf.WriteString("Content-length: 123\r\n")
	buf.WriteString("\r\n")
	buf.WriteString("body")

	needBuf = &bytes.Buffer{}
	needBuf.WriteString("GET /test HTTP/1.1\r\n")
	needBuf.WriteString("HOST: www.asd.com\r\n")
	needBuf.WriteString("Connection: Close\r\n")
	needBuf.WriteString("Content-length: 123\r\n")
	needBuf.WriteString("\r\n")
	test(PROXY_KEEPALIVE_NOTHING, buf.Bytes(), needBuf.Bytes(),
		proxyHTTPHeadersRes{KeepAlive: false, ContentLength: 123, HasContentLength: true, Err: nil})

	buf = &bytes.Buffer{}
	buf.WriteString("GET /test HTTP/1.1\r\n")
	buf.WriteString("HOST: www.asd.com\r\n")
	buf.WriteString("Connection: Close\r\n")
	buf.WriteString("Content-length: 0\r\n")
	buf.WriteString("\r\n")
	buf.WriteString("body")

	needBuf = &bytes.Buffer{}
	needBuf.WriteString("GET /test HTTP/1.1\r\n")
	needBuf.WriteString("HOST: www.asd.com\r\n")
	needBuf.WriteString("Connection: Close\r\n")
	needBuf.WriteString("Content-length: 0\r\n")
	needBuf.WriteString("\r\n")
	test(PROXY_KEEPALIVE_NOTHING, buf.Bytes(), needBuf.Bytes(),
		proxyHTTPHeadersRes{KeepAlive: false, ContentLength: 0, HasContentLength: true, Err: nil})

	buf = &bytes.Buffer{}
	buf.WriteString("GET /test HTTP/1.1\r\n")
	buf.WriteString("HOST: www.asd.com\r\n")
	buf.WriteString("Connection: Close\r\n")
	buf.WriteString("Content-length: 0\r\n")
	buf.WriteString("\r\n")
	buf.WriteString("body")

	needBuf = &bytes.Buffer{}
	needBuf.WriteString("GET /test HTTP/1.1\r\n")
	needBuf.WriteString("HOST: www.asd.com\r\n")
	needBuf.WriteString("Content-length: 0\r\n")
	needBuf.WriteString("Connection: Close\r\n")
	needBuf.WriteString("\r\n")
	test(PROXY_KEEPALIVE_DROP, buf.Bytes(), needBuf.Bytes(),
		proxyHTTPHeadersRes{KeepAlive: false, ContentLength: 0, HasContentLength: true, Err: nil})

	buf = &bytes.Buffer{}
	buf.WriteString("GET /test HTTP/1.1\r\n")
	buf.WriteString("HOST: www.asd.com\r\n")
	buf.WriteString("Connection: Keep-Alive\r\n")
	buf.WriteString("Content-length: 0\r\n")
	buf.WriteString("\r\n")
	buf.WriteString("body")

	needBuf = &bytes.Buffer{}
	needBuf.WriteString("GET /test HTTP/1.1\r\n")
	needBuf.WriteString("HOST: www.asd.com\r\n")
	needBuf.WriteString("Content-length: 0\r\n")
	needBuf.WriteString("Connection: Close\r\n")
	needBuf.WriteString("\r\n")
	test(PROXY_KEEPALIVE_DROP, buf.Bytes(), needBuf.Bytes(),
		proxyHTTPHeadersRes{KeepAlive: true, ContentLength: 0, HasContentLength: true, Err: nil})
}
