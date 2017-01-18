package main

import (
	"testing"
	"github.com/rekby/pair-connections"
	"bytes"
	"io/ioutil"
	"fmt"
)

func TestProxyHttpHeaders(t *testing.T){
	test := func(keepalivemode int, in, outHead []byte, needRes proxyHTTPHeadersRes){
		clientToProxy, proxyIn := pairconnections.CreateTCPPairConnections()
		defer clientToProxy.Close()
		defer proxyIn.Close()

		proxyToServer, proxyOut := pairconnections.CreateTCPPairConnections()
		defer proxyToServer.Close()
		defer proxyOut.Close()

		var proxyRes proxyHTTPHeadersRes
		go func(){
			clientToProxy.Write(in)
		}()

		go func(){
			proxyRes = proxyHTTPHeaders(ConnectionID(""), proxyOut, proxyIn, PROXY_KEEPALIVE_NOTHING)
			proxyOut.Close()
		}()

		received, err := ioutil.ReadAll(proxyToServer)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(received, outHead) {
			t.Errorf("'%s' != '%s'\n\n'%v'\n'%v'", received, outHead, received, outHead)
		}

		if proxyRes.HasContentLength != needRes.HasContentLength {
			t.Error(proxyRes.HasContentLength,needRes.HasContentLength)
		}
		if proxyRes.ContentLength != needRes.ContentLength {
			t.Error(proxyRes.ContentLength,needRes.HasContentLength)
		}
		if proxyRes.KeepAlive != needRes.KeepAlive {
			t.Error(proxyRes.KeepAlive, needRes.KeepAlive)
		}
		errText := fmt.Sprint(proxyRes.Err)
		needErrText := fmt.Sprint(needRes.Err)
		if errText != needErrText {
			t.Error(proxyRes.Err, needRes.Err)
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

	test(PROXY_KEEPALIVE_NOTHING, buf.Bytes(), needBuf.Bytes(), proxyHTTPHeadersRes{KeepAlive:false,ContentLength:0, HasContentLength:false})
}
