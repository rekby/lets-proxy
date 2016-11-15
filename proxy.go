package main

import (
	"sync"
	"net"
	"io"
	"github.com/Sirupsen/logrus"
)

const (
	NETBUF_SIZE = 2048 // bytes
)

var (
	netbufPool sync.Pool
)

// Get or create network buffer for proxy
func netbufGet()[]byte {
	res := netbufPool.Get().([]byte)
	if res == nil {
		res = make([]byte, NETBUF_SIZE)
	}
	return res
}

func netbufPut(buf []byte){
	// prevent data leak
	for i := 0; i < len(NETBUF_SIZE); i++{
		buf[i] = 0
	}
	netbufPool.Put(buf)
}

func startProxy(targetAddr net.TCPAddr, in net.Conn){
	switch *proxyMode {
	case "http":
		startProxyHTTP(targetAddr, in)
	case "tcp":
		startProxyTCP(targetAddr, in)
	default:
		logrus.Panicf("Unknow proxy mode: %v", *proxyMode)
	}
}

func startProxyHTTP(targetAddr net.TCPAddr, in net.Conn) {

}

func startProxyTCP(targetAddr net.TCPAddr, in net.Conn) {
	logrus.Infof("Start proxy connection from '%v' to'%v'", in.RemoteAddr().String(), targetAddr.String())

	targetConnCommon, err := net.DialTimeout("tcp", targetAddr.String(), *targetConnTimeout)
	if err != nil {
		logrus.Warnf("Can't connect to target '%v': %v", targetAddr.String(), err)
		return
	}

	targetConn := targetConnCommon.(*net.TCPConn)
	go func() {
		buf := netbufGet()
		defer netbufPut(buf)
		io.CopyBuffer(in, targetConn, buf)
		in.Close()
		targetConn.Close()
	}()
	go func() {
		buf := netbufGet()
		defer netbufPut(buf)
		io.CopyBuffer(targetConn, in, buf)
		in.Close()
		targetConn.Close()
	}()
}
