package main

import (
	"bytes"
	"github.com/Sirupsen/logrus"
	"io"
	"net"
	"sync"
)

const (
	NETBUF_SIZE = 2048 // bytes
)

var (
	poolNetBuffers sync.Pool
)

// Get or create network buffer for proxy
func netbufGet() (buf []byte) {
	bufInterface := poolNetBuffers.Get()
	if bufInterface == nil {
		buf = make([]byte, NETBUF_SIZE)
	} else {
		buf = bufInterface.([]byte)
		// prevent data leak
		for i := range buf {
			buf[i] = 0
		}

	}
	return buf
}

func netbufPut(buf []byte) {
	poolNetBuffers.Put(buf)
}

func startProxy(targetAddr net.TCPAddr, in net.Conn) {
	targetConnCommon, err := net.DialTimeout("tcp", targetAddr.String(), *targetConnTimeout)
	if err != nil {
		logrus.Warnf("Can't connect to target '%v': %v", targetAddr.String(), err)
		return
	}

	targetConn, ok := targetConnCommon.(*net.TCPConn)
	if !ok {
		logrus.Errorf("Can't cast connection to tcp connection, target '%v'", targetAddr.String())
		return
	}

	switch *proxyMode {
	case "http":
		startProxyHTTP(targetConn, in)
	case "tcp":
		startProxyTCP(targetConn, in)
	default:
		logrus.Panicf("Unknow proxy mode: %v", *proxyMode)
	}
}

func startProxyHTTP(targetConn net.Conn, sourceConn net.Conn) {
	logrus.Infof("Start http-proxy connection from '%v' to'%v'", sourceConn.RemoteAddr().String(), targetConn.RemoteAddr().String())

	// answer from server proxy without changes
	go func() {
		buf := netbufGet()
		defer netbufPut(buf)

		_, err := io.CopyBuffer(sourceConn, targetConn, buf)
		logrus.Debugf("Connection closed with error '%v' -> '%v': %v", sourceConn.RemoteAddr().String(), targetConn.RemoteAddr().String(), err)
		sourceConn.Close()
		targetConn.Close()
	}()

	proxyHTTPHeaders(targetConn, sourceConn)
	go func() {
		buf := netbufGet()
		defer netbufPut(buf)

		_, err := io.CopyBuffer(targetConn, sourceConn, buf)

		logrus.Debugf("Connection closed with error '%v' -> '%v': %v", sourceConn.RemoteAddr().String(), targetConn.RemoteAddr().String(), err)
		sourceConn.Close()
		targetConn.Close()
	}()
}

func proxyHTTPHeaders(targetConn net.Conn, sourceConn net.Conn) {
	buf := netbufGet()
	defer netbufPut(buf)

	// Read lines
	for {
		var i int
		var headerStart []byte
		for i = 0; i < len(buf); i++ {
			readBytes, err := sourceConn.Read(buf[i : i+1])
			if err != nil {
				logrus.Warnf("Error while read header from '%v': %v", sourceConn.RemoteAddr().String(), err)
				return
			}
			if readBytes != 1 {
				logrus.Errorf("Can't read a byte from header from '%v'", sourceConn.RemoteAddr().String())
				return
			}
			if buf[i] == ':' || buf[i] == '\n' {
				headerStart = buf[:i+1]
				logrus.Debugf("Header Name '%v' -> '%v': '%s'", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), buf[:i])
				break
			}
		}
		if len(headerStart) == 0 {
			logrus.Warnf("Header line longer then buffer (%v bytes). Force close connection. '%v' -> '%v'.", len(buf), sourceConn.RemoteAddr(), targetConn.RemoteAddr())
			targetConn.Close()
			sourceConn.Close()
			return
		}

		// Empty line - end http headers
		if bytes.Equal(headerStart, []byte("\n")) || bytes.Equal(headerStart, []byte("\r\n")) {
			remoteTcpAddr := sourceConn.RemoteAddr().(*net.TCPAddr)
			remoteAddrString := remoteTcpAddr.IP.String()

			headerBuf := bytes.NewBuffer(buf)
			headerBuf.Reset()

			// Write real IP
			for _, header := range realIPHeaderNames {
				headerBuf.Write(header)
				headerBuf.WriteByte(':')
				headerBuf.WriteString(remoteAddrString)
				headerBuf.Write([]byte("\r\n"))
			}
			headerBuf.Write([]byte("\r\n")) // end http headers
			logrus.Debugf("Add headers. '%v' -> '%v': '%s'", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), headerBuf.Bytes())

			_, err := targetConn.Write(headerBuf.Bytes())
			if err != nil {
				logrus.Errorf("Error while write real ip headers to target '%v' -> '%v': %v", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), err)
			}

			return
		}

		headerName := bytes.ToUpper(headerStart[:len(headerStart)-1]) // Cut trailing colon from start

		skipHeader := false
		for _, ownHeader := range cutHeaders {
			if bytes.Equal(ownHeader, headerName) {
				skipHeader = true
				break
			}
			ownHeaderS := string(ownHeader)
			headerNameS := string(headerName)
			skipHeader = ownHeaderS == headerNameS
		}

		if skipHeader {
			logrus.Debugf("Skip header: '%v' -> '%v': '%s'", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), headerName)
			buf[0] = headerStart[len(headerStart)-1]

			for buf[0] != '\n' {
				_, err := sourceConn.Read(buf[:1])
				if err != nil {
					logrus.Infof("Error read header. Close connections. '%v' -> '%v': %v", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), err)
					sourceConn.Close()
					targetConn.Close()
					return
				}
			}
		} else {
			logrus.Debugf("Copy header: '%v' -> '%v': '%s'", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), headerName)

			// copy header without changes
			targetConn.Write(headerStart)

			for buf[0] != '\n' {
				readBytes, err := sourceConn.Read(buf[:1])
				if err != nil {
					logrus.Infof("Error read header to copy. Close connections. '%v' -> '%v': %v", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), err)
					sourceConn.Close()
					targetConn.Close()
					return
				}
				if readBytes != 1 {
					logrus.Errorf("Header copy read bytes != 1. Error. Close connections. '%v' -> '%v'", sourceConn.RemoteAddr(), targetConn.RemoteAddr())
					sourceConn.Close()
					targetConn.Close()
					return
				}
				_, err = targetConn.Write(buf[:1])
				if err != nil {
					logrus.Infof("Error write header. Close connections. '%v' -> '%v': %v", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), err)
					sourceConn.Close()
					targetConn.Close()
					return
				}
			}
		}
	}
}

func startProxyTCP(targetConn net.Conn, sourceConn net.Conn) {
	logrus.Infof("Start tcp-proxy connection from '%v' to'%v'", sourceConn.RemoteAddr().String(), targetConn.RemoteAddr().String())

	go func() {
		buf := netbufGet()
		defer netbufPut(buf)

		_, err := io.CopyBuffer(targetConn, sourceConn, buf)
		logrus.Debugf("Connection closed with error '%v' -> '%v': %v", sourceConn.RemoteAddr().String(), targetConn.RemoteAddr().String(), err)
		sourceConn.Close()
		targetConn.Close()
	}()
	go func() {
		buf := netbufGet()
		defer netbufPut(buf)

		_, err := io.CopyBuffer(sourceConn, targetConn, buf)
		logrus.Debugf("Connection closed with error '%v' -> '%v': %v", sourceConn.RemoteAddr().String(), targetConn.RemoteAddr().String(), err)
		sourceConn.Close()
		targetConn.Close()
	}()
}
