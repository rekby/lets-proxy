package main

import (
	"bytes"
	"github.com/Sirupsen/logrus"
	"io"
	"net"
	"strconv"
	"sync"
)

const (
	NETBUF_SIZE = 2048 // bytes
)

//go:generate stringer -type KeepAliveModeType
type KeepAliveModeType int

const (
	KEEPALIVE_BOTH KeepAliveModeType = iota
	KEEPALIVE_NOBACKEND
)

const (
	KEEPALIVE_BOTH_STRING      = "both"
	KEEPALIVE_NOBACKEND_STRING = "nobackend"
)

var (
	poolNetBuffers sync.Pool
	keepAliveMode  KeepAliveModeType
)

// var-constants
var (
	HEAD_CONNECTION            = []byte("CONNECTION")
	HEAD_CONNECTION_KEEP_ALIVE = []byte("KEEP-ALIVE")
	HEAD_CONTENT_LENGTH        = []byte("CONTENT-LENGTH")
)

func connectTo(cid ConnectionID, targetAddr net.TCPAddr)(conn *net.TCPConn, err error){
	targetConnCommon, err := net.DialTimeout("tcp", targetAddr.String(), *targetConnTimeout)
	if err != nil {
		logrus.Warnf("Can't connect to target '%v' cid '%v': %v", targetAddr.String(), cid, err)
		return nil, err
	}

	targetConn := targetConnCommon.(*net.TCPConn)
	targetConn.SetKeepAlive(true)
	targetConn.SetKeepAlivePeriod(*tcpKeepAliveInterval)
	return targetConn, nil
}



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

func proxyHTTPHeaders(cid ConnectionID, targetConn net.Conn, sourceConn net.Conn) (
	res struct {
		KeepAlive        bool
		ContentLength    int64
		HasContextLength bool
		Err              error
	}) {
	buf := netbufGet()
	defer netbufPut(buf)
	var totalReadBytes int

	// Read lines
readHeaderLines:
	for {
		var i int
		var headerStart []byte
		for i = 0; i < len(buf); i++ {
			var readBytes int
			readBytes, res.Err = sourceConn.Read(buf[i : i+1])
			totalReadBytes += readBytes
			if res.Err != nil {
				logrus.Debugf("Error while read header from '%v' cid '%v': %v", sourceConn.RemoteAddr(), cid, res.Err)
				return
			}
			if readBytes != 1 {
				logrus.Infof("Can't read a byte from header from '%v' cid '%v'", sourceConn.RemoteAddr(), cid)
				return
			}
			if buf[i] == ':' || buf[i] == '\n' {
				headerStart = buf[:i+1]
				logrus.Debugf("Header Name '%v' -> '%v' cid '%v': '%s'", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, buf[:i])
				break
			}
		}
		if len(headerStart) == 0 {
			logrus.Infof("Header line longer then buffer (%v bytes). Force close connection. '%v' -> '%v' cid '%v'.", len(buf), sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid)
			return
		}

		// Empty line - end http headers
		if bytes.Equal(headerStart, []byte("\n")) || bytes.Equal(headerStart, []byte("\r\n")) {
			break readHeaderLines
		}

		headerName := headerStart[:len(headerStart)-1] // Cut trailing colon from start
		headerNameUpperCase := bytes.ToUpper(headerName)

		skipHeader := false
		for _, ownHeader := range cutHeaders {
			if bytes.Equal(ownHeader, headerNameUpperCase) {
				skipHeader = true
				break
			}
			ownHeaderS := string(ownHeader)
			headerNameS := string(headerNameUpperCase)
			skipHeader = ownHeaderS == headerNameS
		}

		if skipHeader {
			logrus.Debugf("Skip header: '%v' -> '%v' cid '%v': '%s'", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, headerNameUpperCase)
			buf[0] = headerStart[len(headerStart)-1]

			for buf[0] != '\n' {
				_, res.Err = sourceConn.Read(buf[:1])
				if res.Err != nil {
					logrus.Infof("Error read header. Close connections. '%v' -> '%v' cid '%v': %v", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, res.Err)
					sourceConn.Close()
					targetConn.Close()
					return
				}
			}
			continue readHeaderLines
		}

		logrus.Debugf("Copy header: '%v' -> '%v' cid '%v': '%s'", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, headerName)

		// copy header without changes
		_, res.Err = targetConn.Write(headerStart)
		if res.Err != nil {
			logrus.Infof("Write header start, from '%v' to '%v' cid '%v', headerStart='%s': %v", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, headerStart, res.Err)
			return
		}

		needHeaderContent := bytes.Equal(headerNameUpperCase, HEAD_CONTENT_LENGTH) || bytes.Equal(headerNameUpperCase, HEAD_CONNECTION)
		headerContent := bytes.NewBuffer(buf[1:])
		headerContent.Reset()

		for buf[0] != '\n' {
			var readBytes int
			readBytes, res.Err = sourceConn.Read(buf[:1])
			if res.Err != nil {
				logrus.Infof("Error read header to copy. Close connections. '%v' -> '%v' cid '%v': %v", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, res.Err)
				return
			}
			if readBytes != 1 {
				logrus.Infof("Header copy read bytes != 1. Error. Close connections. '%v' -> '%v' cid '%v'", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid)
				return
			}
			_, res.Err = targetConn.Write(buf[:1])
			if res.Err != nil {
				logrus.Infof("Error write header. Close connections. '%v' -> '%v' cid '%v': %v", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, res.Err)
				return
			}
			if needHeaderContent {
				headerContent.WriteByte(buf[0])
			}
		}
		if needHeaderContent {
			switch {
			case bytes.Equal(headerNameUpperCase, HEAD_CONNECTION):
				res.KeepAlive = bytes.EqualFold(HEAD_CONNECTION_KEEP_ALIVE, bytes.TrimSpace(headerContent.Bytes()))

			case bytes.Equal(headerNameUpperCase, HEAD_CONTENT_LENGTH):
				res.ContentLength, res.Err = strconv.ParseInt(string(bytes.TrimSpace(headerContent.Bytes())), 10, 64)
				if res.Err == nil {
					res.HasContextLength = true
					logrus.Debugf("Header content-length parsed from '%v' to '%v' cid '%v': %v", sourceConn.RemoteAddr(),
						targetConn.RemoteAddr(), cid, res.ContentLength)
				} else {
					logrus.Infof("Can't header content-length parsed from '%v' to '%v' cid '%v' content '%s': %v", sourceConn.RemoteAddr(),
						targetConn.RemoteAddr(), cid, headerContent.Bytes(), res.Err)
				}

			default:
				logrus.Debugf("ERROR. Unknow why i need header content. Code error. From '%v' to '%v' cid '%v', header name '%s'",
					sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, headerNameUpperCase,
				)
			}
		}
	}

	remoteTcpAddr := sourceConn.RemoteAddr().(*net.TCPAddr)
	remoteAddrString := remoteTcpAddr.IP.String()

	headerBuf := bytes.NewBuffer(buf)
	headerBuf.Reset()

	// Write real IP
	for _, header := range realIPHeaderNames {
		headerBuf.Write(header)
		headerBuf.WriteByte(':')
		headerBuf.WriteString(remoteAddrString)
		headerBuf.WriteString("\r\n")
	}

	// Write CID
	if *connectionIdHeader != "" {
		headerBuf.WriteString(*connectionIdHeader)
		headerBuf.WriteString(": ")
		headerBuf.WriteString(cid.String())
		headerBuf.WriteString("\r\n")
	}

	headerBuf.Write(additionalHeaders)
	headerBuf.Write([]byte("\r\n")) // end http headers
	logrus.Debugf("Add headers. '%v' -> '%v': '%s'", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), headerBuf.Bytes())

	_, res.Err = targetConn.Write(headerBuf.Bytes())
	if res.Err != nil {
		logrus.Infof("Error while write real ip headers to target '%v' -> '%v': %v", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), res.Err)
	}

	return
}

func startProxy(cid ConnectionID, targetAddr net.TCPAddr, in net.Conn) {
	switch *proxyMode {
	case "http":
		startProxyHTTP(cid, targetAddr, in)
	case "tcp":
		startProxyTCP(cid, targetAddr, in)
	default:
		in.Close()
		logrus.Panicf("Unknow proxy mode cid '%v': %v", cid, *proxyMode)
	}
}

func startProxyHTTP(cid ConnectionID, targetAddr net.TCPAddr, sourceConn net.Conn) {
	defer sourceConn.Close()

	targetConn, err := connectTo(cid, targetAddr)
	if err == nil {
		defer targetConn.Close()
		logrus.Debugf("Start http-proxy connection from '%v' to '%v' cid '%v'", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid)
	} else {
		logrus.Warnf("Cid '%v'. Can't connect to target '%v': %v", cid, targetAddr, err)
		return
	}


	buf := netbufGet()
	defer netbufPut(buf)
	var receivedBytesCount int64
	for {
		state := proxyHTTPHeaders(cid, targetConn, sourceConn)
		keepAlive := state.KeepAlive
		if state.Err != nil {
			logrus.Debug("Cid '%v'. Can't read headers: %v", cid, state.Err)
			return
		}
		if state.HasContextLength {
			logrus.Debugf("Start keep-alieved proxy. '%v' -> '%v' cid '%v', content-length '%v'", sourceConn.RemoteAddr(),
				targetConn.RemoteAddr(), cid, state.ContentLength)

			//request
			bytesCopied, err := io.CopyBuffer(targetConn, io.LimitReader(sourceConn, state.ContentLength), buf)
			receivedBytesCount += bytesCopied

			if err == nil {
				logrus.Debugf("Connection chunk copied '%v' -> '%v' cid '%v', bytes transferred '%v' (%v), error: %v", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, bytesCopied, receivedBytesCount, err)
			} else {
				logrus.Debugf("Connection closed '%v' -> '%v' cid '%v', bytes transferred '%v' (%v), error: %v", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, bytesCopied, receivedBytesCount, err)
				return
			}

			// proxy answer
			answerState := proxyHTTPHeaders(cid, sourceConn, targetConn)
			keepAlive = keepAlive && answerState.KeepAlive
			var reader io.Reader

			if answerState.HasContextLength {
				reader = io.LimitReader(targetConn, answerState.ContentLength)
			} else {
				reader = targetConn
			}

			_, err = io.CopyBuffer(sourceConn, reader, buf)
			if err != nil {
				logrus.Debugf("Cid '%v'. Can't copy answer to customer: %v", cid, err)
				return
			}
		} else {
			// answer from server proxy without changes
			go func() {
				buf := netbufGet()
				defer netbufPut(buf)

				_, err := io.CopyBuffer(sourceConn, targetConn, buf)
				logrus.Debugf("Connection closed with error1 '%v' -> '%v' cid '%v': %v", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, err)
				sourceConn.Close()
				targetConn.Close()
			}()

			logrus.Debugf("Start proxy without support keepalive middle headers '%v' -> '%v' cid '%v'", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid)
			bytesCopied, err := io.CopyBuffer(targetConn, sourceConn, buf)
			receivedBytesCount += bytesCopied
			if err == nil {
				logrus.Debugf("Connection closed '%v' -> '%v' cid '%v', bytes transferred '%v' (%v).", sourceConn, targetConn, cid, bytesCopied, receivedBytesCount)
			} else {
				logrus.Debugf("Connection closed '%v' -> '%v' cid '%v', bytes transferred '%v' (%v), error: %v", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, bytesCopied, receivedBytesCount, err)
			}
			return
		}

		if !keepAlive {
			return
		}
	}

}

func startProxyTCP(cid ConnectionID, targetAddr net.TCPAddr, sourceConn net.Conn) {
	targetConn, err := connectTo(cid, targetAddr)
	if err == nil {
		logrus.Infof("Start tcp-proxy connection from '%v' to'%v' cid '%v'", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid)
	} else {
		logrus.Warnf("CID '%v'. Can't connect to target addr '%v': %v", cid, targetAddr, err)
		return
	}

	go func() {
		buf := netbufGet()
		defer netbufPut(buf)

		_, err := io.CopyBuffer(targetConn, sourceConn, buf)
		logrus.Debugf("Connection closed with error2 '%v' -> '%v' cid '%v': %v", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, err)
		sourceConn.Close()
		targetConn.Close()
	}()
	go func() {
		buf := netbufGet()
		defer netbufPut(buf)

		_, err := io.CopyBuffer(sourceConn, targetConn, buf)
		logrus.Debugf("Connection closed with error3 '%v' -> '%v' cid '%v': %v", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, err)
		sourceConn.Close()
		targetConn.Close()
	}()
}
