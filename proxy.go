package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
)

const (
	NETBUF_SIZE = 2048 // bytes
)

//go:generate stringer -type KeepAliveModeType
type KeepAliveModeType int

const (
	KEEPALIVE_TRANSPARENT KeepAliveModeType = iota
	KEEPALIVE_NO_BACKEND
)

const (
	KEEPALIVE_TRANSPARENT_STRING = "transparent"
	KEEPALIVE_NO_BACKEND_STRING  = "nobackend"
)

var (
	poolNetBuffers sync.Pool
	keepAliveMode  KeepAliveModeType
)

// var-constants
var (
	HEAD_CONNECTION         = []byte("CONNECTION")
	HEAD_CONNECTION_CLOSE   = []byte("CLOSE")
	HEAD_CONTENT_LENGTH     = []byte("CONTENT-LENGTH")
	HEAD_HTTP_1_1           = []byte("HTTP/1.1")
	HEAD_HEAD_METHOD_PREFIX = []byte("HEAD ")
	STATUS_LINE_PREFIX      = []byte("HTTP/1.")

	// https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#Summary_table
	HTTP_METHOD_WITHOUT_BODY_PREFIXES = [][]byte{[]byte("GET "), []byte("HEAD "), []byte("DELETE "), []byte("TRACE ")}

	STATUS_CODES_WITHOUT_BODY = [][]byte{[]byte("1"), []byte("204"), []byte("304")}
)

func connectTo(cid ConnectionID, targetAddr net.TCPAddr) (conn *net.TCPConn, err error) {
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

const (
	PROXY_KEEPALIVE_NOTHING = iota
	PROXY_KEEPALIVE_FORCE
	PROXY_KEEPALIVE_DROP
)

type proxyHTTPHeadersRes struct {
	KeepAlive        bool
	ContentLength    int64
	HasContentLength bool
	HasBody          bool
	Err              error
	IsHeadMethod     bool
}

func proxyHTTPHeaders(cid ConnectionID, targetConn net.Conn, sourceConn net.Conn, proxyKeepAliveMode int) (
	res proxyHTTPHeadersRes) {
	res.HasBody = true

	buf := netbufGet()
	defer netbufPut(buf)
	var totalReadBytes int

	isFirstLine := true
	// Read lines
readHeaderLines:
	for {
		var i int
		var headerStart []byte
		for i = 1; i < len(buf); i++ {
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
				headerStart = buf[1 : i+1]
				logrus.Debugf("Header Name '%v' -> '%v' cid '%v': '%s'", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, buf[:i])
				break
			}
		}
		if len(headerStart) == 0 {
			logrus.Infof("Header line longer then buffer (%v bytes). Force close connection. '%v' -> '%v' cid '%v'.", len(buf), sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid)
			res.Err = errors.New("Very long header name")
			return
		}

		if isFirstLine {
			isFirstLine = false

			lastIndex := len(headerStart) - 1
			for lastIndex > 0 && headerStart[lastIndex] == '\r' || headerStart[lastIndex] == '\n' {
				lastIndex--
			}
			trimmedHeader := headerStart[:lastIndex+1]
			if bytes.HasPrefix(trimmedHeader, STATUS_LINE_PREFIX) {
				// Response
				statusLine := trimmedHeader
				if bytes.HasPrefix(statusLine, HEAD_HTTP_1_1) {
					res.KeepAlive = true
				}

				var statusCode []byte
				if statusCodeIndex := bytes.IndexByte(statusLine, ' '); statusCodeIndex >= 0 {
					statusCode = statusLine[statusCodeIndex+1 : statusCodeIndex+1+3] // 3 digit
				}
				for _, statusCodeWithoutBody := range STATUS_CODES_WITHOUT_BODY {
					if bytes.HasPrefix(statusCode, statusCodeWithoutBody) {
						res.HasBody = false
					}
				}
			} else {
				// request
				requestLine := trimmedHeader
				if bytes.HasSuffix(requestLine, HEAD_HTTP_1_1) {
					res.KeepAlive = true
				}
				if bytes.HasPrefix(requestLine, HEAD_HEAD_METHOD_PREFIX) {
					res.IsHeadMethod = true
				}

				for _, testMethod := range HTTP_METHOD_WITHOUT_BODY_PREFIXES {
					if bytes.HasPrefix(requestLine, testMethod) {
						res.HasBody = false
					}
				}
			}
		}

		// Empty line - end http headers
		if bytes.Equal(headerStart, []byte("\n")) || bytes.Equal(headerStart, []byte("\r\n")) {
			break readHeaderLines
		}

		headerName := headerStart[:len(headerStart)-1] // Cut trailing colon from start

		skipHeader := false
		for _, ownHeader := range cutHeaders {
			if bytes.EqualFold(ownHeader, headerName) {
				skipHeader = true
				break
			}
		}

		switch proxyKeepAliveMode {
		case PROXY_KEEPALIVE_NOTHING:
			// pass
		case PROXY_KEEPALIVE_DROP:
			skipHeader = skipHeader || bytes.EqualFold(headerName, HEAD_CONNECTION)
		case PROXY_KEEPALIVE_FORCE:
			skipHeader = skipHeader || bytes.EqualFold(headerName, HEAD_CONNECTION)
		default:
			panic("Unknow proxyKeepAliveMode")
		}

		if skipHeader {
			logrus.Debugf("Skip header: '%v' -> '%v' cid '%v': '%s'", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, headerName)
		} else {
			logrus.Debugf("Copy header: '%v' -> '%v' cid '%v': '%s'", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, headerName)

			_, res.Err = targetConn.Write(headerStart)
			if res.Err != nil {
				logrus.Infof("Write header start, from '%v' to '%v' cid '%v', headerStart='%s': %v", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, headerStart, res.Err)
				return
			}
		}

		headerContent := bytes.NewBuffer(buf[1+len(headerStart):])
		headerContent.Reset()

		needHeaderContent := bytes.EqualFold(headerName, HEAD_CONTENT_LENGTH) || bytes.EqualFold(headerName, HEAD_CONNECTION)

		buf[0] = 0
		for buf[0] != '\n' {
			var readBytes int
			readBytes, res.Err = sourceConn.Read(buf[:1])
			if res.Err != nil {
				logrus.Infof("Error read header to copy. Close connections. '%v' -> '%v' cid '%v': %v", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, res.Err)
				return
			}
			if readBytes != 1 {
				logrus.Infof("Header copy read bytes != 1. Error. Close connections. '%v' -> '%v' cid '%v'", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid)
				res.Err = errors.New("Can't read a byte from source conn")
				return
			}
			if !skipHeader {
				_, res.Err = targetConn.Write(buf[:1])
			}
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
			case bytes.EqualFold(headerName, HEAD_CONNECTION):
				res.KeepAlive = !bytes.EqualFold(HEAD_CONNECTION_CLOSE, bytes.TrimSpace(headerContent.Bytes()))

			case bytes.EqualFold(headerName, HEAD_CONTENT_LENGTH):
				res.ContentLength, res.Err = strconv.ParseInt(string(bytes.TrimSpace(headerContent.Bytes())), 10, 64)
				if res.Err == nil {
					res.HasContentLength = true
					logrus.Debugf("Header content-length parsed from '%v' to '%v' cid '%v': %v", sourceConn.RemoteAddr(),
						targetConn.RemoteAddr(), cid, res.ContentLength)
				} else {
					logrus.Infof("Can't header content-length parsed from '%v' to '%v' cid '%v' content '%s': %v", sourceConn.RemoteAddr(),
						targetConn.RemoteAddr(), cid, headerContent.Bytes(), res.Err)
				}

			default:
				logrus.Debugf("ERROR. Unknow why i need header content. Code error. From '%v' to '%v' cid '%v', header name '%s'",
					sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, headerName,
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

	// Write Keepalive
	switch proxyKeepAliveMode {
	case PROXY_KEEPALIVE_FORCE:
		headerBuf.WriteString("Connection: Keep-Alive\r\n")
	case PROXY_KEEPALIVE_DROP:
		headerBuf.WriteString("Connection: Close\r\n")
	case PROXY_KEEPALIVE_NOTHING:
		// pass
	default:
		panic(errors.New("Unknown proxy keepalive mode"))
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

func startProxyHTTP(cid ConnectionID, targetAddr net.TCPAddr, customerConn net.Conn) {
	defer customerConn.Close()

	var backendConn *net.TCPConn
	defer func() {
		if backendConn != nil {
			backendConn.Close()
		}
	}()
	var err error

	buf := netbufGet()
	defer netbufPut(buf)
	var receivedBytesCount int64
	for {
		if backendConn == nil {
			backendConn, err = connectTo(cid, targetAddr)
			if err == nil {
				logrus.Debugf("Start http-proxy connection from '%v' to '%v' cid '%v'", customerConn.RemoteAddr(), backendConn.RemoteAddr(), cid)
			} else {
				logrus.Warnf("Cid '%v'. Can't connect to target '%v': %v", cid, targetAddr, err)
				return
			}
		}

		proxyKeepAliveModeToBackend := PROXY_KEEPALIVE_NOTHING
		proxyKeepAliveModeToCustomer := PROXY_KEEPALIVE_NOTHING
		if keepAliveMode == KEEPALIVE_NO_BACKEND {
			customerConn.SetReadDeadline(time.Now().Add(*keepAliveCustomerTimeout))
			proxyKeepAliveModeToBackend = PROXY_KEEPALIVE_DROP
			proxyKeepAliveModeToCustomer = PROXY_KEEPALIVE_FORCE
		}
		state := proxyHTTPHeaders(cid, backendConn, customerConn, proxyKeepAliveModeToBackend)
		if keepAliveMode == KEEPALIVE_NO_BACKEND {
			// Current not timeout during proxy request.
			customerConn.SetReadDeadline(time.Time{})
		}
		keepAlive := state.KeepAlive
		if state.Err != nil {
			logrus.Debugf("Cid '%v'. Can't read headers: %v", cid, state.Err)
			return
		}
		if state.HasContentLength || !state.HasBody {
			logrus.Debugf("Start keep-alieved proxy. '%v' -> '%v' cid '%v', content-length '%v'", customerConn.RemoteAddr(),
				backendConn.RemoteAddr(), cid, state.ContentLength)

			if state.HasBody {
				//request
				bytesCopied, err := io.CopyBuffer(backendConn, io.LimitReader(customerConn, state.ContentLength), buf)
				receivedBytesCount += bytesCopied

				if err == nil {
					logrus.Debugf("Connection chunk copied '%v' -> '%v' cid '%v', bytes transferred '%v' (%v), error: %v", customerConn.RemoteAddr(), backendConn.RemoteAddr(), cid, bytesCopied, receivedBytesCount, err)
				} else {
					logrus.Debugf("Connection closed '%v' -> '%v' cid '%v', bytes transferred '%v' (%v), error: %v", customerConn.RemoteAddr(), backendConn.RemoteAddr(), cid, bytesCopied, receivedBytesCount, err)
					return
				}
			}

			// proxy answer
			answerState := proxyHTTPHeaders(cid, customerConn, backendConn, proxyKeepAliveModeToCustomer)
			keepAlive = keepAlive && answerState.KeepAlive
			var reader io.Reader

			if answerState.HasBody && !state.IsHeadMethod {
				if answerState.HasContentLength {
					reader = io.LimitReader(backendConn, answerState.ContentLength)
				} else {
					reader = backendConn
				}
			}

			_, err = io.CopyBuffer(customerConn, reader, buf)
			if err != nil {
				logrus.Debugf("Cid '%v'. Can't copy answer to customer: %v", cid, err)
				return
			}

			switch keepAliveMode {
			case KEEPALIVE_TRANSPARENT:
				// pass
				// keep connections
			case KEEPALIVE_NO_BACKEND:
				backendConn.Close()
				backendConn = nil
			default:
				panic(fmt.Errorf("I doesn't know keep alive mode '%v'", keepAliveMode))
			}
		} else {
			// answer from server proxy without changes
			go func() {
				buf := netbufGet()
				defer netbufPut(buf)

				_, err := io.CopyBuffer(customerConn, backendConn, buf)
				logrus.Debugf("Connection closed with error1 '%v' -> '%v' cid '%v': %v", customerConn.RemoteAddr(), backendConn.RemoteAddr(), cid, err)
				customerConn.Close()
				backendConn.Close()
			}()

			logrus.Debugf("Start proxy without support keepalive middle headers '%v' -> '%v' cid '%v'", customerConn.RemoteAddr(), backendConn.RemoteAddr(), cid)
			bytesCopied, err := io.CopyBuffer(backendConn, customerConn, buf)
			receivedBytesCount += bytesCopied
			if err == nil {
				logrus.Debugf("Connection closed '%v' -> '%v' cid '%v', bytes transferred '%v' (%v).", customerConn, backendConn, cid, bytesCopied, receivedBytesCount)
			} else {
				logrus.Debugf("Connection closed '%v' -> '%v' cid '%v', bytes transferred '%v' (%v), error: %v", customerConn.RemoteAddr(), backendConn.RemoteAddr(), cid, bytesCopied, receivedBytesCount, err)
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
