package main

import (
	"bytes"
	"errors"
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
	zeroTime       = time.Time{}
)

// var-constants
var (
	HEAD_CONNECTION         = []byte("CONNECTION")
	HEAD_CONNECTION_CLOSE   = []byte("CLOSE")
	HEAD_CONTENT_LENGTH     = []byte("CONTENT-LENGTH")
	HEAD_HTTP_1_1           = []byte("HTTP/1.1")
	HEAD_HEAD_METHOD_PREFIX = []byte("HEAD ")
	STATUS_LINE_PREFIX      = []byte("HTTP/1.")
	TRANSFER_ENCODING       = []byte("Transfer-Encoding")
	CHUNKED                 = []byte("chunked")

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
	IsLimited        bool
	Chunked          bool
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
				//var headerName []byte
				//if len(headerStart) > 0 {
				//	headerName = headerStart[:len(headerStart)-1]
				//}
				//logrus.Debugf("Header Name '%v' -> '%v' cid '%v': '%s'", sourceConn.RemoteAddr(), targetConn.RemoteAddr(), cid, headerName)
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
						res.IsLimited = true
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
						res.IsLimited = true
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
		case PROXY_KEEPALIVE_DROP, PROXY_KEEPALIVE_FORCE:
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

		needHeaderContent := bytes.EqualFold(headerName, HEAD_CONTENT_LENGTH) || bytes.EqualFold(headerName, HEAD_CONNECTION) || bytes.EqualFold(headerName, TRANSFER_ENCODING)

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
					res.IsLimited = true
					logrus.Debugf("Header content-length parsed from '%v' to '%v' cid '%v': %v", sourceConn.RemoteAddr(),
						targetConn.RemoteAddr(), cid, res.ContentLength)
				} else {
					logrus.Infof("Can't header content-length parsed from '%v' to '%v' cid '%v' content '%s': %v", sourceConn.RemoteAddr(),
						targetConn.RemoteAddr(), cid, headerContent.Bytes(), res.Err)
				}
			case bytes.EqualFold(headerName, TRANSFER_ENCODING):
				encoding := bytes.TrimSpace(headerContent.Bytes())
				if bytes.EqualFold(encoding, CHUNKED) {
					res.Chunked = true
					res.IsLimited = true
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

func proxyHTTPBody(cid ConnectionID, dst, src net.Conn, headers proxyHTTPHeadersRes) (err error) {
	switch {
	case !headers.HasBody:
		logrus.Debugf("Cid '%v'. No body.", cid)
	case headers.HasContentLength:
		logrus.Debugf("Cid '%v'. '%v' -> '%v'. Proxy with content length: %v", cid, src.RemoteAddr(), dst.RemoteAddr(), headers.ContentLength)
		mem := netbufGet()
		//_, err = io.CopyBuffer(dst, io.LimitReader(src, headers.ContentLength), mem)
		if headers.ContentLength == 7 {
			logrus.Debug(7777)
		}
		for i := int64(0); i < headers.ContentLength; i++ {
			buf := make([]byte, 1)
			_, err := src.Read(buf)
			if err != nil {
				s := err.Error()
				_ = s
			}
			dst.Write(buf)
		}
		netbufPut(mem)
		logrus.Debugf("Cid '%v'. '%v' -> '%v'. Proxy content finished.", cid, src.RemoteAddr(), dst.RemoteAddr())
	case headers.Chunked:
		mem := netbufGet()
		defer netbufPut(mem)

		logrus.Debugf("Cid '%v'. '%v' -> '%v'. Start proxy chunks", cid, src.RemoteAddr(), dst.RemoteAddr())
		for {
			buf := bytes.NewBuffer(mem[1:])
			buf.Reset()

			// read chunk header
			b := &mem[0]
			*b = 0
			for *b != '\n' {
				readBytes, err := src.Read(mem[:1])
				if err != nil {
					logrus.Debugf("Cid '%v'. Can't read chunk header: %v", cid, err)
					return err
				}
				if readBytes == 0 {
					continue
				}
				buf.WriteByte(*b)
			}
			chunkHeader := buf.Bytes()
			dst.Write(chunkHeader)
			noDigitIndex := -0
			for {
				if len(chunkHeader) <= noDigitIndex {
					break
				}
				if !isHexDigit(chunkHeader[noDigitIndex]) {
					break
				}
				noDigitIndex++
			}

			chunkLen, err := strconv.ParseInt(string(chunkHeader[:noDigitIndex]), 16, 64)
			if err != nil {
				logrus.Debugf("Cid '%v'. '%v' -> '%v'. Can't parse chunk len '%s': %v", cid, src.RemoteAddr(), dst.RemoteAddr(), chunkHeader, err)
				return err
			}

			if chunkLen == 0 {
				logrus.Debugf("Cid '%v'. '%v' -> '%v'. Complete proxy chunks. Proxy trailer.", cid, src.RemoteAddr(), dst.RemoteAddr())
				buf := bytes.NewBuffer(mem[1:])

				for {
					// read line
					buf.Reset()
					for {
						readBytes, err := src.Read(mem[:1])
						if err != nil {
							logrus.Debugf("Cid '%v'. '%v' -> '%v'. Error while read chunked trailer: %v", cid, src.RemoteAddr(), err)
							return err
						}
						if readBytes == 0 {
							continue
						}
						err = buf.WriteByte(mem[0])
						if err != nil {
							logrus.Debugf("Cid '%v'. '%v' -> '%v'. Error while write chunked trailer to buffer: %v", cid, src.RemoteAddr(), err)
						}

						if mem[0] == '\n' {
							break
						}
					}
					line := buf.Bytes()
					_, err = dst.Write(line)
					if err != nil {
						logrus.Debugf("Cid '%v'. '%v' -> '%v'. Error while write chunked trailer dst: %v", cid, src.RemoteAddr(), err)
						return err
					}
					if len(line) == 2 { // \r\n only
						logrus.Debugf("Cid '%v'. '%v' -> '%v'. Complete proxy trailer.", cid, src.RemoteAddr(), dst.RemoteAddr())
						break
					}
				}

				return nil
			} else {
				logrus.Debugf("Cid '%v'. '%v' -> '%v'. Proxy chunk: %v", cid, src.RemoteAddr(), dst.RemoteAddr(), chunkLen)
				_, err = io.CopyBuffer(dst, io.LimitReader(src, chunkLen+2), mem) // + \r\n at end of data
			}
		}

	default:
		logrus.Debugf("Cid '%v'. '%v' -> '%v'. Proxy content until close connection", cid, src.RemoteAddr(), dst.RemoteAddr())
		buf := netbufGet()
		_, err = io.CopyBuffer(dst, src, buf)
		netbufPut(buf)
		logrus.Debugf("Cid '%v'. '%v' -> '%v'. Proxy content finished.", cid, src, dst)
	}
	return err
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
			proxyKeepAliveModeToBackend = PROXY_KEEPALIVE_DROP
			proxyKeepAliveModeToCustomer = PROXY_KEEPALIVE_FORCE
		}
		logrus.Debugf("Cid '%v'. Start proxy request", cid)
		customerConn.SetReadDeadline(time.Now().Add(*keepAliveCustomerTimeout))
		requestHeadersRes := proxyHTTPHeaders(cid, backendConn, customerConn, proxyKeepAliveModeToBackend)
		customerConn.SetReadDeadline(time.Now().Add(*maxRequestTime))

		if requestHeadersRes.Err != nil {
			logrus.Debugf("Cid '%v'. Can't read headers: %v", cid, requestHeadersRes.Err)
			return
		}
		if requestHeadersRes.IsLimited {
			err = proxyHTTPBody(cid, backendConn, customerConn, requestHeadersRes)
		} else {
			go func() {
				// proxy request until close connection
				logrus.Debugf("Cid '%v'. Unlimited request mode.", cid)
				proxyHTTPBody(cid, backendConn, customerConn, requestHeadersRes)
			}()
		}

		responseHeadersRes := proxyHTTPHeaders(cid, customerConn, backendConn, proxyKeepAliveModeToCustomer)
		if responseHeadersRes.Err != nil {
			return
		}
		if requestHeadersRes.IsHeadMethod {
			logrus.Debugf("Cid '%v'. No proxy body for HEAD method.", cid)
		} else {
			err = proxyHTTPBody(cid, customerConn, backendConn, responseHeadersRes)
			if err != nil {
				logrus.Debugf("Cid '%v'. Error while proxy body: %v", cid, err)
			}
		}

		if proxyKeepAliveModeToCustomer == PROXY_KEEPALIVE_DROP || !requestHeadersRes.KeepAlive || !requestHeadersRes.IsLimited {
			// close connections by defer
			return
		}

		if proxyKeepAliveModeToBackend == PROXY_KEEPALIVE_DROP || !responseHeadersRes.KeepAlive || !responseHeadersRes.IsLimited {
			backendConn.Close()
			backendConn = nil
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

func isHexDigit(b byte) bool {
	return ('0' <= b && b <= '9') || ('a' <= b && b <= 'f') || ('A' <= b && b <= 'F')
}
