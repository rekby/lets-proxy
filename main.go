package main

import (
	"crypto/tls"
	"flag"
	"github.com/Sirupsen/logrus"
	"io"
	"log"
	"net"
	"strings"
	"time"
	"crypto/rsa"
	cryptorand "crypto/rand"
	"context"
)

const (
	LETSENCRYPT_CREATE_CERTIFICATE_TIMEOUT = time.Minute
	LETSENCRYPT_PRODUCTION_API_URL         = "https://acme-v01.api.letsencrypt.org/directory"
	LETSENCRYPT_STAGING_API_URL            = "https://acme-staging.api.letsencrypt.org/directory"
	PRIVATE_KEY_BITS=2048
	TRY_COUNT = 10
	RETRY_SLEEP = time.Second
)

var (
	bindTo            = flag.String("bind-to", ":443", "")
	targetPort        = flag.Int("target-port", 80, "")
	targetConnTimeout = flag.Duration("target-conn-timeout", time.Second, "")
	acmeApiUrl        = flag.String("acme-server", LETSENCRYPT_PRODUCTION_API_URL, "")
	acmeTestServer    = flag.Bool("test-server", false, "Use test lets encrypt server instead of <acme-server>")
)

var (
	localIPs    []net.IP
	acmeService *acmeStruct
)

type stateStruct struct{
	PrivateKey *rsa.PrivateKey
}

func main() {
	var err error

	flag.Parse()

	// Init
	logrus.SetLevel(logrus.DebugLevel)
	localIPs = getLocalIPs()
	acmeService = &acmeStruct{}

	// init service
	acmeService = &acmeStruct{}
	if *acmeTestServer {
		acmeService.serverAddress = LETSENCRYPT_STAGING_API_URL
	} else {
		acmeService.serverAddress = *acmeApiUrl
	}
	logrus.Info("Generate private keys")
	acmeService.privateKey, err = rsa.GenerateKey(cryptorand.Reader, PRIVATE_KEY_BITS)
	if err != nil {
		logrus.Panic("Can't generate private key")
	}
	acmeService.Init()
	acmeService.RegisterEnsure(context.TODO())

	// Start listen
	tcpAddr, err := net.ResolveTCPAddr("tcp", *bindTo)
	if err != nil {
		logrus.Panicf("Can't resolve bind-to address '%v': %v", *bindTo, err)
	}
	logrus.Errorf("Start listen: %v", tcpAddr)

	listener, err := net.ListenTCP("tcp", tcpAddr)
	logrus.Debug(listener.Addr())
	logrus.Debugf("%#v", listener)
	if err != nil {
		panic(err)
	}
	for {
		tcpConn, err := listener.AcceptTCP()
		if err != nil {
			panic(err)
		}
		go handleTcpConnection(tcpConn)
	}
}

func certificateGet(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := strings.ToLower(clientHello.ServerName)
	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.Debugf("Required certificate for domain '%v'", domain)
	}
	return acmeService.CreateCertificate(domain)
}

func handleTcpConnection(in *net.TCPConn) {
	target, err := getTargetConn(in)
	if err != nil {
		logrus.Errorf("Can't get target IP/port for '%v': %v", target.String(), err)
		return
	}

	// handle ssl
	tlsConfig := tls.Config{
		GetCertificate: certificateGet,
	}
	tlsConn := tls.Server(in, &tlsConfig)

	startProxy(target, tlsConn)
}

func getLocalIPs() (res []net.IP) {
	bindAddr, _ := net.ResolveTCPAddr("tcp", *bindTo)
	if bindAddr.IP.IsUnspecified() || len(bindAddr.IP) == 0 {
		addresses, err := net.InterfaceAddrs()
		if err != nil {
			log.Panic("Can't get local ip addresses:", err)
		}
		res = make([]net.IP, 0, len(addresses))
		for _, addr := range addresses {
			logrus.Debug("Local ip:", addr.String())
			ip, _, err := net.ParseCIDR(addr.String())
			if err == nil {
				res = append(res, ip)
			} else {
				logrus.Errorf("Can't parse local ip '%v': %v", addr.String(), err)
			}
		}
	} else {
		res = []net.IP{bindAddr.IP}
	}
	if logrus.GetLevel() >= logrus.InfoLevel {
		ipStrings := make([]string, len(res))
		for i, addr := range res {
			ipStrings[i] =addr.String()
		}
		logrus.Info("Local ip:", ipStrings)
	}
	return res
}

func getTargetConn(in *net.TCPConn) (net.TCPAddr, error) {
	targetAddrP, err := net.ResolveTCPAddr("tcp", in.LocalAddr().String())
	if err != nil {
		logrus.Errorf("Can't resolve local addr '%v': %v", in.LocalAddr().String(), err)
		return net.TCPAddr{}, err
	}
	targetAddrP.Port = *targetPort
	return *targetAddrP, nil
}

func startProxy(targetAddr net.TCPAddr, in net.Conn) {
	logrus.Infof("Start proxy connection from '%v' to'%v'", in.RemoteAddr().String(), targetAddr.String())

	targetConnCommon, err := net.DialTimeout("tcp", targetAddr.String(), *targetConnTimeout)
	if err != nil {
		logrus.Warnf("Can't connect to target '%v': %v", targetAddr.String(), err)
		return
	}

	targetConn := targetConnCommon.(*net.TCPConn)
	go func() {
		io.Copy(in, targetConn)
		in.Close()
		targetConn.Close()
	}()
	go func() {
		io.Copy(targetConn, in)
		in.Close()
		targetConn.Close()
	}()
}
