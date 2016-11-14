package main

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"github.com/Sirupsen/logrus"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"encoding/pem"
	"crypto/ecdsa"
)

const (
	LETSENCRYPT_CREATE_CERTIFICATE_TIMEOUT = time.Minute
	LETSENCRYPT_PRODUCTION_API_URL         = "https://acme-v01.api.letsencrypt.org/directory"
	LETSENCRYPT_STAGING_API_URL            = "https://acme-staging.api.letsencrypt.org/directory"
	PRIVATE_KEY_BITS                       = 2048
	TRY_COUNT                              = 10
	RETRY_SLEEP                            = time.Second
)

var (
	bindTo            = flag.String("bind-to", ":443", "")
	targetPort        = flag.Int("target-port", 80, "")
	targetConnTimeout = flag.Duration("target-conn-timeout", time.Second, "")
	acmeApiUrl        = flag.String("acme-server", LETSENCRYPT_PRODUCTION_API_URL, "")
	acmeTestServer    = flag.Bool("test", false, "Use test lets encrypt server instead of <acme-server>")
	certDir           = flag.String("cert-dir", "certs", `Directory for save cached certificates. Set cert-dir="" for disable save certs`)
)

var (
	localIPs    []net.IP
	acmeService *acmeStruct
)

type stateStruct struct {
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

func certificateCacheGet(domain string) *tls.Certificate {
	if *certDir == "" {
		logrus.Debugf("Skip certificateCacheGet becouse certDir is empty")
		return nil
	}
	keyPath := filepath.Join(*certDir, domain+".key")
	certPath := filepath.Join(*certDir, domain+".crt")
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)

	switch {
	case err == nil:
		logrus.Debugf("Certificate files readed for domain '%v'", domain)
	case os.IsNotExist(err):
		logrus.Debugf("Certificate cache path key: '%v', cert: '%v'", keyPath, certPath)
		logrus.Infof("Have no certificate/key in cert-dir for domain '%v'", domain)
		return nil
	default:
		logrus.Errorf("Can't certificate/key load from file for domain '%v': %v", domain)
		return nil
	}

	if len(cert.Certificate) == 0 {
		logrus.Errorf("No certificates in file for domain '%v', file '%v'", domain, certPath)
		return nil
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err == nil {
		logrus.Debugf("Certificate parsed for domain '%v'", domain)
		return &cert
	} else {
		logrus.Errorf("Can't parse certificate for domain '%v': %v", domain, err)
		return nil
	}
}

func certificateCachePut(domain string, cert *tls.Certificate) {
	logrus.Infof("Certificate put to cache for domain '%v'", domain)
	if *certDir == "" {
		logrus.Debugf("Skip certificateCachePut becouse certDir is empty")
		return
	}
	err := os.MkdirAll(*certDir, 0600)
	if err != nil {
		logrus.Errorf("Can't create dir for save cached cert '%v':%v", *certDir, err)
		return
	}

	keyPath := filepath.Join(*certDir, domain+".key")
	certPath := filepath.Join(*certDir, domain+".crt")

	keyFile, err := os.Create(keyPath)
	if keyFile != nil {
		defer keyFile.Close()
	}
	if err != nil {
		logrus.Errorf("Can't open file for save key '%v':%v", keyPath, err)
		return
	}

	switch key := cert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		keyBytes := x509.MarshalPKCS1PrivateKey(key)
		pemBlock := pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
		err = pem.Encode(keyFile, &pemBlock)
		if err != nil {
			logrus.Errorf("Error while write bytes to rsa-key file '%v': %v", keyPath, err)
			return
		}
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			logrus.Errorf("Error while marshal ecdsa-key for domain '%v': %v", domain, err)
			return
		}
		pemBlock := pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
		err = pem.Encode(keyFile, &pemBlock)
		if err != nil {
			logrus.Errorf("Error while write bytes to ecdsa-key file '%v': %v", keyPath, err)
			return
		}
	}

	certFile, err := os.Create(certPath)
	if certFile != nil {
		defer certFile.Close()
	}
	if err != nil {
		logrus.Errorf("Can't open file for write certificate '%v': %v", certPath, err)
		return
	}
	for _, certBytes := range cert.Certificate {
		pemBlock := pem.Block{Type:"CERTIFICATE", Bytes:certBytes}
		err = pem.Encode(certFile, &pemBlock)
		if err != nil {
			logrus.Errorf("Can't write pem block to certificate '%v': %v", certPath, err)
			return
		}
	}

	logrus.Infof("Save certificate for domain '%v' to files: %v, %v", domain, keyPath, certPath)
}

func certificateGet(clientHello *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
	domain := strings.ToLower(clientHello.ServerName)
	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.Debugf("Required certificate for domain '%v'", domain)
	}

	if strings.HasSuffix(domain, ACME_DOMAIN_SUFFIX) {
		// force generate new certificate, without caching.
		return acmeService.CreateCertificate(domain)
	}

	cert = certificateCacheGet(domain)

	switch {
	case cert != nil && cert.Leaf.NotAfter.Before(time.Now()):
		logrus.Warnf("Expired certificate got from cache for domain '%v'", domain)
		// pass to create new certificate.
	case cert != nil:
		return cert, nil
	default:
		// pass
	}

	cert, err = acmeService.CreateCertificate(domain)
	if err == nil {
		certificateCachePut(domain, cert)
	}
	return cert, err
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
		MinVersion:     tls.VersionSSL30,
	}
	tlsConn := tls.Server(in, &tlsConfig)
	err = tlsConn.Handshake()
	logrus.Debug("tls ciper:", tlsConn.ConnectionState().CipherSuite)
	if err == nil {
		logrus.Debug("Handshake for incoming:", tlsConn.RemoteAddr().String())
	} else {
		logrus.Infof("Error in tls handshake from '%v':%v", tlsConn.RemoteAddr(), err)
	}

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
			ipStrings[i] = addr.String()
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
