package main

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"flag"
	"github.com/Sirupsen/logrus"
	"github.com/hashicorp/golang-lru"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

const (
	LETSENCRYPT_CREATE_CERTIFICATE_TIMEOUT = time.Minute
	LETSENCRYPT_PRODUCTION_API_URL         = "https://acme-v01.api.letsencrypt.org/directory"
	LETSENCRYPT_STAGING_API_URL            = "https://acme-staging.api.letsencrypt.org/directory"
	PRIVATE_KEY_BITS                       = 2048
	TRY_COUNT                              = 10
	RETRY_SLEEP                            = time.Second * 5
	STATE_FILEMODE                         = 0600
)

var (
	bindTo            = flag.String("bind-to", ":443", "")
	targetPort        = flag.Int("target-port", 80, "")
	targetConnTimeout = flag.Duration("target-conn-timeout", time.Second, "")
	acmeApiUrl        = flag.String("acme-server", LETSENCRYPT_PRODUCTION_API_URL, "")
	acmeTestServer    = flag.Bool("test", false, "Use test lets encrypt server instead of <acme-server>")
	certDir           = flag.String("cert-dir", "certificates", `Directory for save cached certificates. Set cert-dir=- for disable save certs`)
	certMemCount      = flag.Int("in-memory-cnt", 10000, "How many count of certs cache in memory for prevent parse it from file")
	stateFilePath     = flag.String("state-file", "state.json", "Path to save some state data, for example account key")
	proxyMode         = flag.String("proxy-mode", "http", "Proxy-mode after tls handle (http|tcp).")
)

var (
	localIPs    []net.IP
	acmeService *acmeStruct
)

type stateStruct struct {
	PrivateKey *rsa.PrivateKey
	changed    bool
}

func main() {
	var err error

	flag.Parse()

	// Init
	logrus.SetLevel(logrus.DebugLevel)

	if *proxyMode != "http" && *proxyMode != "tcp" {
		logrus.Panicf("Unknow proxy mode: %v", *proxyMode)
	}
	logrus.Info("Proxy mode: %v", *proxyMode)

	localIPs = getLocalIPs()
	acmeService = &acmeStruct{}
	if *certMemCount > 0 {
		logrus.Infof("Create memory cache for '%v' certificates", *certMemCount)
		certMemCache, err = lru.New(*certMemCount)
		if err != nil {
			logrus.Errorf("Can't create memory cache:", err)
			certMemCache = nil
		}
	} else {
		logrus.Info("Memory cache turned off")
	}
	if *certDir == "-" {
		*certDir = ""
	}

	// init service
	var state stateStruct
	stateBytes, err := ioutil.ReadFile(*stateFilePath)
	if err == nil {
		err = json.Unmarshal(stateBytes, &state)
		if err != nil {
			logrus.Errorf("Can't parse state file '%v': %v", *stateFilePath, err)
		}
	} else {
		logrus.Errorf("Can't read state file '%v': %v", *stateFilePath, err)
	}

	acmeService = &acmeStruct{}
	if *acmeTestServer {
		acmeService.serverAddress = LETSENCRYPT_STAGING_API_URL
	} else {
		acmeService.serverAddress = *acmeApiUrl
	}

	if state.PrivateKey == nil {
		logrus.Info("Generate private keys")
		state.PrivateKey, err = rsa.GenerateKey(cryptorand.Reader, PRIVATE_KEY_BITS)
		state.changed = true
		if err != nil {
			logrus.Panic("Can't generate private key")
		}
	} else {
		logrus.Debugf("Skip generate keys - it was read from state")
	}

	saveState(state)

	acmeService.privateKey = state.PrivateKey

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
	case cert != nil && cert.Leaf != nil && cert.Leaf.NotAfter.Before(time.Now()):
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

func saveState(state stateStruct) {
	if state.changed {
		logrus.Infof("Saving state to '%v'", *stateFilePath)
	} else {
		logrus.Debug("Skip save state becouse it isn't changed")
		return
	}
	stateBytes, err := json.MarshalIndent(&state, "", "    ")
	if err != nil {
		logrus.Errorf("Can't save state to file '%v': %v", *stateFilePath, err)
		return
	}
	err = ioutil.WriteFile(*stateFilePath+".new", stateBytes, STATE_FILEMODE)
	if err != nil {
		logrus.Errorf("Error while write state bytes to file '%v': %v", *stateFilePath+".new", err)
		return
	}
	err = os.Rename(*stateFilePath, *stateFilePath+".old")
	if err != nil {
		logrus.Errorf("Can't rename '%v' to '%v': %v", *stateFilePath, *stateFilePath+".old", err)
	}
	err = os.Rename(*stateFilePath+".new", *stateFilePath)
	if err != nil {
		logrus.Errorf("Can't rename '%v' to '%v': %v", *stateFilePath+".new", *stateFilePath, err)
	}
}
