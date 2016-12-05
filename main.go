package main

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/hashicorp/golang-lru"
	"github.com/kardianos/service"
	"gopkg.in/natefinch/lumberjack.v2"
	"io"
	"io/ioutil"
	"math"
	"net"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
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
	SERVICE_NAME_EXAMPLE                   = "<service-name>"
	WORKING_DIR_ARG_NAME                   = "working-dir"
	DEFAULT_BIND_PORT                      = 443
	DAEMON_KEY_NAME                        = "daemon"
)

var (
	acmeParallelCount             = flag.Int("acme-parallel", 10, "count of parallel requests for acme server")
	acmeServerUrl                 = flag.String("acme-server", LETSENCRYPT_PRODUCTION_API_URL, "")
	additionalHeadersParam        = flag.String("additional-headers", "X-Forwarded-Proto=https", "Additional headers for proxied requests. Several headers separated by comma.")
	allowIPRefreshInterval        = flag.Duration("allow-ips-refresh", time.Hour, "For local, domain and ifconfig.io - how often allow ip addresses will be refreshed. Allowable format https://golang.org/pkg/time/#ParseDuration")
	allowIPsString                = flag.String("allowed-ips", "auto", "allowable ip-addresses (ipv4,ipv6) separated by comma. It can contain special variables (without quotes): 'auto' - try to auto determine allowable address, it logic can change between versions. 'local' (all autodetected local IP) and 'nat' - detect IP by request to http://ifconfig.io/ip - it need for public ip autodetection behinde nat.")
	bindToS                       = flag.String("bind-to", ":443", "")
	blockBadDomainDuration        = flag.Duration("block-bad-domain-duration", time.Hour, "Disable try obtain certtificate for domain after error")
	certDir                       = flag.String("cert-dir", "certificates", `Directory for save cached certificates. Set cert-dir=- for disable save certs`)
	certJsonSave                  = flag.Bool("cert-json", false, "Save json info about certificate near the certificate file with same name with .json extension")
	connectionIdHeader            = flag.String("connection-id-header", "", "Header name for send connection id to backend in http proxy mode. Default it isn't send.")
	daemonFlag                    = flag.Bool(DAEMON_KEY_NAME, false, "Start as background daemon. Supported in unix OS only.")
	defaultDomain                 = flag.String("default-domain", "", "Usage when SNI domain doesn't available (have zero length). For example client doesn't support SNI. It used for obtain and use certificate only. It isn't forse set header HOST in request.")
	getIPByExternalRequestTimeout = flag.Duration("get-ip-by-external-request-timeout", 10*time.Second, "Timeout for request to external service for ip detection. For example when server behind nat.")
	inMemoryCertCount             = flag.Int("in-memory-cnt", 100, "How many count of certs cache in memory for prevent parse it from file")
	logLevel                      = flag.String("loglevel", "warning", "fatal|error|warning|info|debug")
	logOutput                     = flag.String("logout", "-", "Path to logout. Special: '-' (without quotes) - stderr")
	logrotateMaxAge               = flag.Int("logrotate-age", 30, "How many days keep old backups")
	logrotateMaxCount             = flag.Int("logrotate-count", 30, "How many old backups keep. 0 mean infinite")
	logrotateMb                   = flag.Int("logrotate-mb", 100, "logrotate by size in megabytes. 0 Mean no logrotate by size.")
	logrotateTime                 = flag.String("logrotate-time", "", "minutely|hourly|daily|weekly|monthly|yearly|\"\", empty or none mean no logrotate by time. Weekly - rotate log at midnight from sunday to monday")
	minTLSVersion                 = flag.String("min-tls", "", "Minimul supported tls version: ssl3,tls10,tls11,tls12. Default is golang's default.")
	noLogStderr                   = flag.Bool("no-log-stderr", false, "supress log to stderr")
	nonCertDomains                = flag.String("non-cert-domains", "", "No obtain certificate for mathed domains. Regexpes separated by comma.")
	pidFilePath                   = flag.String("pid-file", "lets-proxy.pid", "Write pid of process. When used --daemon - lock the file for prevent double-start daemon.")
	proxyMode                     = flag.String("proxy-mode", "http", "Proxy-mode after tls handle (http|tcp).")
	realIPHeader                  = flag.String("real-ip-header", "X-Real-IP", "The header will contain original IP of remote connection. It can be few headers, separated by comma.")
	runAs                         = flag.String("runas", "", "Run as other user. It work only for --daemon, only for unix and require to run from specified user or root. It can be user login or user id. It change default work dir to home folder of the user (can be changed by explicit --" + WORKING_DIR_ARG_NAME + "). Run will fail if use the option without --daemon.")
	serviceAction                 = flag.String("service-action", "", "start,stop,install,uninstall,reinstall")
	serviceName                   = flag.String("service-name", SERVICE_NAME_EXAMPLE, "service name, need for service actions")
	stateFilePath                 = flag.String("state-file", "state.json", "Path to save some state data, for example account key")
	subdomainsUnionS              = flag.String("subdomains-union", "www", "Comma-separated subdomains which try to obtain certificates with common domain name. For example if received request to domain.com it try obtain certificate for www.domain.com and domain.com same time and save them in one cert - as domain.com. Change option on working copy of program will need to obtain new certificates while request to added/removed subdomains.")
	targetConnString              = flag.String("target", ":80", "IP, :port or IP:port. Default port is 80. Default IP - same which receive connection.")
	mapTargetS                    = flag.String("target-map", "", "Remap target for some received ip:port. It write if from receiveIP[:receivePort]=targetIP[:targetPort]. It ca comtains few map,separated by comma. Example: --map=1.2.3.10=127.0.0.1,1.2.3.11=127.0.0.2:8999")
	targetConnTimeout             = flag.Duration("target-conn-timeout", time.Second, "")
	tcpKeepAliveInterval          = flag.Duration("tcp-keepalive-interval", time.Minute, "Interval between send tcp keepalive packages detect dead connections")
	acmeTestServer                = flag.Bool("test", false, "Use test lets encrypt server instead of <acme-server>")
	timeToRenew                   = flag.Duration("time-to-renew", time.Hour*24*30, "Time to end of certificate for background renew.")
	versionPrint                  = flag.Bool("version", false, "print version and exit.")
	workingDir                    = flag.String(WORKING_DIR_ARG_NAME, "", "Set working dir")
)

var (
	realIPHeaderNames         [][]byte // IP headers, generated by the proxy, included real IP address
	cutHeaders                [][]byte // internal - all headers, that cut from request (upper case).
	additionalHeaders         []byte   // prepared additional headers
	acmeService               *acmeStruct
	nonCertDomainsRegexps     []*regexp.Regexp
	paramTargetTcpAddr        *net.TCPAddr
	subdomainPrefixedForUnion []string
	bindTo                    []net.TCPAddr
	globalConnectionNumber    int64
	targetMap                 map[string]*net.TCPAddr
)

// constants in var
var (
	VERSION = "unversioned" // need be var becouse it redefine by --ldflags "-X main.VERSION" during autobuild
)

type stateStruct struct {
	PrivateKey *rsa.PrivateKey
	changed    bool
}

type nullWriter struct{}

type ConnectionID string

func (cid ConnectionID) String() string {
	return string(cid)
}

func (nullWriter) Write(buf []byte) (int, error) {
	return len(buf), nil
}

func main() {
	flag.Usage = usage
	flag.Parse()

	// Set loglevel
	logrus.SetLevel(logrus.WarnLevel)
	switch *logLevel {
	case "fatal":
		logrus.SetLevel(logrus.FatalLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	case "warning":
		logrus.SetLevel(logrus.WarnLevel)
	case "info":
		logrus.SetLevel(logrus.InfoLevel)
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	default:
		logrus.Errorf("Use default loglevel '%v', becouse unknow level: '%v'", logrus.GetLevel(), *logLevel)
	}

	isDaemon := false

	if *daemonFlag && *serviceAction == "" {
		if !daemonize() {
			return
		}
		isDaemon = true
	} else {
		if *pidFilePath != "" {
			ioutil.WriteFile(*pidFilePath, []byte(strconv.Itoa(os.Getpid())), 0600)
		}
	}

	if *workingDir != "" {
		err := os.Chdir(*workingDir)
		if err != nil {
			logrus.Error("Can't change working dir: ", err)
		}
	}

	if *versionPrint {
		fmt.Println(strings.TrimSpace(VERSION))
		return
	}

	isDaemon = isDaemon || !service.Interactive() && runtime.GOOS == "windows"

	logouts := []io.Writer{}
	if *noLogStderr || isDaemon { // Run as windows-service or unix-daemon
		// pass - no log to stderr
	} else {
		logouts = append(logouts, os.Stderr)
	}

	if *logOutput != "-" {
		lr := &lumberjack.Logger{
			Filename:   *logOutput,
			MaxSize:    *logrotateMb,
			MaxAge:     *logrotateMaxAge,
			MaxBackups: *logrotateMaxCount,
			LocalTime:  true,
		}
		if *logrotateMb == 0 {
			lr.MaxSize = int(math.MaxInt32) // about 2 Petabytes. Really no reachable in this scenario.
		}
		defer lr.Close()

		_, err := lr.Write([]byte{})
		if err == nil {
			logouts = append(logouts, lr)
			go startTimeLogRotator(lr)
		} else {
			logrus.Errorf("Can't log to file '%v': %v", *logOutput, err)
		}
	}

	// setlogout
	switch len(logouts) {
	case 0:
		logrus.SetOutput(nullWriter{})
	case 1:
		logrus.SetOutput(logouts[0])
	default:
		logrus.SetOutput(io.MultiWriter(logouts...))
	}

	logrus.Infof("Use log level: '%v'", logrus.GetLevel())
	logrus.Info("Version: ", VERSION)

	if *runAs != "" && !*daemonFlag {
		logrus.Fatal("Key --runas used without --daemon key. It isn't supported.")
	}

	prepare()

	var serviceArguments []string
	if *workingDir == "" {
		wd, _ := os.Getwd()
		serviceArguments = append([]string{"--" + WORKING_DIR_ARG_NAME + "=" + wd}, os.Args[1:]...)
	} else {
		serviceArguments = os.Args[1:]
	}

	// remove --service-action argument
	newServiceArguments := make([]string, 0, len(serviceArguments))
	for _, arg := range serviceArguments {
		if strings.HasPrefix(arg, "--service-action=") {
			continue
		}
		newServiceArguments = append(newServiceArguments, arg)
	}
	serviceArguments = newServiceArguments

	logrus.Debug("Service arguments:", serviceArguments)
	svcConfig := &service.Config{
		Name:        *serviceName,
		Description: "Reverse proxy for handle ssl/https requests",
		Arguments:   serviceArguments,
	}
	program := &letsService{}
	s, err := service.New(program, svcConfig)
	if err != nil {
		logrus.Error("Can't init service", err)
	}
	if err == nil && !service.Interactive() {
		s.Run()
		return
	}

	if *serviceAction != "" && *serviceName == SERVICE_NAME_EXAMPLE {
		logrus.Error("Setup service-name for usage service-action")
		os.Exit(1)
	}

	switch *serviceAction {
	case "":
		logrus.Info("Start interactive mode")

		// Simple start
		listeners := startListeners()
		if listeners == nil {
			logrus.Error("Can't start listener:", err)
			os.Exit(1)
		} else {
			acceptConnections(listeners)
			return
		}

	case "install":
		err = s.Install()
		if err == nil {
			fmt.Println("Service installed")
		} else {
			fmt.Println("Service install error:", err)
			os.Exit(1)
		}
	case "uninstall":
		err = s.Uninstall()
		if err == nil {
			fmt.Println("Service uninstalled")
		} else {
			fmt.Println("Service uninstall error:", err)
			os.Exit(1)
		}
	case "reinstall":
		// Uninstall
		err = s.Uninstall()
		if err == nil {
			fmt.Println("Service uninstalled")
		} else {
			fmt.Println("Service uninstall error:", err)
		}

		// Install
		err = s.Install()
		if err == nil {
			fmt.Println("Service installed")
		} else {
			fmt.Println("Service install error:", err)
			os.Exit(1)
		}
	case "start":
		err = s.Start()
		if err == nil {
			fmt.Println("Service started")
		} else {
			fmt.Println("Service start error:", err)
			os.Exit(1)
		}
	case "stop":
		err = s.Stop()
		if err == nil {
			fmt.Println("Service stopped")
		} else {
			fmt.Println("Service stopped error")
			os.Exit(1)
		}
	default:
		fmt.Printf("Unknown service action: '%v'\n", *serviceAction)
		os.Exit(1)
	}

}

func acceptConnections(listeners []*net.TCPListener) {
	for _, listener := range listeners {
		go acceptConnectionsFromAListener(listener)
	}

	// force lock lifetime - to keep old behaviour
	var ch chan bool
	<-ch
}

func acceptConnectionsFromAListener(listener *net.TCPListener) {
	started := time.Now().Unix()
	for {
		tcpConn, err := listener.AcceptTCP()
		if err != nil || tcpConn == nil {
			logrus.Warn("Can't accept tcp connection: ", err)
			if tcpConn != nil {
				tcpConn.Close()
			}
			continue
		}
		go func() {
			cn := atomic.AddInt64(&globalConnectionNumber, 1)
			cid := ConnectionID(strconv.FormatInt(started, 10) + "-" + strconv.FormatInt(cn, 10))

			defer func() {
				recoveredErr := recover()
				if recoveredErr != nil {
					logrus.Errorf("PANIC error, handled by recover cid '%v': %v. Version '%v'. Stacktrace: %s",
						cid, recoveredErr, VERSION, debug.Stack(),
					)
				}
			}()

			handleTcpConnection(cid, tcpConn)
		}()
	}
}

func certificateGet(clientHello *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), LETSENCRYPT_CREATE_CERTIFICATE_TIMEOUT)
	defer cancelFunc()

	domain := clientHello.ServerName
	if domain == "" {
		domain = *defaultDomain
	}
	err = domainValidName(domain)
	if err != nil {
		logrus.Infof("Bad domain name '%v': %v", domain, err)
		return nil, errors.New("Bad domain name")
	}

	domain = strings.ToLower(domain)

	var baseDomain = domain
	var domainsToObtain []string

	for _, subdomainPrefix := range subdomainPrefixedForUnion {
		if strings.HasPrefix(domain, subdomainPrefix) {
			baseDomain = domain[len(subdomainPrefix):]
			break
		}
	}

	logrus.Debugf("Required certificate for domain '%v'", domain)

	if strings.HasSuffix(domain, ACME_DOMAIN_SUFFIX) {
		// force generate new certificate, without caching.
		return acmeService.CreateCertificate(ctx, []string{domain}, "")
	}

	now := time.Now()
checkCertInCache:
	for {
		if ctx.Err() != nil {
			logrus.Info("Can't get certificate for domain '%v' by cancel context: %v", domain, ctx.Err())
			return nil, errors.New("Get certificate timeout")
		}

		cert = certificateCacheGet(baseDomain)
		if cert != nil && !containString(cert.Leaf.DNSNames, domain) {
			cert = nil
		}

		switch {
		case cert != nil && cert.Leaf.NotAfter.Before(now):
			// pass to obtain cert
			logrus.Warnf("Expired certificate got from cache for domain '%v'", domain)

		case cert != nil:
			// need for background cert renew
			if cert.Leaf.NotAfter.Before(time.Now().Add(*timeToRenew)) {
				go func(domainsToObtain []string, baseDomain string) {
					// TODO: additional check to exiting certs for avoid overwrite and clean by regexp
					if obtainDomainsLock(domainsToObtain) {
						defer obtainDomainsUnlock(domainsToObtain)
					}

					cert, err := acmeService.CreateCertificate(ctx, domainsToObtain, "")
					if err == nil {
						logrus.Infof("Background certificate obtained for: %v", cert.Leaf.DNSNames)
						certificateCachePut(baseDomain, cert)
					}
				}(cert.Leaf.DNSNames, baseDomain)
			}
			return cert, nil
		default:
			// pass to obtain cert
		}

		if badDomainsGetBad([]string{domain}) != nil {
			logrus.Infof("Temporary blocked domain: '%v'", domain)
			return nil, errors.New("Domain temporary blocked")
		}

		if domainsToObtain == nil {
			domainsToObtain = make([]string, 1, len(subdomainPrefixedForUnion)+1)
			domainsToObtain[0] = baseDomain
			for _, subdomain := range subdomainPrefixedForUnion {
				domainsToObtain = append(domainsToObtain, subdomain+baseDomain)
			}
		}

		if obtainDomainsLock(domainsToObtain) {
			break checkCertInCache // create cert
		} else {
			// wait, then cert in cache again
			logrus.Infof("Obtain certificate in process for domain '%v', wait a second and check it again", domain)
			time.Sleep(time.Second)
			continue checkCertInCache
		}
	}
	defer obtainDomainsUnlock(domainsToObtain)

	// check if get cert between check cache and lock to obtain
	cert = certificateCacheGet(baseDomain)
	if cert != nil && !containString(cert.Leaf.DNSNames, domain) {
		cert = nil
	}

	if cert != nil {
		return cert, nil
	}

	allowedByRegexp := make([]string, 0, len(domainsToObtain))
forRegexpCheckDomain:
	for _, checkDomain := range domainsToObtain {
		for _, re := range nonCertDomainsRegexps {
			if re.MatchString(domain) {
				logrus.Debugf("Ignore obtain cert for domain '%v' by regexp '%v'", domain, re.String())
				continue forRegexpCheckDomain
			}
		}
		allowedByRegexp = append(allowedByRegexp, checkDomain)
	}
	logrus.Debugf("Allowed domains by regexp for '%v': '%v'", domainsToObtain, allowedByRegexp)
	if !containString(allowedByRegexp, domain) {
		return nil, errors.New("Reject domain by regexp")
	}

	cert, err = acmeService.CreateCertificate(ctx, allowedByRegexp, domain)
	if err == nil {
		certificateCachePut(domainsToObtain[0], cert)

		domainsForBlock := []string{}
		for _, checkDomain := range allowedByRegexp {
			if !containString(cert.Leaf.DNSNames, checkDomain) {
				domainsForBlock = append(domainsForBlock, checkDomain)
			}
		}
		if len(domainsForBlock) > 0 {
			badDomainsAdd(domainsForBlock)
		}
	} else {
		logrus.Infof("Can't obtain certificate for domains '%v': %v", allowedByRegexp, err)
		badDomainsAdd([]string{domain})
		return nil, errors.New("Can't obtain acme certificate")
	}

	return cert, err
}

func getTargetAddr(cid ConnectionID, in *net.TCPConn) (net.TCPAddr, error) {
	var target net.TCPAddr

	var mappedTarget *net.TCPAddr
	if targetMap != nil {
		mappedTarget = targetMap[in.LocalAddr().String()]
	}
	if mappedTarget == nil {
		target = *paramTargetTcpAddr
	} else {
		target = *mappedTarget
		logrus.Debugf("Select target address by target map (cid %v) '%v' -> '%v'", cid, in.LocalAddr(), target)
	}

	if target.IP == nil || target.IP.IsUnspecified() {
		receiveAddr, ok := in.LocalAddr().(*net.TCPAddr)
		if !ok {
			logrus.Errorf("Can't cast incoming addr to tcp addr: '%v'", in.LocalAddr())
			return net.TCPAddr{}, errors.New("Can't cast incoming addr to tcp addr")
		}
		target.IP = receiveAddr.IP
	} else {
		target.IP = paramTargetTcpAddr.IP
	}

	if target.Port == 0 {
		target.Port = paramTargetTcpAddr.Port
	}

	logrus.Debugf("Target address for '%v' (cid '%v'): %v", in.RemoteAddr(), cid, target)
	return target, nil
}

func handleTcpConnection(cid ConnectionID, in *net.TCPConn) {
	logrus.Debugf("Receive incoming connection from %v, cid: '%v'", in.RemoteAddr(), cid)

	in.SetKeepAlive(true)
	in.SetKeepAlivePeriod(*tcpKeepAliveInterval)

	target, err := getTargetAddr(cid, in)
	if err != nil {
		logrus.Errorf("Can't get target IP/port for '%v' (cid '%v'): %v", in.RemoteAddr(), cid, err)
		return
	}

	// handle ssl
	tlsConfig := tls.Config{
		GetCertificate: certificateGet,
	}
	switch strings.TrimSpace(*minTLSVersion) {
	case "":
		// pass
	case "ssl3":
		tlsConfig.MinVersion = tls.VersionSSL30
	case "tls10":
		tlsConfig.MinVersion = tls.VersionTLS10
	case "tls11":
		tlsConfig.MinVersion = tls.VersionTLS11
	case "tls12":
		tlsConfig.MinVersion = tls.VersionTLS12
	default:
		logrus.Errorf("Doesn't know tls version '%v', use default. cid '%v'", *minTLSVersion, cid)
	}
	tlsConn := tls.Server(in, &tlsConfig)
	err = tlsConn.Handshake()
	logrus.Debugf("tls ciper, cid %v: %v", cid, tlsConn.ConnectionState().CipherSuite)
	if err == nil {
		logrus.Debugf("Handshake for incoming cid '%v': %v", cid, tlsConn.RemoteAddr())
	} else {
		logrus.Infof("Error in tls handshake from '%v' cid '%v' :%v", tlsConn.RemoteAddr(), cid, err)
		tlsConn.Close()
		return
	}

	serverName := tlsConn.ConnectionState().ServerName
	if serverName == "" {
		serverName = *defaultDomain + " (by default)"
	}
	logrus.Infof("Start proxy from '%v' to '%v' cid '%v' domain '%v'", in.RemoteAddr(), &target, cid, serverName)
	startProxy(cid, target, tlsConn)
}

func prepare() {
	var err error

	// Init
	if *proxyMode != "http" && *proxyMode != "tcp" {
		logrus.Panicf("Unknow proxy mode: %v", *proxyMode)
	}
	logrus.Infof("Proxy mode: %v", *proxyMode)

	for _, ignoreDomain := range strings.Split(*nonCertDomains, ",") {
		ignoreDomain = strings.TrimSpace(ignoreDomain)
		if ignoreDomain == "" {
			continue
		}
		ignoreDomainRE, err := regexp.Compile(ignoreDomain)
		if err != nil {
			logrus.Errorf("Bad ignore domain regexp '%v': %v", ignoreDomain, err)
		}
		if ignoreDomainRE != nil {
			nonCertDomainsRegexps = append(nonCertDomainsRegexps, ignoreDomainRE)
		}
	}
	if logrus.GetLevel() >= logrus.InfoLevel {
		regexps := []string{}
		for _, re := range nonCertDomainsRegexps {
			regexps = append(regexps, re.String())
		}
		logrus.Info("Non cert domain regexps: ", "['"+strings.Join(regexps, "', '")+"']")
	}

	for _, line := range strings.Split(*realIPHeader, ",") {
		line = strings.TrimSpace(line)
		if line != "" {
			realIPHeaderNames = append(realIPHeaderNames, []byte(line))
			cutHeaders = append(realIPHeaderNames, []byte(strings.ToUpper(line)))
		}
	}

	for _, addHeader := range strings.Split(*additionalHeadersParam, ",") {
		headerParts := strings.SplitN(addHeader, "=", 2)
		if len(headerParts) > 0 {
			cutHeaders = append(cutHeaders, []byte(strings.ToUpper(headerParts[0])))
		}
		buf := &bytes.Buffer{}
		buf.WriteString(headerParts[0])
		buf.WriteByte(':')
		if len(headerParts) == 2 {
			buf.WriteString(headerParts[1])
		}
		buf.WriteString("\r\n")
		additionalHeaders = append(additionalHeaders, buf.Bytes()...)
	}

	if *inMemoryCertCount > 0 {
		logrus.Infof("Create memory cache for '%v' certificates", *inMemoryCertCount)
		certMemCache, err = lru.New(*inMemoryCertCount)
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

	workingDir, err := os.Getwd()
	logrus.Infof("Working dir '%v', err: %v", workingDir, err)

	// targetConn
	targetAddrS := *targetConnString
	if !strings.ContainsRune(*targetConnString, ':') || // doesn't contain colon (only ipv4 or domain name)
		len(*targetConnString) > 0 && (*targetConnString)[len(*targetConnString)-1] == ']' { // is ipv6 only, without port
		targetAddrS += ":80"
	}
	paramTargetTcpAddr, err = net.ResolveTCPAddr("tcp", targetAddrS)
	if err != nil {
		logrus.Panicf("Can't resolve target addr '%v': %v", targetConnString, err)
	}
	logrus.Info("Target addr: ", paramTargetTcpAddr)

	subdomainPrefixedForUnion = strings.Split(*subdomainsUnionS, ",")
	for i := range subdomainPrefixedForUnion {
		subdomainPrefixedForUnion[i] = subdomainPrefixedForUnion[i] + "."
	}
	logrus.Info("Subdomain union: ", subdomainPrefixedForUnion)

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

	// bindTo
	for _, addrS := range strings.Split(*bindToS, ",") {
		addrTcp, err := net.ResolveTCPAddr("tcp", addrS)
		if err == nil {
			logrus.Debugf("Parse bind tcp addr '%v' -> '%v'", addrS, addrTcp)
		} else {
			addrIp, err := net.ResolveIPAddr("ip", addrS)
			if addrIp != nil && err == nil {
				addrTcp = &net.TCPAddr{
					IP:   addrIp.IP,
					Port: DEFAULT_BIND_PORT,
				}
				logrus.Debugf("Parse bind ip addr '%v' -> '%v'", addrS, addrTcp)
			} else {
				logrus.Errorf("Can't parse bind address '%v'", addrS)
			}
		}
		if addrTcp != nil {
			ipv4 := addrTcp.IP.To4()
			if ipv4 != nil {
				addrTcp.IP = ipv4
			}
			bindTo = append(bindTo, *addrTcp)
		}
	}

	if *bindToS == "" {
		bindTo = []net.TCPAddr{
			{IP: net.IPv6unspecified, Port: DEFAULT_BIND_PORT},
			{IP: net.IPv4zero, Port: DEFAULT_BIND_PORT},
		}
	}

	if len(bindTo) == 0 {
		logrus.Fatal("Nothing address to bind")
	}

	initAllowedIPs()

	// targetMap
	if *mapTargetS != "" {
		targetMap = make(map[string]*net.TCPAddr, strings.Count(*mapTargetS, ",")+1)
		for _, m := range strings.Split(*mapTargetS, ",") {
			equalIndex := strings.Index(m, "=")
			if equalIndex < 0 {
				logrus.Errorf("Error in target-maps, doesn't contain equal sign: %v", m)
				continue
			}

			receiver := resolveAddr(m[:equalIndex])
			if receiver.IP == nil || receiver.IP.IsUnspecified() {
				logrus.Errorf("In map targets receiver must have IP part, but it can't parsed for IP: %v", m)
				continue
			}
			if receiver.Port == 0 {
				receiver.Port = bindTo[0].Port
			}

			target := resolveAddr(m[equalIndex+1:])
			if target.Port == 0 {
				target.Port = paramTargetTcpAddr.Port
			}
			targetMap[receiver.String()] = target
		}
	}
	if logrus.GetLevel() >= logrus.InfoLevel {
		for k, v := range targetMap {
			logrus.Printf("Map target '%v' -> '%v'", k, v)
		}
	}

	acmeService = &acmeStruct{}
	acmeService.timeToRenew = *timeToRenew
	if *acmeTestServer {
		acmeService.serverAddress = LETSENCRYPT_STAGING_API_URL
	} else {
		acmeService.serverAddress = *acmeServerUrl
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

	badDomainsStartCleaner()
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

	if _, err := os.Stat(*stateFilePath); !os.IsNotExist(err) {
		logrus.Infof("Rename current state file '%v' -> '%v'", *stateFilePath, *stateFilePath+".old")

		err = os.Rename(*stateFilePath, *stateFilePath+".old")
		if err != nil {
			logrus.Errorf("Can't rename '%v' to '%v': %v", *stateFilePath, *stateFilePath+".old", err)
		}
	} else {
		logrus.Infof("Create new state file '%v'", *stateFilePath)
	}

	err = os.Rename(*stateFilePath+".new", *stateFilePath)
	if err != nil {
		logrus.Errorf("Can't rename '%v' to '%v': %v", *stateFilePath+".new", *stateFilePath, err)
	}
}

// return nil if can't start any listeners
func startListeners() []*net.TCPListener {
	listeners := make([]*net.TCPListener, 0, len(bindTo))
	for _, bindAddr := range bindTo {
		// Start listen
		logrus.Infof("Start listen: %v", bindAddr)

		listener, err := net.ListenTCP("tcp", &bindAddr)
		if err == nil {
			listeners = append(listeners, listener)
		} else {
			logrus.Errorf("Can't start listen on '%v': %v", bindAddr, err)
		}
	}
	if len(listeners) == 0 {
		return nil
	}
	return listeners
}

func startTimeLogRotator(logger *lumberjack.Logger) {
	for {
		now := time.Now()
		var sleepUntil time.Time
		switch *logrotateTime {
		case "", "none":
			return // no rotate by time
		case "minutely":
			sleepUntil = time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute()+1, 0, 0, time.Local)
		case "hourly":
			sleepUntil = time.Date(now.Year(), now.Month(), now.Day(), now.Hour()+1, 0, 0, 0, time.Local)
		case "daily":
			sleepUntil = time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.Local)
		case "weekly":
			sleepUntil := now.AddDate(0, 0, -int(now.Weekday())+int(time.Monday))                                   // Set to this week monday
			sleepUntil = time.Date(sleepUntil.Year(), sleepUntil.Month(), sleepUntil.Day(), 0, 0, 0, 0, time.Local) // set to midnight
			if sleepUntil.Before(now) {
				sleepUntil = sleepUntil.AddDate(0, 0, 7)
			}
		case "monthly":
			sleepUntil = time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.Local)
		case "yearly":
			sleepUntil = time.Date(now.Year()+1, 1, 1, 0, 0, 0, 0, time.Local)
		default:
			logrus.Errorf("Doesn't know logrotate time interval: '%v'. Turn off time rotation.", *logrotateTime)
			return
		}

		time.Sleep(sleepUntil.Sub(now))
		logrus.Info("Rotate log:", *logrotateTime)
		logger.Rotate()
	}
}

func containString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func resolveAddr(s string) *net.TCPAddr {
	tcpAddr, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		ipAddr, err := net.ResolveIPAddr("ip", s)
		if err != nil {
			logrus.Debugf("Can't resolce address: %v", s)
			return nil
		}
		tcpAddr = &net.TCPAddr{
			IP: ipAddr.IP,
		}
	}

	if tcpAddr.IP.To4() != nil {
		tcpAddr.IP = tcpAddr.IP.To4()
	}
	return tcpAddr
}

func usage() {
	flag.CommandLine.SetOutput(os.Stdout)

	fmt.Println("Version:", VERSION)
	fmt.Println("Website: https://github.com/rekby/lets-proxy")
	fmt.Println("Developer: timofey@koolin.ru")
	fmt.Println()

	flag.PrintDefaults()

	flag.CommandLine.SetOutput(os.Stderr)
}
