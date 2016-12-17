package main

// from time to time see https://godoc.org/golang.org/x/crypto/acme/autocert
// it isn't ready for usage now, but can simple code in future.

import (
	"crypto/rsa"

	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"github.com/Sirupsen/logrus"
	"github.com/hlandau/acme/acmeapi"
	"github.com/hlandau/acme/acmeapi/acmeutils"
	"strings"
	"sync"
	"time"
)

const (
	SNI01_EXPIRE_TOKEN time.Duration = time.Minute * 10
	ACME_DOMAIN_SUFFIX               = ".acme.invalid"
)

type acmeStruct struct {
	serverAddress string
	privateKey    *rsa.PrivateKey
	acmePool      *acmeClientPool
	timeToRenew   time.Duration

	mutex *sync.Mutex

	authDomainsMutex      *sync.Mutex
	authDomains           map[string]time.Time
	backgroundCertsObtain map[string]*sync.Mutex // sync for obtain only once certificate for the domain same time
}

func (this *acmeStruct) authDomainCheck(domain string) bool {
	this.authDomainsMutex.Lock()
	defer this.authDomainsMutex.Unlock()

	logrus.Debug("Check acme auth domain:", domain)
	_, ok := this.authDomains[domain]
	return ok
}

func (this *acmeStruct) authDomainDelete(domain string) {
	this.authDomainsMutex.Lock()
	defer this.authDomainsMutex.Unlock()

	logrus.Debug("Delete acme auth domain:", domain)
	delete(this.authDomains, domain)
}

func (this *acmeStruct) authDomainPut(domain string) {
	this.authDomainsMutex.Lock()
	defer this.authDomainsMutex.Unlock()

	logrus.Debug("Put acme auth domain:", domain)
	this.authDomains[domain] = time.Now().Add(SNI01_EXPIRE_TOKEN)
}

// return ok domains for create cert. Order or returned domains unspecified.
func (this *acmeStruct) checkDomains(ctx context.Context, domains []string) []string {
	logrus.Debugf("Check allowable of domains for: %v", domains)
	wg := &sync.WaitGroup{}
	wg.Add(len(domains))

	allowed := make(chan string, len(domains))

	for _, domain := range domains {
		go func(check_domain string) {
			defer func() {
				err := recover()
				if err != nil {
					logrus.Errorf("Have panic while check domain %v: %v", DomainPresent(check_domain), err)
				}
				wg.Done()
			}()
			if domainHasLocalIP(ctx, check_domain) {
				allowed <- check_domain
			}
		}(domain)
	}

	go func() {
		wg.Wait()
		close(allowed)
	}()

	allowedDomains := make([]string, 0, len(domains))
	for domain := range allowed {
		allowedDomains = append(allowedDomains, domain)
	}

	return allowedDomains
}

func (this *acmeStruct) Cleanup() {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	now := time.Now()
	for token, expire := range this.authDomains {
		if expire.Before(now) {
			delete(this.authDomains, token)
		}
	}
}

func (this *acmeStruct) CleanupTimer() {
	this.Cleanup()
	time.AfterFunc(SNI01_EXPIRE_TOKEN, this.CleanupTimer)
}

func (this *acmeStruct) authorizeDomain(ctx context.Context, domain string) error {
	client, err := this.acmePool.Get(ctx)
	if client != nil {
		defer this.acmePool.Put(client)
	}

	if err != nil {
		logrus.Errorf("Can't get acme client for authorize domain %v: %v", DomainPresent(domain), err)
		return err
	}

	var auth *acmeapi.Authorization

	for i := 0; i < TRY_COUNT; i++ {
		logrus.Debugf("Create new authorization for domain %v", DomainPresent(domain))
		auth, err = client.NewAuthorization(domain, ctx)
		if err == nil {
			break
		} else {
			logrus.Infof("Can't create new authorization for domain %v: %v", DomainPresent(domain), err)
			time.Sleep(RETRY_SLEEP)
		}
	}
	if err == nil {
		logrus.Infof("Create authorization for domain %v", DomainPresent(domain))
	} else {
		logrus.Errorf("Can't create new authorization for domain %v: %v", DomainPresent(domain), err)
		return errors.New("Can't create new authorization for domain")
	}

	if logrus.GetLevel() >= logrus.DebugLevel {
		challengeTypes := make([]string, len(auth.Challenges))
		for i := range auth.Challenges {
			challengeTypes[i] = auth.Challenges[i].Type
		}
		logrus.Debugf("Challenge types for domain %v: %v. Challenge combinations: %v", DomainPresent(domain), challengeTypes, auth.Combinations)
	}

	canAuthorize := false
	var challenge *acmeapi.Challenge
	for _, cmb := range auth.Combinations {
		if len(cmb) == 1 && auth.Challenges[cmb[0]].Type == "tls-sni-01" {
			canAuthorize = true
			challenge = auth.Challenges[cmb[0]]
			break
		}
	}
	if !canAuthorize {
		logrus.Errorf("Can't find good challange combination for domain: '%v'", domain)
		return errors.New("Can't find good challange combination")
	}

	acmeHostName, err := acmeutils.TLSSNIHostname(this.privateKey, challenge.Token)
	if err == nil {
		logrus.Debugf("Create acme-auth hostname for domain %v: %v", DomainPresent(domain), acmeHostName)
	} else {
		logrus.Errorf("Can't create acme domain for domain %v token '%v': %v", DomainPresent(domain), challenge.Token, err)
		return errors.New("Can't create acme domain")
	}
	this.authDomainPut(acmeHostName)
	// defer this.authDomainDelete(acmeHostName) // no detete auth domain - it will be cleaned up be timeout.
	// it need for check authDomain while create cert - out of the function

	logrus.Debugf("Create challenge response for domain %v", DomainPresent(domain))
	challengeResponse, err := acmeutils.ChallengeResponseJSON(this.privateKey, challenge.Token, challenge.Type)
	if err == nil {
		//pass
	} else {
		logrus.Errorf("Can't create challenge response for domain %v, token '%v', challenge type %v: %v",
			DomainPresent(domain), challenge.Token, challenge.Type, err)
		return errors.New("Can't create challenge response")
	}
	for i := 0; i < TRY_COUNT; i++ {
		logrus.Debugf("Respond to challenge for domain %v", DomainPresent(domain))
		err = client.RespondToChallenge(challenge, challengeResponse, this.privateKey, ctx)
		if err == nil {
			break
		} else {
			logrus.Info("Can't send response for challenge of domain %v: %v", DomainPresent(domain), err)
			time.Sleep(RETRY_SLEEP)
		}
	}
	if err == nil {
		logrus.Debugf("Send challenge response for domain %v", DomainPresent(domain))
	} else {
		logrus.Errorf("Can't send response for challenge of domain %v: %v", DomainPresent(domain), err)
		return errors.New("Can't send response for challenge")
	}

	for i := 0; i < TRY_COUNT; i++ {
		logrus.Debugf("Load challenge for domain %v", DomainPresent(domain))
		err = client.LoadChallenge(challenge, ctx)
		if err == nil {
			break
		} else {
			logrus.Infof("Can't load challenge for domain %v: %v", DomainPresent(domain), err)
			time.Sleep(RETRY_SLEEP)
		}
	}
	if err == nil {
		// pass
	} else {
		logrus.Errorf("Can't load challenge for domain %v: %v", DomainPresent(domain), err)
		return errors.New("Can't load challenge")
	}

	return nil
}

/*
Create a certificate for domains (all domains in one certificate).
If can't create certificate for some of domains - certificate will be created for subset of domains.
Caller have to check ok domains in cert.Leaf.DNSNames

if main_domain != "" - return cert only if it contains main_domain.
Doesn't try to obtain cert if check of main_domain is bad or can't authorized it.
*/
func (this *acmeStruct) CreateCertificate(ctx context.Context, domains []string, main_domain string) (cert *tls.Certificate, err error) {

	// Check suffix for avoid mutex sync in DeleteAcmeAuthDomain
	if len(domains) == 1 && strings.HasSuffix(domains[0], ACME_DOMAIN_SUFFIX) {
		logrus.Debugf("Detect auth-domain mode for domain %v", DomainPresent(domains[0]))
		if this.authDomainCheck(domains[0]) {
			logrus.Debugf("Return self-signed certificate for domain %v", DomainPresent(domains[0]))
			return this.createCertificateSelfSigned(domains[0])
		} else {
			logrus.Debugf("Detect auth-domain is not present in list '%v'", DomainPresent(domains[0]))
			return nil, errors.New("Not allowed auth-domain")
		}
	}

	domainsForCert := this.checkDomains(ctx, domains)
	if len(domainsForCert) == 0 {
		return nil, errors.New("Domains is bad by self-check")
	}
	if main_domain != "" && !containString(domainsForCert, main_domain) {
		return nil, errors.New("Main domain doesn't allowed by domainsCheck")
	}

	return this.createCertificateAcme(ctx, domainsForCert, main_domain)
}

func (this *acmeStruct) createCertificateAcme(ctx context.Context, domains []string, main_domain string) (cert *tls.Certificate, err error) {
	authorizedDomains := make([]string, 0, len(domains))

	authorizedDomainsChan := make(chan string, len(domains))
	wg := &sync.WaitGroup{}
	wg.Add(len(domains))

	for _, domain := range domains {
		go func(auth_domain string) {
			defer func() {
				err := recover()
				if err != nil {
					logrus.Errorf("Panic while authorize domain %v: %v", DomainPresent(auth_domain), err)
				}
				wg.Done()
			}()

			auth_err := this.authorizeDomain(ctx, auth_domain)
			if auth_err == nil {
				authorizedDomainsChan <- auth_domain
			} else {
				logrus.Infof("Can't authorize domain %v: %v", DomainPresent(auth_domain), auth_err)
			}
		}(domain)
	}

	go func() {
		wg.Wait()
		close(authorizedDomainsChan)
	}()

	for domain := range authorizedDomainsChan {
		authorizedDomains = append(authorizedDomains, domain)
	}
	if main_domain != "" && !containString(authorizedDomains, main_domain) {
		logrus.Info("Authorized domains '%v' doesn't contain main domain %v", authorizedDomains, DomainPresent(main_domain))
		return nil, errors.New("Authorized domains doesn't contain main domain")
	}

	// sort domains
	for i := 0; i < len(authorizedDomains)-1; i++ {
		l := strings.ToLower(authorizedDomains[i])
		r := strings.ToLower(authorizedDomains[i+1])

		// www. - to end, other - alphabet
		if strings.HasPrefix(l, "www.") && !strings.HasPrefix(r, "www.") || l > r {
			tmp := authorizedDomains[i]
			authorizedDomains[i] = authorizedDomains[i+1]
			authorizedDomains[i+1] = tmp
		}
	}

	if len(authorizedDomains) == 0 {
		logrus.Info("Can't authorize any domains from '%v'", domains)
		return nil, errors.New("Can't authorize domains")
	}

	client, err := this.acmePool.Get(ctx)
	if client != nil {
		defer this.acmePool.Put(client)
	}
	if err != nil {
		logrus.Errorf("Can't get acme client from pool for domains '%v': %v", authorizedDomains, err)
		return nil, err
	}

	// Generate CSR
	certKey, err := rsa.GenerateKey(cryptorand.Reader, *privateKeyBits)
	if err == nil {
		logrus.Debugf("Create private key for domains '%v'", authorizedDomains)
	} else {
		logrus.Errorf("Can't create rsa key for domain %v: %v", DomainPresent(main_domain), err)
		return nil, errors.New("Can't create rsa key")
	}
	certRequest := &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &certKey.PublicKey,
		Subject:            pkix.Name{CommonName: authorizedDomains[0]},
		DNSNames:           authorizedDomains,
	}
	logrus.Debugf("Create CSR for domains '%v'", authorizedDomains)
	csrDER, err := x509.CreateCertificateRequest(cryptorand.Reader, certRequest, certKey)
	if err == nil {
		logrus.Debugf("Created CSR for domains '%v'", authorizedDomains)
	} else {
		logrus.Errorf("Can't create csr for domains '%v': %v", authorizedDomains, err)
		return nil, errors.New("Can't create csr")
	}

	var certResponse *acmeapi.Certificate
	for i := 0; i < TRY_COUNT; i++ {
		logrus.Debugf("Certificate request for domains '%v'", authorizedDomains)
		certResponse, err = client.RequestCertificate(csrDER, ctx)
		if err == nil {
			break
		} else {
			logrus.Infof("Can't get certificate for domains '%v': %v (response: %#v)", authorizedDomains, err, certResponse)
			time.Sleep(RETRY_SLEEP)
		}
	}
	if err == nil {
		logrus.Infof("Get certificate for domains '%v'", authorizedDomains)
	} else {
		logrus.Errorf("Can't get certificate for domains '%v': %v", authorizedDomains, err)
		return nil, errors.New("Can't request certificate")
	}

	pemEncode := func(b []byte, t string) []byte {
		return pem.EncodeToMemory(&pem.Block{Bytes: b, Type: t})
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Bytes: certResponse.Certificate, Type: "CERTIFICATE"})
	for _, extraCert := range certResponse.ExtraCertificates {
		extraCertPEM := pem.EncodeToMemory(&pem.Block{Bytes: extraCert, Type: "CERTIFICATE"})
		certPEM = append(certPEM, '\n')
		certPEM = append(certPEM, extraCertPEM...)
	}
	logrus.Debugf("CERT PEM:\n%s", certPEM)
	certKeyPEM := pemEncode(x509.MarshalPKCS1PrivateKey(certKey), "RSA PRIVATE KEY")

	tmpCert, err := tls.X509KeyPair(certPEM, certKeyPEM)
	logrus.Debugf("Parsed cert count for domains '%v': %v", authorizedDomains, len(tmpCert.Certificate))
	if err == nil {
		logrus.Infof("Cert parsed for domains '%v'", authorizedDomains)
		cert = &tmpCert
	} else {
		logrus.Errorf("Can't parse cert for domains '%v': %v", authorizedDomains, err)
		return nil, errors.New("Can't parse cert for domain")
	}

	if len(cert.Certificate) > 0 {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err == nil {
			logrus.Debugf("Leaf certificate parsed from domains '%v'", authorizedDomains)
		} else {
			logrus.Errorf("Can't parse leaf certificate for domains '%v': %v", authorizedDomains, err)
			cert.Leaf = nil
		}
	} else {
		logrus.Errorf("Certificate for domains doesn't contain certificates '%v'", authorizedDomains)
		return nil, errors.New("Certificate for domain doesn't contain certificates")
	}

	return cert, nil
}

func (this *acmeStruct) createCertificateSelfSigned(domain string) (cert *tls.Certificate, err error) {
	derCert, privateKey, err := acmeutils.CreateTLSSNICertificate(domain)
	if err != nil {
		logrus.Errorf("Can't create tls-sni-01 self-signed certificate for '%v': %v", DomainPresent(domain), err)
		return nil, err
	}

	cert = &tls.Certificate{}
	cert.Certificate = [][]byte{derCert}
	cert.PrivateKey = privateKey
	return cert, nil
}

func (this *acmeStruct) Init() {
	this.acmePool = NewAcmeClientPool(*acmeParallelCount, this.privateKey, this.serverAddress)

	this.mutex = &sync.Mutex{}

	this.authDomainsMutex = &sync.Mutex{}
	this.authDomains = make(map[string]time.Time)
	this.CleanupTimer()
}
