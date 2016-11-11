package main

import (
	"crypto/rsa"

	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"github.com/Sirupsen/logrus"
	"github.com/hlandau/acme/acmeapi"
	"github.com/hlandau/acme/acmeapi/acmeutils"
	context "golang.org/x/net/context"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	SNI01_EXPIRE_TOKEN time.Duration = time.Minute * 10
)

type acmeStruct struct {
	serverAddress string
	privateKey    *rsa.PrivateKey
	client        *acmeapi.Client

	mutex                *sync.Mutex
	acmeauthDomainsMutex *sync.Mutex
	acmeAuthDomains      map[string]time.Time
}

func (this *acmeStruct) Init() {
	this.client = &acmeapi.Client{
		AccountKey:   this.privateKey,
		DirectoryURL: this.serverAddress,
	}

	this.mutex = &sync.Mutex{}

	this.acmeauthDomainsMutex = &sync.Mutex{}
	this.acmeAuthDomains = make(map[string]time.Time)
	this.CleanupTimer()
}

func (this *acmeStruct) RegisterEnsure(ctx context.Context) (err error) {
	reg := &acmeapi.Registration{}
	for i := 0; i < TRY_COUNT+1; i++ { // +1 count need for request latest agreement uri
		reg.AgreementURI = reg.LatestAgreementURI
		if reg.AgreementURI != "" {
			logrus.Info("Auto agree with terms:", reg.LatestAgreementURI)
		}
		err = this.client.UpsertRegistration(reg, ctx)
		if reg.AgreementURI != "" && err == nil {
			return
		}
	}
	return err
}

func (this *acmeStruct) Cleanup() {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	now := time.Now()
	for token, expire := range this.acmeAuthDomains {
		if expire.Before(now) {
			delete(this.acmeAuthDomains, token)
		}
	}
}

func (this *acmeStruct) CleanupTimer() {
	this.Cleanup()
	time.AfterFunc(SNI01_EXPIRE_TOKEN, this.Cleanup)
}

func (this *acmeStruct) CreateCertificate(domain string) (cert *tls.Certificate, err error) {
	// Check suffix for avoid mutex sync in DeleteAcmeAuthDomain
	if strings.HasSuffix(domain, ".acme.invalid") {
		logrus.Debugf("Detect auth-domain mode for domain '%v'", domain)
		if this.DeleteAcmeAuthDomain(domain) {
			logrus.Debugf("Return self-signed certificate for domain '%v'", domain)
			return this.createCertificateSelfSigned(domain)
		} else {
			logrus.Debugf("Detect auth-domain is not present in list '%v'", domain)
			return nil, errors.New("Now allowed auth-domain")
		}
	}

	// check about we serve the domain
	ips, err := net.LookupIP(domain)
	if err != nil {
		logrus.Warnf("Can't lookup ip for domain '%v': %v", domain, err)
		return nil, errors.New("Can't lookup ip of the domain")
	}
	isLocalIP := false
checkLocalIP:
	for _, ip := range ips {
		for _, localIP := range localIPs {
			if ip.Equal(localIP) {
				isLocalIP = true
				break checkLocalIP
			}
		}
	}
	if !isLocalIP {
		logrus.Warnf("Domain have ip of other server. Domain '%v', Domain ips: %v, Server ips: %v", domain, ips, localIPs)
		return nil, errors.New("Domain have ip of other server.")
	}

	return this.createCertificateAcme(domain)
}

func (this *acmeStruct) createCertificateAcme(domain string) (cert *tls.Certificate, err error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	var auth *acmeapi.Authorization

	ctx, cancelFunc := context.WithTimeout(context.Background(), LETSENCRYPT_CREATE_CERTIFICATE_TIMEOUT)
	defer cancelFunc()

	for i := 0; i < TRY_COUNT; i++ {
		auth, err = this.client.NewAuthorization(domain, ctx)
		if err == nil {
			break
		} else {
			logrus.Infof("Can't create new authorization for domain '%v': %v", domain, err)
			time.Sleep(RETRY_SLEEP)
		}
	}
	if err == nil {
		logrus.Infof("Create authorization for domain '%v'", domain)
	} else {
		logrus.Errorf("Can't create new authorization for domain '%v': %v", domain, err)
		return nil, errors.New("Can't create new authorization for domain")
	}

	if logrus.GetLevel() >= logrus.DebugLevel {
		challengeTypes := make([]string, len(auth.Challenges))
		for i := range auth.Challenges {
			challengeTypes[i] = auth.Challenges[i].Type
		}
		logrus.Debugf("Challenge types for domain '%v': %v. Challenge combinations: %v", domain, challengeTypes, auth.Combinations)
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
		return nil, errors.New("Can't find good challange combination")
	}

	acmeHostName, err := acmeutils.TLSSNIHostname(this.privateKey, challenge.Token)
	if err == nil {
		logrus.Debugf("Create acme-auth hostname for domain '%v': %v", domain, acmeHostName)
	} else {
		logrus.Errorf("Can't create acme domain for domain '%v' token '%v': %v", domain, challenge.Token, err)
		return nil, errors.New("Can't create acme domain")
	}
	this.PutAcmeAuthDomain(acmeHostName)

	challengeResponse, err := acmeutils.ChallengeResponseJSON(this.privateKey, challenge.Token, challenge.Type)
	if err == nil {
		logrus.Debugf("Create challenge response for domain '%v'", domain)
	} else {
		logrus.Errorf("Can't create challenge response for domain '%v', token '%v', challenge type %v: %v",
			domain, challenge.Token, challenge.Type, err)
		return nil, errors.New("Can't create challenge response")
	}
	for i := 0; i < TRY_COUNT; i++ {
		err = this.client.RespondToChallenge(challenge, challengeResponse, this.privateKey, ctx)
		if err == nil {
			break
		} else {
			logrus.Info("Can't send response for challenge of domain '%v': %v", domain, err)
			time.Sleep(RETRY_SLEEP)
		}
	}
	if err == nil {
		logrus.Debugf("Send challenge response for domain '%v'", domain)
	} else {
		logrus.Errorf("Can't send response for challenge of domain '%v': %v", domain, err)
		return nil, errors.New("Can't send response for challenge")
	}

	for i := 0; i < TRY_COUNT; i++ {
		err = this.client.LoadChallenge(challenge, ctx)
		if err != nil {
			logrus.Infof("Can't load challenge for domain '%v': %v", domain, err)
			time.Sleep(RETRY_SLEEP)
		}
	}
	if err == nil {
		logrus.Debugf("Load challenge for domain '%v'", domain)
	} else {
		logrus.Errorf("Can't load challenge for domain '%v': %v", domain, err)
		return nil, errors.New("Can't load challenge")
	}

	// Generate CSR
	certKey, err := rsa.GenerateKey(cryptorand.Reader, PRIVATE_KEY_BITS)
	if err == nil {
		logrus.Debugf("Create private key for domain '%v'", domain)
	} else {
		logrus.Errorf("Can't create rsa key for domain '%v': %v", err)
		return nil, errors.New("Can't create rsa key")
	}
	certRequest := &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &certKey.PublicKey,
		Subject:            pkix.Name{CommonName: domain},
		DNSNames:           []string{domain},
	}
	csrDER, err := x509.CreateCertificateRequest(cryptorand.Reader, certRequest, certKey)
	if err == nil {
		logrus.Debugf("Create CSR for domain '%v'", domain)
	} else {
		logrus.Errorf("Can't create csr for domain '%v': %v", domain, err)
		return nil, errors.New("Can't create csr")
	}

	var certResponse *acmeapi.Certificate
	for i := 0; i < TRY_COUNT; i++ {
		certResponse, err = this.client.RequestCertificate(csrDER, ctx)
		if err != nil {
			logrus.Infof("Can't get certificate for domain '%v': %v", domain, err)
			time.Sleep(RETRY_SLEEP)
		}
	}
	if err == nil {
		logrus.Infof("Get certificate for domain '%v'", domain)
	} else {
		logrus.Errorf("Can't get certificate for domain '%v': %v", domain, err)
		return nil, errors.New("Can't request certificate")
	}
	cert = &tls.Certificate{}
	cert.Certificate = [][]byte{certResponse.Certificate}
	logrus.Debugf("Certificate for domain '%v':\n%s", domain, certResponse.Certificate)
	//cert.Leaf, err = x509.ParseCertificate(certResponse.Certificate)
	//if err == nil {
	//	logrus.Debugf("Parse certificate for domain '%v'", domain)
	//} else {
	//	logrus.Errorf("Can't parse certificate for domain '%v':%v", domain, err)
	//	return nil, errors.New("Can't parse certificate")
	//}
	return cert, nil
}

func (this *acmeStruct) createCertificateSelfSigned(domain string) (cert *tls.Certificate, err error) {
	derCert, privateKey, err := acmeutils.CreateTLSSNICertificate(domain)
	if err != nil {
		logrus.Errorf("Can't create tls-sni-01 self-signed certificate for '%v': %v", domain, err)
		return nil, err
	}

	cert = &tls.Certificate{}
	cert.Certificate = [][]byte{derCert}
	cert.PrivateKey = privateKey
	return cert, nil
}

func (this *acmeStruct) PutAcmeAuthDomain(domain string) {
	this.acmeauthDomainsMutex.Lock()
	defer this.acmeauthDomainsMutex.Unlock()

	logrus.Debug("Put acme auth domain:", domain)
	this.acmeAuthDomains[domain] = time.Now().Add(SNI01_EXPIRE_TOKEN)
}

func (this *acmeStruct) DeleteAcmeAuthDomain(domain string) bool {
	this.acmeauthDomainsMutex.Lock()
	defer this.acmeauthDomainsMutex.Unlock()

	logrus.Debug("Delete acme auth domain:", domain)
	_, ok := this.acmeAuthDomains[domain]
	if ok {
		delete(this.acmeAuthDomains, domain)
	}
	return ok
}
