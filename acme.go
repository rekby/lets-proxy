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

	mutex            *sync.Mutex
	authDomainsMutex *sync.Mutex
	authDomains      map[string]time.Time
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
	time.AfterFunc(SNI01_EXPIRE_TOKEN, this.Cleanup)
}

func (this *acmeStruct) CreateCertificate(domain string) (cert *tls.Certificate, err error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), LETSENCRYPT_CREATE_CERTIFICATE_TIMEOUT)
	defer func() {
		if ctx.Err() == nil {
			cancelFunc() // cancel all background processes. In real life - nothing.
		} else {
			logrus.Infof("Can't create certificate by context for domain '%v': %v", ctx.Err())
		}
	}()

	// Check suffix for avoid mutex sync in DeleteAcmeAuthDomain
	if strings.HasSuffix(domain, ACME_DOMAIN_SUFFIX) {
		logrus.Debugf("Detect auth-domain mode for domain '%v'", domain)
		if this.authDomainCheck(domain) {
			logrus.Debugf("Return self-signed certificate for domain '%v'", domain)
			return this.createCertificateSelfSigned(domain)
		} else {
			logrus.Debugf("Detect auth-domain is not present in list '%v'", domain)
			return nil, errors.New("Now allowed auth-domain")
		}
	}

	if !domainHasLocalIP(ctx, domain) {
		return nil, errors.New("Domain have ip of other server.")
	}

	return this.createCertificateAcme(ctx, domain)
}

func (this *acmeStruct) createCertificateAcme(ctx context.Context, domain string) (cert *tls.Certificate, err error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	var auth *acmeapi.Authorization
	client, err := this.acmePool.Get(ctx)
	if client != nil {
		defer this.acmePool.Put(client)
	}
	if err != nil {
		logrus.Errorf("Can't get acme client from pool for domain '%v': %v", domain, err)
		return nil, err
	}

	for i := 0; i < TRY_COUNT; i++ {
		logrus.Debugf("Create new authorization for domain '%v'", domain)
		auth, err = client.NewAuthorization(domain, ctx)
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
	this.authDomainPut(acmeHostName)
	defer this.authDomainDelete(acmeHostName)

	logrus.Debugf("Create challenge response for domain '%v'", domain)
	challengeResponse, err := acmeutils.ChallengeResponseJSON(this.privateKey, challenge.Token, challenge.Type)
	if err == nil {
		//pass
	} else {
		logrus.Errorf("Can't create challenge response for domain '%v', token '%v', challenge type %v: %v",
			domain, challenge.Token, challenge.Type, err)
		return nil, errors.New("Can't create challenge response")
	}
	for i := 0; i < TRY_COUNT; i++ {
		logrus.Debugf("Respond to challenge for domain '%v'", domain)
		err = client.RespondToChallenge(challenge, challengeResponse, this.privateKey, ctx)
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
		logrus.Debugf("Load challenge for domain '%v'", domain)
		err = client.LoadChallenge(challenge, ctx)
		if err == nil {
			break
		} else {
			logrus.Infof("Can't load challenge for domain '%v': %v", domain, err)
			time.Sleep(RETRY_SLEEP)
		}
	}
	if err == nil {
		// pass
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
	logrus.Debugf("Create CSR for domain '%v'", domain)
	csrDER, err := x509.CreateCertificateRequest(cryptorand.Reader, certRequest, certKey)
	if err == nil {
		logrus.Debugf("Created CSR for domain '%v'", domain)
	} else {
		logrus.Errorf("Can't create csr for domain '%v': %v", domain, err)
		return nil, errors.New("Can't create csr")
	}

	var certResponse *acmeapi.Certificate
	for i := 0; i < TRY_COUNT; i++ {
		logrus.Debugf("Certificate request for domain '%v'", domain)
		certResponse, err = client.RequestCertificate(csrDER, ctx)
		if err == nil {
			break
		} else {
			logrus.Infof("Can't get certificate for domain '%v': %v (response: %#v)", domain, err, certResponse)
			time.Sleep(RETRY_SLEEP)
		}
	}
	if err == nil {
		logrus.Infof("Get certificate for domain '%v'", domain)
	} else {
		logrus.Errorf("Can't get certificate for domain '%v': %v", domain, err)
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
	logrus.Debugf("Parsed cert count for domain '%v':", len(tmpCert.Certificate))
	if err == nil {
		logrus.Infof("Cert parsed for domain '%v'", domain)
		cert = &tmpCert
	} else {
		logrus.Errorf("Can't parse cert for domain '%v': %v", domain, err)
		return nil, errors.New("Can't parse cert for domain")
	}

	if len(cert.Certificate) > 0 {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err == nil {
			logrus.Debugf("Leaf certificate parsed from domain '%v'", domain)
		} else {
			logrus.Errorf("Can't parse leaf certificate for domain '%v': %v", domain, err)
			cert.Leaf = nil
		}
	} else {
		logrus.Errorf("Certificate for domain doesn't contain certificates '%v'", domain)
		return nil, errors.New("Certificate for domain doesn't contain certificates")
	}

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

func (this *acmeStruct) Init() {
	this.acmePool = NewAcmeClientPool(*parallelAcmeRequests, this.privateKey, this.serverAddress)

	this.mutex = &sync.Mutex{}

	this.authDomainsMutex = &sync.Mutex{}
	this.authDomains = make(map[string]time.Time)
	this.CleanupTimer()
}
