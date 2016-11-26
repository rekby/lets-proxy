package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/Sirupsen/logrus"
	"github.com/hashicorp/golang-lru"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

var (
	certMemCache      *lru.Cache
	DEFAULT_FILE_MODE os.FileMode = 0666
)

// Must return valid certificate with non nil cert.Leaf or return nil
func certificateCacheGet(domain string) *tls.Certificate {
	if certMemCache != nil {
		certP, ok := certMemCache.Get(domain)
		if ok {
			logrus.Debugf("Got certificate from memory cache for domain '%v'", domain)
			return certP.(*tls.Certificate)
		} else {
			logrus.Debugf("Havn't certificate for '%v' in memory cache", domain)
		}
	}

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

		if certMemCache != nil {
			logrus.Debugf("Put certificate to memory cache '%v' while get from disk cache", domain)
			certMemCache.Add(domain, &cert)
		}
		return &cert
	} else {
		logrus.Errorf("Can't parse certificate for domain '%v': %v", domain, err)
		return nil
	}
}

func certificateCachePut(domain string, cert *tls.Certificate) {
	logrus.Infof("Certificate put to cache for domain '%v'", domain)

	if certMemCache != nil {
		logrus.Debugf("Put cert in memory cache for domain '%v'", domain)
		certMemCache.Add(domain, cert)
	}

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
	jsonPath := filepath.Join(*certDir, domain+".json")

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
		pemBlock := pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
		err = pem.Encode(certFile, &pemBlock)
		if err != nil {
			logrus.Errorf("Can't write pem block to certificate '%v': %v", certPath, err)
			return
		}
	}

	logrus.Infof("Save certificate for domain '%v' to files: %v, %v", domain, keyPath, certPath)

	if *certJsonInfo {
		if cert.Leaf != nil {
			info := struct {
				Domains    []string
				ExpireDate time.Time
			}{}
			info.Domains = cert.Leaf.DNSNames
			info.ExpireDate = cert.Leaf.NotAfter.UTC()
			jsInfoBytes, err := json.Marshal(info)
			if err == nil {
				err = ioutil.WriteFile(jsonPath, jsInfoBytes, DEFAULT_FILE_MODE)
				if err == nil {
					logrus.Debug("Save cert metadata to: ", jsonPath)
				} else {
					logrus.Errorf("Can't write file '%v': %v", jsonPath, err)
				}
			} else {
				logrus.Errorf("Can't marshal json cert info (%v): %v", cert.Leaf.DNSNames, err)
			}
		} else {
			logrus.Error("Certificate leaf is nil while save in cache")
		}
	}
}
