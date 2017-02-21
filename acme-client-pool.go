package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/hlandau/acme/acmeapi"
)

const (
	ACMECLIENT_ACCEPT_RULES_INTERVAL = time.Hour * 24 // Accept rules once per day
)

type acmeClientPool struct {
	privateKey    crypto.PrivateKey
	serverAddress string

	ch                  chan bool
	rulesAcceptNextTime atomic.Value
}

func NewAcmeClientPool(maxCount int, key crypto.PrivateKey, serverAddress string) *acmeClientPool {
	res := &acmeClientPool{
		privateKey:    key,
		serverAddress: serverAddress,
	}
	res.ch = make(chan bool, maxCount)
	for i := 0; i < maxCount; i++ {
		res.ch <- false
	}
	return res
}

func (pool *acmeClientPool) Get(ctx context.Context) (*acmeapi.Client, error) {
	logrus.Debugf("Get acme client from pool. It has free %v of %v", len(pool.ch), cap(pool.ch))
	<-pool.ch
	logrus.Debug("Lock client in pool")

	client := &acmeapi.Client{
		AccountKey:   pool.privateKey,
		DirectoryURL: pool.serverAddress,
	}
	if *acmeSslCheckDisable {
		client.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	}

	rulesAcceptNextTime, _ := pool.rulesAcceptNextTime.Load().(time.Time)

	if rulesAcceptNextTime.Before(time.Now()) {
		reg := &acmeapi.Registration{}
		logrus.Debugf("Expire accept rules timeout. Start agree with current rules")
		for {
			// repeat until success or context timeout
			reg.AgreementURI = reg.LatestAgreementURI
			logrus.Debug("Try agree with terms:", reg.LatestAgreementURI)
			err := client.UpsertRegistration(reg, ctx)
			if err != nil {
				logrus.Debugf("Can't agree with terms: %v", err)
			}
			if reg.AgreementURI != "" && err == nil {
				nextTime := time.Now().Add(ACMECLIENT_ACCEPT_RULES_INTERVAL)
				pool.rulesAcceptNextTime.Store(nextTime)
				logrus.Infof("Agreed with terms: %v. Next agree: %v", reg.LatestAgreementURI, nextTime)
				break
			}
			if ctx.Err() != nil {
				pool.ch <- false
				return nil, err
			}
		}
	}
	return client, nil
}

func (pool *acmeClientPool) Put(*acmeapi.Client) {
	logrus.Debug("Put acme client in pool")
	pool.ch <- false
}
