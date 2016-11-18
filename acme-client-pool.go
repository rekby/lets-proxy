package main

import (
	"context"
	"crypto"
	"github.com/Sirupsen/logrus"
	"github.com/hlandau/acme/acmeapi"
	"sync/atomic"
	"time"
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
	logrus.Debug("Get acme client from pool")
	<-pool.ch

	client := &acmeapi.Client{
		AccountKey:   pool.privateKey,
		DirectoryURL: pool.serverAddress,
	}

	rulesAcceptNextTime, _ := pool.rulesAcceptNextTime.Load().(time.Time)

	if rulesAcceptNextTime.Before(time.Now()) {
		reg := &acmeapi.Registration{}
		for {
			// repeat until success or context timeout
			reg.AgreementURI = reg.LatestAgreementURI
			if reg.AgreementURI != "" {
				logrus.Debug("Try agree with terms:", reg.LatestAgreementURI)
			}
			err := client.UpsertRegistration(reg, ctx)
			if reg.AgreementURI != "" && err == nil {
				nextTime := time.Now().Add(ACMECLIENT_ACCEPT_RULES_INTERVAL)
				pool.rulesAcceptNextTime.Store(nextTime)
				logrus.Infof("Agree with terms: %v. Next agree: %v", reg.LatestAgreementURI, nextTime)
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
