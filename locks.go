package main

import (
	"time"
	"sync"
	"github.com/Sirupsen/logrus"
)

var (
	certDomainsObtaining      = make(map[string]bool)
	certDomainsObtainingMutex = &sync.Mutex{}

	tmpBlockedDomain      = make(map[string]time.Time)
	tmpBlockedDomainMutex = &sync.Mutex{}

)

/*
Check for all of domains doesn't in obtaining process. If ok - lock all domains and return true.
If any of domains already in obtaining process - return false and lock nothing.
*/
func obtainDomainsLock(domains []string) bool {
	certDomainsObtainingMutex.Lock()
	defer certDomainsObtainingMutex.Unlock()

	alreadyObtaining := false
	for _, domain := range domains {
		alreadyObtaining = certDomainsObtaining[domain]
		if alreadyObtaining {
			return false
		}
	}

	for _, domain := range domains {
		certDomainsObtaining[domain] = true
	}
	return true
}

/*
Unlock all domains from obtaining lock without any check
*/
func obtainDomainsUnlock(domains []string) {
	certDomainsObtainingMutex.Lock()
	defer certDomainsObtainingMutex.Unlock()

	if logrus.GetLevel() >= logrus.DebugLevel {
		for _, domain := range domains {
			if !certDomainsObtaining[domain] {
				logrus.Debugf("Release from obtain cert not locked domain: %v", domain)
			}
		}
	}

	for _, domain := range domains {
		delete(certDomainsObtaining, domain)
	}
}


func tmpBlockDomainsAdd(domains []string){
	tmpBlockedDomainMutex.Lock()
	defer tmpBlockedDomainMutex.Unlock()

	deadline := time.Now().Add(*blockBadDomainDuration)
	for _, domain := range domains {
		tmpBlockedDomain[domain] = deadline
	}
	logrus.Debugf("Add domains to block '%v', dedline: '%v'", domains, deadline)
}

// if no domains blocked - return nil
func tmpBlockDomainGetBlocked(domains []string)(res []string){
	tmpBlockedDomainMutex.Lock()
	defer tmpBlockedDomainMutex.Unlock()

	now := time.Now()
	for _, domain := range domains {
		if deadline, ok := tmpBlockedDomain[domain]; ok && now.Before(deadline) {
			res = append(res, domain)
		}
	}
	return res
}

func tmpBlockDomainCleanerStart(){
	tmpBlockedDomainMutex.Lock()
	defer tmpBlockedDomainMutex.Unlock()

	now := time.Now()
	toClean := make([]string, 0, len(tmpBlockedDomain))
	for domain, deadline := range tmpBlockedDomain {
		if deadline.Before(now) {
			toClean = append(toClean, domain)
		}
	}

	for _, domain := range toClean {
		delete(tmpBlockedDomain, domain)
	}

	logrus.Debugf("Clean blocked domains list, remove domains: '%v'", toClean)

	time.AfterFunc(*blockBadDomainDuration, tmpBlockDomainCleanerStart)
}