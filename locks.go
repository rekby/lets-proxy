package main

import (
	"github.com/Sirupsen/logrus"
	"sync"
	"time"
)

var (
	certDomainsObtaining      = make(map[string]bool)
	certDomainsObtainingMutex = &sync.Mutex{}

	badDomainMap      = make(map[string]time.Time)
	badDomainMapMutex = &sync.Mutex{}
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

func badDomainsAdd(domains []string) {
	badDomainMapMutex.Lock()
	defer badDomainMapMutex.Unlock()

	deadline := time.Now().Add(*blockBadDomainDuration)
	for _, domain := range domains {
		badDomainMap[domain] = deadline
	}
	logrus.Debugf("Add domains to block '%v', dedline: '%v'", domains, deadline)
}

// if no domains blocked - return nil
func badDomainsGetBad(domains []string) (res []string) {
	badDomainMapMutex.Lock()
	defer badDomainMapMutex.Unlock()

	now := time.Now()
	for _, domain := range domains {
		if deadline, ok := badDomainMap[domain]; ok && now.Before(deadline) {
			res = append(res, domain)
		}
	}
	return res
}

func badDomainsStartCleaner() {
	badDomainMapMutex.Lock()
	defer badDomainMapMutex.Unlock()

	now := time.Now()
	toClean := make([]string, 0, len(badDomainMap))
	for domain, deadline := range badDomainMap {
		if deadline.Before(now) {
			toClean = append(toClean, domain)
		}
	}

	for _, domain := range toClean {
		delete(badDomainMap, domain)
	}

	logrus.Debugf("Clean blocked domains list, remove domains: '%v'", toClean)

	time.AfterFunc(*blockBadDomainDuration, badDomainsStartCleaner)
}
