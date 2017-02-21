package main

import (
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
)

var (
	certDomainsObtaining      = make(map[string]bool)
	certDomainsObtainingMutex = &sync.Mutex{}

	skipDomainMap      = make(map[string]time.Time)
	skipDomainMapMutex = &sync.Mutex{}
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

func skipDomainsAdd(domains []string) {
	if *blockBadDomainDuration == 0 {
		logrus.Debugf("Skip add domains to bad list, becouse bad list is disabled: '%v'", domains)
		return
	}

	skipDomainMapMutex.Lock()
	defer skipDomainMapMutex.Unlock()

	deadline := time.Now().Add(*blockBadDomainDuration)
	for _, domain := range domains {
		skipDomainMap[domain] = deadline
	}
	logrus.Debugf("Add domains to block '%v', dedline: '%v'", domains, deadline)
}

// return true if some of domains is bad domain
func skipDomainsCheck(domains []string) bool {
	skipDomainMapMutex.Lock()
	defer skipDomainMapMutex.Unlock()

	now := time.Now()
	for _, domain := range domains {
		if deadline, ok := skipDomainMap[domain]; ok && now.Before(deadline) {
			return true
		}
	}
	return false
}

func skipDomainsFlush() {
	logrus.Debug("Flush skip domains set")
	skipDomainMapMutex.Lock()
	skipDomainMap = make(map[string]time.Time)
	skipDomainMapMutex.Unlock()
}

func skipDomainsStartCleaner() {
	if *blockBadDomainDuration == 0 {
		logrus.Debugf("Bad domain cleaner doesn't start becouse block domains is disabled")
		return
	}

	skipDomainMapMutex.Lock()
	defer skipDomainMapMutex.Unlock()

	now := time.Now()
	toClean := make([]string, 0, len(skipDomainMap))
	for domain, deadline := range skipDomainMap {
		if deadline.Before(now) {
			toClean = append(toClean, domain)
		}
	}

	for _, domain := range toClean {
		delete(skipDomainMap, domain)
	}

	logrus.Debugf("Clean blocked domains list, remove domains: '%v'", toClean)

	time.AfterFunc(*blockBadDomainDuration, skipDomainsStartCleaner)
}
