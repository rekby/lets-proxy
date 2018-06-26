package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
)

var (
	allowedDomainChars [255]bool
)

func init() {
	for _, b := range []byte("1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM.-") {
		allowedDomainChars[b] = true
	}
}

func domainValidName(domain string) error {
	if len(domain) == 0 {
		return errors.New("Zero length domain name")
	}
	if domain[0] == '.' || domain[0] == '-' {
		return errors.New("Bad start symbol")
	}
	if domain[len(domain)-1] == '-' {
		return errors.New("Bad end symbol")
	}

	for _, byte := range []byte(domain) {
		if !allowedDomainChars[byte] {
			return errors.New("Bad symbol")
		}
	}
	return nil
}

func domainHasLocalIP(ctx context.Context, domain string) (res bool) {
	defer func() { logrus.Debugf("domainHasLocalIP for '%v': %v", domain, res) }()

	var ipsChan = make(chan []net.IP, 1)
	defer func() {
		// clean channel for no leak blocked goroutines
		for range ipsChan {
			// pass
		}
	}()

	ipLess := func(l net.IP, r net.IP) bool {
		l = l.To16()
		r = r.To16()
		return bytes.Compare([]byte(l), []byte(r)) == -1
	}

	var dnsRequests = &sync.WaitGroup{}

	dnsRequests.Add(1)
	go func() {
		ips, err := net.LookupIP(domain)
		if err == nil {
			ipsChan <- ips
		} else {
			logrus.Infof("Can't local lookup ip for domain %v: %v", DomainPresent(domain), err)
		}
		logrus.Debugf("Receive answer from local lookup for domain %v ips: '%v'", DomainPresent(domain), ips)
		dnsRequests.Done()
	}()

	domainForRequest := domain
	if !strings.HasSuffix(domainForRequest, ".") {
		domainForRequest += "."
	}
	dnsq := func(server string) {
		const recordTypeForRequest = 2 // two request for every server: for A and AAAA record
		var serverWg sync.WaitGroup
		serverWg.Add(recordTypeForRequest)

		var dnsServerIpsChan = make(chan []net.IP, recordTypeForRequest)

		var dnsRequestErrorCount int32

		go func() {
			defer serverWg.Done()
			ips, err := getIPsFromDNS(ctx, domainForRequest, server, dns.TypeA)
			if err == nil {
				dnsServerIpsChan <- ips
			} else {
				logrus.Debugf("Error with request to dns server '%v' (type A) for domain '%v': %v", server, domain, err)
				atomic.AddInt32(&dnsRequestErrorCount, 1)
			}
		}()

		go func() {
			defer serverWg.Done()

			ips, err := getIPsFromDNS(ctx, domainForRequest, server, dns.TypeAAAA)
			if err == nil {
				dnsServerIpsChan <- ips
			} else {
				logrus.Debugf("Error with request to dns server '%v' (type AAAA) for domain '%v': %v", server, domain, err)
				atomic.AddInt32(&dnsRequestErrorCount, 1)
			}
		}()

		go func() {
			serverWg.Wait()
			close(dnsServerIpsChan)
		}()

		var serverResult []net.IP
		for serverIps := range dnsServerIpsChan {
			serverResult = append(serverResult, serverIps...)
		}

		if dnsRequestErrorCount > 0 {
			logrus.Infof("Dns server '%v' has errors while request process for domain '%v'. It is not send IP result for main IP comparer.", server, domain)
			return
		}

		sort.Slice(serverResult, func(i, j int) bool {
			return ipLess(serverResult[i], serverResult[j])
		})
		ipsChan <- serverResult
	}

	dnsServers := []string{
		"8.8.8.8:53",                  // google 1
		"[2001:4860:4860::8844]:53",   // google 2 (ipv6)
		"77.88.8.8:53",                // yandex 1
		"[2a02:6b8:0:1::feed:0ff]:53", // yandex 2 (ipv6)
	}
	dnsRequests.Add(len(dnsServers))
	for _, dnsServer := range dnsServers {
		go func(server string) {
			dnsq(server)
			dnsRequests.Done()
		}(dnsServer)
	}

	go func() {
		// close channel after all requests complete
		dnsRequests.Wait()
		close(ipsChan)
	}()

	hasIP := false
	allowIPs := getAllowIPs()
	for ips := range ipsChan {
		if len(ips) > 0 {
			hasIP = true
			logrus.Debugf("Has IP for domain '%v' set: %v", domain, hasIP)
		} else {
			logrus.Infof("Some dns server doesn't know domain and no return IP addresses (see debug log for details) for domain: %v", domain)
			return false
		}
		for _, ip := range ips {
			// If domain has ip doesn't that doesn't bind to the server
			if !ipContains(allowIPs, ip) {
				logrus.Debugf("Domain have ip of other server. domain %v, Domain ips: '%v', Server ips: '%v'", DomainPresent(domain), ips, allowIPs)
				return false
			}
		}
	}

	logrus.Debugf("HasIP after receive all dns answer for domain '%v': %v", domain, hasIP)

	if !hasIP {
		logrus.Infof("Doesn't found ip addresses for domain %v", DomainPresent(domain))
		return false
	}
	return true
}

func getIPsFromDNS(ctx context.Context, domain, dnsServer string, recordType uint16) (ips []net.IP, err error) {
	dnsClient := dns.Client{}

	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		ctxTimeout := deadline.Sub(time.Now())
		dnsClient.DialTimeout = ctxTimeout
		dnsClient.ReadTimeout = ctxTimeout
		dnsClient.WriteTimeout = ctxTimeout
	}

	msg := dns.Msg{}
	msg.Id = dns.Id()
	msg.SetQuestion(domain, recordType)
	answer, _, err := dnsClient.Exchange(&msg, dnsServer)
	if err != nil {
		logrus.Infof("Error from dns server '%v' for domain %v, record type '%v': %v", dnsServer, DomainPresent(domain), dns.TypeToString[recordType], err)
		return nil, err
	}
	if answer.Id != msg.Id {
		logrus.Infof("Error answer ID from dns server '%v' for domain %v, record type '%v', %v != %v", dnsServer, DomainPresent(domain), dns.TypeToString[recordType], msg.Id, answer.Id)
		return nil, errors.New("error answer ID from dns server")
	}
	var res []net.IP
	for _, r := range answer.Answer {
		if r.Header().Rrtype != recordType {
			continue
		}
		switch r.Header().Rrtype {
		case dns.TypeA:
			res = append(res, r.(*dns.A).A)
		case dns.TypeAAAA:
			res = append(res, r.(*dns.AAAA).AAAA)
		default:
			continue
		}
	}
	logrus.Debugf("Receive answer from dns server '%v' for domain %v record type '%v' ips: '%v'", dnsServer, DomainPresent(domain), dns.TypeToString[recordType], res)
	return res, nil
}
