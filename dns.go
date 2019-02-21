package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
)

const (
	dnsDefaultPort = ":53"
)

var (
	allowedDomainChars [255]bool
	dnsServers         []string
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

	for _, latinChar := range []byte(domain) {
		if !allowedDomainChars[latinChar] {
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

		ipsChan <- serverResult
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
		ctxTimeout := time.Until(deadline)
		if *dnsTimeout < ctxTimeout {
			ctxTimeout = *dnsTimeout
		}
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

func parseDnsServers(arg string) (res []string) {
	parts := strings.Split(arg, ",")
	for _, part := range parts {
		part := strings.TrimSpace(part)
		if part == "" {
			continue
		}

		ip := net.ParseIP(part)
		tcpAddr, _ := net.ResolveTCPAddr("tcp", part)
		var ipPort string
		switch {
		case ip.To4() != nil:
			ipPort = ip.To4().String() + dnsDefaultPort
		case ip.To16() != nil:
			ipPort = "[" + ip.String() + "]" + dnsDefaultPort
		case tcpAddr != nil:
			ipPort = tcpAddr.String()
		default:
			logrus.Errorf("Error parse dns address '%v'", part)
			continue
		}
		logrus.Debugf("Parse dns '%v' to '%v'", part, ipPort)
		res = append(res, ipPort)
	}
	logrus.Infof("Parse dns servers: %v", res)
	return res
}
