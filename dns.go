package main

import (
	"context"
	"errors"
	"github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"net"
	"strings"
	"sync"
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

func domainHasLocalIP(ctx context.Context, domain string) bool {
	var ipsChan = make(chan []net.IP, 1)
	defer func() {
		// clean channel
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
			logrus.Warnf("Can't local lookup ip for domain %v: %v", DomainPresent(domain), err)
		}
		logrus.Debugf("Receive answer from local lookup for domain %v ips: '%v'", DomainPresent(domain), ips)
		dnsRequests.Done()
	}()

	domainForRequest := domain
	if !strings.HasSuffix(domainForRequest, ".") {
		domainForRequest += "."
	}
	dnsq := func(server string) {
		dnsRequests.Add(2) // for A and AAAA requests
		go func() {
			ipsChan <- getIPsFromDNS(ctx, domainForRequest, server, dns.TypeA)
			dnsRequests.Done()
		}()
		go func() {
			ipsChan <- getIPsFromDNS(ctx, domainForRequest, server, dns.TypeAAAA)
			dnsRequests.Done()
		}()
	}

	dnsq("8.8.8.8:53")                  // google 1
	dnsq("[2001:4860:4860::8844]:53")   // google 2 (ipv6)
	dnsq("77.88.8.8:53")                // yandex 1
	dnsq("[2a02:6b8:0:1::feed:0ff]:53") // yandex 2 (ipv6)

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
		}
		for _, ip := range ips {
			// If domain has ip doesn't that doesn't bind to the server
			if !ipContains(allowIPs, ip) {
				logrus.Debugf("Domain have ip of other server. domain %v, Domain ips: '%v', Server ips: '%v'", DomainPresent(domain), ips, allowIPs)
				return false
			}
		}
	}

	if !hasIP {
		logrus.Infof("Doesn't found ip addresses for domain %v", DomainPresent(domain))
		return false
	}
	return true

}

func getIPsFromDNS(ctx context.Context, domain, dnsServer string, recordType uint16) []net.IP {
	dnsClient := dns.Client{}

	msg := dns.Msg{}
	msg.Id = dns.Id()
	msg.SetQuestion(domain, recordType)
	answer, _, err := dnsClient.Exchange(&msg, dnsServer)
	if err != nil {
		logrus.Infof("Error from dns server '%v' for domain %v, record type '%v': %v", dnsServer, DomainPresent(domain), dns.TypeToString[recordType], err)
		return nil
	}
	if answer.Id != msg.Id {
		logrus.Infof("Error answer ID from dns server '%v' for domain %v, record type '%v', %v != %v", dnsServer, DomainPresent(domain), dns.TypeToString[recordType], msg.Id, answer.Id)
		return nil
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
	return res
}
