package main

import (
	"bytes"
	"github.com/Sirupsen/logrus"
	"net"
	"sort"
	"sync"
)

type ipSlice []net.IP

func (slice ipSlice) Len() int {
	return len(slice)
}

func (slice ipSlice) Less(a, b int) bool {
	return compareIPs(slice[a], slice[b]) == -1
}

func (slice ipSlice) Swap(a, b int) {
	tmp := slice[a]
	slice[a] = slice[b]
	slice[b] = tmp
}

var (
	globalAllowedIPs ipSlice
	allowIPsMutex    = &sync.Mutex{}
)

func compareIPs(a, b net.IP) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	case a.Equal(b):
		return 0
	default:
		return bytes.Compare([]byte(a), []byte(b))
	}
}

func getAllowIPs() ipSlice {
	return globalAllowedIPs
}

func getLocalIPs() (res []net.IP) {
	bindAddr, _ := net.ResolveTCPAddr("tcp", *bindTo)
	if bindAddr.IP.IsUnspecified() || len(bindAddr.IP) == 0 {
		addresses, err := net.InterfaceAddrs()
		if err != nil {
			logrus.Panic("Can't get local ip addresses:", err)
		}
		res = make([]net.IP, 0, len(addresses))
		for _, addr := range addresses {
			logrus.Info("Local ip:", addr.String())
			ip, _, err := net.ParseCIDR(addr.String())
			if err == nil {
				res = append(res, ip)
			} else {
				logrus.Errorf("Can't parse local ip '%v': %v", addr.String(), err)
			}
		}
	} else {
		res = []net.IP{bindAddr.IP}
	}
	if logrus.GetLevel() >= logrus.InfoLevel {
		ipStrings := make([]string, len(res))
		for i, addr := range res {
			ipStrings[i] = addr.String()
		}
		logrus.Info("Local ip:", ipStrings)
	}
	return res
}

func initAllowedIPs() {
	globalAllowedIPs = getLocalIPs()
	sort.Sort(globalAllowedIPs)
}

func ipContains(slice ipSlice, ip net.IP)bool{
	ips := getAllowIPs()
	index := sort.Search(len(ips), func(n int) bool { return compareIPs(ip, ips[n]) >= 0 })
	if index == len(ips) {
		return false
	}
	return compareIPs(ip, ips[index]) == 0
}
