package main

import (
	"bytes"
	"github.com/Sirupsen/logrus"
	"net"
	"sort"
	"sync/atomic"
)

type ipSlice []net.IP

func (slice ipSlice) Len() int {
	return len(slice)
}

func (slice ipSlice) Less(a, b int) bool {
	return ipCompare(slice[a], slice[b]) == -1
}

func (slice ipSlice) Swap(a, b int) {
	tmp := slice[a]
	slice[a] = slice[b]
	slice[b] = tmp
}

var (
	globalAllowedIPs atomic.Value
)

func init(){
	globalAllowedIPs.Store(ipSlice{})
}

func getAllowIPs() ipSlice {
	return globalAllowedIPs.Load().(ipSlice)
}

func getLocalIPs() (res ipSlice) {
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
	var localIPs = getLocalIPs()
	sort.Sort(localIPs)
	globalAllowedIPs.Store(localIPs)
}

func ipCompare(a, b net.IP) int {
	// normalize ips
	if ipv4 := a.To4(); ipv4 != nil {
		a = ipv4
	}
	if ipv4 := b.To4(); ipv4 != nil {
		b = ipv4
	}

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


// slice must be sorted
func ipContains(slice ipSlice, ip net.IP)bool{
	index := sort.Search(len(slice), func(n int) bool { return ipCompare(slice[n], ip) >= 0 })
	if index == len(slice) {
		return false
	}
	return ipCompare(ip, slice[index]) == 0
}
