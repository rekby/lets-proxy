package main

import (
	"bytes"
	"github.com/Sirupsen/logrus"
	"io/ioutil"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
	needUpdateAllowedIpList = false

	globalAllowedIPs atomic.Value
	localIPNetworks  = []net.IPNet{ // additional filter to ip.IsGlobalUnicast, issue https://github.com/golang/go/issues/11772
		parseNet("10.0.0.0/8"),
		parseNet("172.16.0.0/12"),
		parseNet("192.168.0.0/16"),
		parseNet("FC00::/7"),
	}
)

func init() {
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
			logrus.Error("Can't get local ip addresses:", err)
			return nil
		}
		res = make([]net.IP, 0, len(addresses))
		for _, addr := range addresses {
			logrus.Info("Local ip: ", addr.String())
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

func getIpByExternalRequest() (res ipSlice) {
	fGetIp := func(network string) net.IP {
		client := http.Client{Transport: &http.Transport{
			Dial: func(_supress_network, addr string) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		},
		}
		client.Timeout = *getIPByExternalRequestTimeout
		resp, err := client.Get("http://ifconfig.io/ip")
		if resp != nil && resp.Body != nil {
			defer resp.Body.Close()
		}
		if err != nil {
			logrus.Debugf("Can't request to http://ifconfig.io/ip (%v): %v", network, err)
			return nil
		}
		respBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logrus.Debugf("Can't read response from http://ifconfig.io/ip (%v): %v", network, err)
			return nil
		}
		ip := net.ParseIP(strings.TrimSpace(string(respBytes)))
		logrus.Debugf("Detected ip by http://ifconfig.io/ip (%v): %v", network, ip)
		return ip
	}

	res = make(ipSlice, 2)

	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		res[0] = fGetIp("tcp4")
		wg.Done()
	}()
	go func() {
		res[1] = fGetIp("tcp6")
		wg.Done()
	}()
	wg.Wait()
	return res
}

func initAllowedIPs() {
	var allowedIPs ipSlice

forAllowed:
	for _, allowed := range strings.Split(*allowIPsString, ",") {
		allowed = strings.TrimSpace(allowed)
		switch {
		case allowed == "local":
			logrus.Debug("Detect local ips")
			needUpdateAllowedIpList = true
			localIPs := getLocalIPs()
			logrus.Debug("Detect local ips:", localIPs)
			allowedIPs = append(allowedIPs, localIPs...)
		case allowed == "nat":
			logrus.Debug("Detect nated ips")
			needUpdateAllowedIpList = true
			allowedIPs = append(allowedIPs, getIpByExternalRequest()...)
		case allowed == "auto":
			logrus.Debug("Autodetect ips")
			bindedTcpAddr, _ := net.ResolveTCPAddr("tcp", *bindTo)
			var bindedIP net.IP
			var localIPs ipSlice

			if bindedTcpAddr != nil && len(bindedTcpAddr.IP) > 0 && !bindedTcpAddr.IP.IsUnspecified() {
				bindedIP = bindedTcpAddr.IP
			}
			if bindedIP == nil {
				needUpdateAllowedIpList = true
				logrus.Debug("No binded ip, autodetect all local ips.")
				localIPs = getLocalIPs()
				allowedIPs = append(allowedIPs, localIPs...)
			} else {
				logrus.Debug("Add binded IP:", bindedIP)
				localIPs = ipSlice{bindedIP}
				if isPublicIp(bindedTcpAddr.IP) {
					logrus.Debug("Binded IP is public. Stop autodetection")
					continue forAllowed
				}
			}

			hasPublicIPv4 := false
			for _, ip := range localIPs {
				if ip.To4() != nil && isPublicIp(ip) {
					hasPublicIPv4 = true
					break
				}
			}
			if !hasPublicIPv4 && len(bindedIP) != net.IPv6len {
				needUpdateAllowedIpList = true
				sort.Sort(localIPs)
				logrus.Debug("Can't find local public ipv4 address. Try detect ip by external request. Local addresses:", localIPs)
				externalIPs := getIpByExternalRequest()
				logrus.Debug("IP addresses by external request:", externalIPs)
				allowedIPs = append(allowedIPs, externalIPs...)
			}
		case net.ParseIP(allowed) != nil:
			allowedIPs = append(allowedIPs, net.ParseIP(allowed))
		}
	}

	sort.Sort(allowedIPs)
	cleanedAllowedIPs := ipSlice{}
	prevIP := net.IP{}
	for _, ip := range allowedIPs {
		if ip == nil {
			continue
		}
		if ip.Equal(prevIP) {
			continue
		}

		cleanedAllowedIPs = append(cleanedAllowedIPs, ip)
		prevIP = ip
	}
	allowedIPs = make(ipSlice, len(cleanedAllowedIPs))
	copy(allowedIPs, cleanedAllowedIPs)
	logrus.Info("Detected allowed IPs:", allowedIPs)
	if needUpdateAllowedIpList {
		logrus.Infof("Next update allowed ip list: %v (after %v)", time.Now().Add(*allowIPRefreshInterval), *allowIPRefreshInterval)
	} else {
		logrus.Info("No need update alowed ip list")
	}
	globalAllowedIPs.Store(allowedIPs)

	if needUpdateAllowedIpList {
		time.AfterFunc(*allowIPRefreshInterval, initAllowedIPs)
	}
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
func ipContains(slice ipSlice, ip net.IP) bool {
	index := sort.Search(len(slice), func(n int) bool { return ipCompare(slice[n], ip) >= 0 })
	if index == len(slice) {
		return false
	}
	return ipCompare(ip, slice[index]) == 0
}

func isPublicIp(ip net.IP) bool {
	if len(ip) == 0 {
		return false
	}
	if !ip.IsGlobalUnicast() {
		return false
	}
	for _, net := range localIPNetworks {
		if net.Contains(ip) {
			return false
		}
	}
	return true
}
func parseNet(s string) net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	if ipnet == nil {
		panic("ipnet == nil: " + s)
	}
	return *ipnet
}
