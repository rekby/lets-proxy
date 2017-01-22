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
	"flag"
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

	globalAllowedIPs               atomic.Value
	globalAllowedIPsMutex           = sync.Mutex{}
	globalAllowedIPsNextUpdateTime atomic.Value
	localIPNetworks                  = []net.IPNet{ // additional filter to ip.IsGlobalUnicast, issue https://github.com/golang/go/issues/11772
		parseNet("10.0.0.0/8"),
		parseNet("172.16.0.0/12"),
		parseNet("192.168.0.0/16"),
		parseNet("FC00::/7"),
	}
)

func getAllowIPs() ipSlice {
	if !flag.Parsed() {
		logrus.Debug("Try get allowed ips before parse options")
		return nil
	}

	if *allowIPRefreshInterval == 0 {
		res := forceReadAllowedIPs()
		logrus.Infof("Update allowed ips to: %v", res)
		return res
	}

	if nextUpdateTime, ok := globalAllowedIPsNextUpdateTime.Load().(time.Time); !ok || nextUpdateTime.Before(time.Now()){
		globalAllowedIPsMutex.Lock()
		defer globalAllowedIPsMutex.Unlock()

		// second check after get mutex. It can be updated in other thread
		if nextUpdateTime, ok := globalAllowedIPsNextUpdateTime.Load().(time.Time); !ok || nextUpdateTime.Before(time.Now()){
			res := forceReadAllowedIPs()
			logrus.Infof("Update allowed ips to: %v", res)
			globalAllowedIPs.Store(res)
			globalAllowedIPsNextUpdateTime.Store(time.Now().Add(*allowIPRefreshInterval))
		}
	}
	ips := globalAllowedIPs.Load().(ipSlice)
	return ips
}

func getLocalIPs() (res ipSlice) {
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

func forceReadAllowedIPs() ipSlice {
	var allowedIPs ipSlice
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

			hasUnspecifiedIpv4 := false
			hasUnspecifiedIpv6 := false
			hasIpv4 := false
			hasIpv6 := false

			var autoAllowedIps ipSlice

			for _, tcpAddr := range bindTo {
				switch {
				case tcpAddr.IP.Equal(net.IPv4zero):
					hasUnspecifiedIpv4 = true
					hasIpv4 = true
				case tcpAddr.IP.Equal(net.IPv6unspecified):
					hasUnspecifiedIpv6 = true
					hasIpv6 = true
				case tcpAddr.IP == nil:
					hasUnspecifiedIpv4 = true
					hasUnspecifiedIpv6 = true
					hasIpv4 = true
					hasIpv6 = true
				default:
					if len(tcpAddr.IP) == net.IPv4len {
						hasIpv4 = true
						logrus.Debugf("Add binded ipv4 to allowed: %v", tcpAddr.IP)
						autoAllowedIps = append(autoAllowedIps, tcpAddr.IP)
					} else {
						hasIpv6 = true
						logrus.Debugf("Add binded ipv6 to allowed: %v", tcpAddr.IP)
						autoAllowedIps = append(autoAllowedIps, tcpAddr.IP)
					}
				}
			}

			var localIPs ipSlice
			if hasUnspecifiedIpv6 || hasUnspecifiedIpv4 {
				needUpdateAllowedIpList = true
				logrus.Debug("Has unspecified ip addresses, autodetect all local ips.")
				localIPs = getLocalIPs()
				for _, ip := range localIPs {
					if hasUnspecifiedIpv4 && len(ip) == net.IPv4len ||
						hasUnspecifiedIpv6 && len(ip) == net.IPv6len {
						autoAllowedIps = append(autoAllowedIps, ip)
					}
				}
			}

			hasPublicIPv4 := false
			for _, ip := range autoAllowedIps {
				if ip.To4() != nil && isPublicIp(ip) {
					hasPublicIPv4 = true
					break
				}
			}
			if !hasPublicIPv4 {
				needUpdateAllowedIpList = true
				sort.Sort(autoAllowedIps)
				logrus.Debug("Can't find local public ipv4 address. Try detect ip by external request. Local addresses:", localIPs)
				externalIPs := getIpByExternalRequest()
				for _, ip := range externalIPs {
					if ip.To4() != nil && hasIpv4 || ip.To4() == nil && hasIpv6 {
						logrus.Debug("IP add allowed by external request:", ip)
						autoAllowedIps = append(autoAllowedIps, ip)
					} else {
						logrus.Debug("IP skip allowed by external request (ip family):", ip)
					}
				}

			}

			sort.Sort(autoAllowedIps)
			logrus.Debugf("Add auto-allowed ips: %v", autoAllowedIps)
			allowedIPs = append(allowedIPs, autoAllowedIps...)
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
	return allowedIPs
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
		logrus.Errorf("Can't parse cidr '%v': %v", s, err)
		return net.IPNet{}
	}
	if ipnet == nil {
		logrus.Error("Can't parse cidr '%v', nil result.", s)
		return net.IPNet{}
	}
	return *ipnet
}
