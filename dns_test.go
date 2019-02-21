package main

import (
	"net"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompareIPs(t *testing.T) {
	if -1 != ipCompare(net.ParseIP("127.0.0.1"), net.ParseIP("::1")) {
		t.Error(ipCompare(net.ParseIP("127.0.0.1"), net.ParseIP("::1")))
	}
}

func TestIPContains(t *testing.T) {
	var slice ipSlice

	if ipContains(slice, nil) {
		t.Error()
	}

	slice = []net.IP{
		net.ParseIP("1.2.3.4"),
	}
	sort.Sort(slice)
	if ipContains(slice, net.ParseIP("")) {
		t.Error()
	}

	slice = []net.IP{
		net.ParseIP("1.2.3.4"),
	}
	sort.Sort(slice)
	if !ipContains(slice, net.ParseIP("1.2.3.4")) {
		t.Error()
	}

	slice = []net.IP{
		net.ParseIP("::1"),
		net.ParseIP("127.0.0.1"),
		net.ParseIP("172.17.0.2"),
		net.ParseIP("2001:470:28:177:0:242:ac11:2"),
		net.ParseIP("fe80::42:acff:fe11:2"),
	}
	sort.Sort(slice)
	if !ipContains(slice, net.ParseIP("2001:470:28:177:0:242:ac11:2")) {
		t.Error()
	}
}

func TestParseDnsStrings(t *testing.T) {
	a := assert.New(t)
	a.EqualValues([]string(nil), parseDnsServers(""))
	a.EqualValues([]string{"1.2.3.4:53"}, parseDnsServers("1.2.3.4"))
	a.EqualValues([]string{"1.2.3.4:54"}, parseDnsServers("1.2.3.4:54"))
	a.EqualValues([]string{"[::1]:53"}, parseDnsServers("::1"))
	a.EqualValues([]string{"[::1]:54"}, parseDnsServers("[::1]:54"))
	a.EqualValues([]string{
		"8.8.8.8:53", "[2001:4860:4860::8844]:53", "77.88.8.8:53", "[2a02:6b8:0:1::feed:ff]:53", "1.1.1.1:53",
	},
		parseDnsServers("8.8.8.8,2001:4860:4860::8844,77.88.8.8,2a02:6b8:0:1::feed:0ff,1.1.1.1"))
}
