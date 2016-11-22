package main

import (
	"testing"
	"net"
	"sort"
)

func TestCompareIPs(t *testing.T){
	if -1 != ipCompare(net.ParseIP("127.0.0.1"), net.ParseIP("::1")){
		t.Error(ipCompare(net.ParseIP("127.0.0.1"), net.ParseIP("::1")))
	}
}

func TestIPContains(t *testing.T){
	var slice ipSlice

	slice = []net.IP{}
	sort.Sort(slice)
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
