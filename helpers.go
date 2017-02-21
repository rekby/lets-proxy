package main

import "github.com/miekg/dns/idn"

type DomainPresent string

func (encoded DomainPresent) String() string {
	encodedS := string(encoded)
	if *preventIDNDecode {
		return "'" + encodedS + "'"
	}
	unpuny := idn.FromPunycode(encodedS)
	if encodedS == unpuny {
		return "'" + encodedS + "'"
	} else {
		return "'" + encodedS + "' ('" + unpuny + "')"
	}
}
