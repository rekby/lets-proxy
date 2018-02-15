package main

import (
	"golang.org/x/net/idna"
)

type DomainPresent string

func (encoded DomainPresent) String() string {
	encodedS := string(encoded)
	if *preventIDNDecode {
		return "'" + encodedS + "'"
	}
	unpuny, _ := idna.ToUnicode(encodedS)
	if encodedS == unpuny {
		return "'" + encodedS + "'"
	} else {
		return "'" + encodedS + "' ('" + unpuny + "')"
	}
}
