// Code generated by "stringer -type KeepAliveModeType"; DO NOT EDIT.

package main

import "fmt"

const _KeepAliveModeType_name = "KEEPALIVE_TRANSPARENTKEEPALIVE_NO_BACKEND"

var _KeepAliveModeType_index = [...]uint8{0, 21, 41}

func (i KeepAliveModeType) String() string {
	if i < 0 || i >= KeepAliveModeType(len(_KeepAliveModeType_index)-1) {
		return fmt.Sprintf("KeepAliveModeType(%d)", i)
	}
	return _KeepAliveModeType_name[_KeepAliveModeType_index[i]:_KeepAliveModeType_index[i+1]]
}