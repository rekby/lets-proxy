// copy of https://github.com/ncw/rclone/blob/006227baed4fb53413b0598170d6c5cabf4e350e/fs/redirect_stderr_windows.go
// Log the panic under windows to the log file
//
// Code from minix, via
//
// http://play.golang.org/p/kLtct7lSUg

// +build windows

package panichandler

import (
	"fmt"
	"os"
	"syscall"
)

var (
	kernel32         = syscall.MustLoadDLL("kernel32.dll")
	procSetStdHandle = kernel32.MustFindProc("SetStdHandle")
)

func setStdHandle(stdhandle int32, handle syscall.Handle) error {
	r0, _, e1 := syscall.Syscall(procSetStdHandle.Addr(), 2, uintptr(stdhandle), uintptr(handle), 0)
	if r0 == 0 {
		if e1 != 0 {
			return error(e1)
		}
		return syscall.EINVAL
	}
	return nil
}

// redirectStderr to the file passed in
func RedirectStderr(f *os.File) error {
	err := setStdHandle(syscall.STD_ERROR_HANDLE, syscall.Handle(f.Fd()))
	if err == nil {
		return nil
	} else {
		return fmt.Errorf("Failed to redirect stderr to file: %v", err)
	}
}
