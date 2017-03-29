// copy of https://github.com/ncw/rclone/blob/006227baed4fb53413b0598170d6c5cabf4e350e/fs/redirect_stderr_unix.go
// Log the panic under unix to the log file

// +build darwin dragonfly freebsd linux nacl netbsd openbsd

package panichandler

import (
	"os"

	"fmt"

	"golang.org/x/sys/unix"
)

// redirectStderr to the file passed in
func RedirectStderr(f *os.File) error {
	err := unix.Dup2(int(f.Fd()), int(os.Stderr.Fd()))
	if err == nil {
		return nil
	} else {
		return fmt.Errorf("Failed to redirect stderr to file: %v", err)
	}
}
