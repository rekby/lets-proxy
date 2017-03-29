// copy of https://github.com/ncw/rclone/blob/006227baed4fb53413b0598170d6c5cabf4e350e/fs/redirect_stderr.go
// Log the panic to the log file - for oses which can't do this

// +build !windows,!darwin,!dragonfly,!freebsd,!linux,!nacl,!netbsd,!openbsd

package panichandler

import (
	"errors"
	"os"
)

// redirectStderr to the file passed in
func RedirectStderr(f *os.File) error {
	return errors.New("Can't redirect stderr to file")
}
