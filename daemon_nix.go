// +build !windows

package main

import (
	"bufio"
	"bytes"
	"errors"
	"github.com/Sirupsen/logrus"
	"github.com/sevlyar/go-daemon"
	"os"
	"strconv"
	"syscall"
	"path/filepath"
)

type User struct {
	Name           string
	HomeDir        string
	UserId         uint32
	DefaultGroupId uint32
}

var (
	daemonContext *daemon.Context // need global var for prevent close (and unlock) pid-file
)
// return true if it is child process
func daemonize() bool {

	daemonContext = &daemon.Context{}

	if *runAs != "" {
		userName := *runAs
		user, err := userLookup(userName)
		if err != nil {
			logrus.Fatalf("Can't lookup runas user '%v': %v", userName, err)
		}

		logrus.Infof("Parse runas '%v' as %v:%v", *runAs, user.UserId, user.DefaultGroupId)
		daemonContext.Credential = &syscall.Credential{
			Uid: user.UserId,
			Gid: user.DefaultGroupId,
		}
		daemonContext.WorkDir = user.HomeDir
	}

	if *workingDir != "" {
		daemonContext.WorkDir = *workingDir
	}
	logrus.Infof("Daemon working dir: %v", daemonContext.WorkDir)

	if *pidFilePath != "" {
		pidPath := *pidFilePath
		if !filepath.IsAbs(pidPath) && daemonContext.WorkDir != "" {
			pidPath = filepath.Join(daemonContext.WorkDir, pidPath)
		}
		daemonContext.PidFileName = pidPath
		logrus.Infof("Pidfile: %v", daemonContext.PidFileName)
	}

	child, err := daemonContext.Reborn()
	if err != nil {
		logrus.Fatalf("Can't start daemon process: %v", err)
	}

	if child == nil {
		logrus.Info("Start as daemon child")
		return true
	} else {
		logrus.Info("Start as daemons parent")
		return false
	}
}

// "os/user".Lookup need cgo and can't used when binary is cross-compiled.
// use own lookup
func userLookup(login string) (*User, error) {
	var isId bool = false
	_, err := parseUint32(login)
	if err == nil {
		isId = true
	}

	loginBytes := []byte(login)

	passwdFile, err := os.Open("/etc/passwd")
	if passwdFile != nil {
		defer passwdFile.Close()
	}
	if err != nil {
		return nil, err
	}

	splitBytes := []byte(":")
	scanner := bufio.NewScanner(passwdFile)
	var userLine []byte
	var userLineParts [][]byte
	for scanner.Scan() {
		line := scanner.Bytes()
		lineParts := bytes.SplitN(line, splitBytes, 7)
		if len(lineParts) < 6 {
			logrus.Warnf("Short passwd line '%s'", line)
			continue
		}

		if isId && bytes.Equal(lineParts[2], loginBytes) ||
			!isId && bytes.Equal(lineParts[0], loginBytes) {
			userLine = line
			userLineParts = lineParts
			break
		}
	}

	if scanner.Err() != nil {
		return nil, err
	}
	if userLineParts == nil {
		return nil, errors.New("User not found")
	}

	user := User{
		Name:    string(userLineParts[0]),
		HomeDir: string(userLineParts[5]),
	}

	user.UserId, err = parseUint32(string(userLineParts[2]))
	if err != nil {
		logrus.Errorf("Can't parse user id '%s' from passwd line '%s': %v", userLineParts[2], userLine, err)
		return nil, errors.New("Can't parse user id")
	}

	user.DefaultGroupId, err = parseUint32(string(userLineParts[3]))
	if err != nil {
		logrus.Errorf("Can't parse users group id '%s' from passwd line '%s': %v", userLineParts[3], userLine, err)
		return nil, errors.New("Can't parse group id")
	}

	return &user, nil
}

func parseUint32(s string) (uint32, error) {
	res, err := strconv.ParseUint(s, 10, 32)
	if err == nil {
		return uint32(res), nil
	} else {
		return 0, err
	}
}
