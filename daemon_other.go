// +build !windows

package main

import (
	"github.com/sevlyar/go-daemon"
	"os"
	"github.com/Sirupsen/logrus"
	"context"
)

// return true if it is child process
func daemonize(ctx context.Context)bool{
	daemonContext := &daemon.Context{}
	daemonContext.PidFileName = *daemonLockFile
	daemonContext.Args = make([]string, 0, len(os.Args)-1)
	daemonKey1 := "-" + DAEMON_KEY_NAME
	daemonKey2 := "--" + DAEMON_KEY_NAME
	for _, arg := range os.Args {
		if arg != daemonKey1 && arg != daemonKey2 {
			daemonContext.Args = append(daemonContext.Args, arg)
		}
	}

	child, err := daemonContext.Reborn()
	if err != nil {
		logrus.Fatalf("Can't start daemon process: %v")
	}

	go func(){
		<-ctx.Done()
		daemonContext.Release()
	}()

	if child == nil {
		logrus.Info("Start as daemon child")
		return true
	} else {
		logrus.Info("Start as daemons parent")
		return false
	}
}
