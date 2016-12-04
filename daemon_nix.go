// +build !windows

package main

import (
	"github.com/sevlyar/go-daemon"
	"github.com/Sirupsen/logrus"
	"context"
)

// return true if it is child process
func daemonize(ctx context.Context)bool{
	daemonContext := &daemon.Context{}
	daemonContext.PidFileName = *pidFilePath

	child, err := daemonContext.Reborn()
	if err != nil {
		logrus.Fatalf("Can't start daemon process: %v", err)
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
