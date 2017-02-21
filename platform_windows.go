package main

import (
	"github.com/Sirupsen/logrus"
)

func daemonize() bool {
	logrus.Error("Windows doesn't support daemon mode")
	return false
}

func signalWorker() {
	// stub
}
