package main

import (
	"context"
	"github.com/Sirupsen/logrus"
)

func daemonize(ctx context.Context) bool {
	logrus.Error("Windows doesn't support daemon mode")
	return false
}
