package main

import (
	"os"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/kardianos/service"
)

type letsService struct{}

func (*letsService) Start(s service.Service) error {
	logrus.Info("Start service")
	return startWork()
}

func (*letsService) Stop(s service.Service) error {
	logrus.Info("Stop service")
	go func() {
		time.Sleep(time.Second / 10)
		os.Exit(0)
	}()
	return nil
}
