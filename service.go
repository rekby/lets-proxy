package main

import (
	"github.com/kardianos/service"
	"os"
	"errors"
	"fmt"
	"github.com/Sirupsen/logrus"
	"time"
)

type letsService struct{}

func (*letsService) Start(s service.Service) error {
	logrus.Info("Start service")
	listener, err := startListener()
	if listener != nil {
		go acceptConnections(listener)
		return nil
	}
	return errors.New(fmt.Sprint("Can't start listener with nil error: ", err))
}

func (*letsService) Stop(s service.Service) error {
	logrus.Info("Stop service")
	go func(){
		time.Sleep(time.Second/10)
		os.Exit(0)
	}()
	return nil
}
