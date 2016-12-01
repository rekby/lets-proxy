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
	listeners := startListeners()
	if listeners == nil {
		return errors.New(fmt.Sprint("Can't start any listeners"))
	} else {
		go acceptConnections(listeners)
		return nil
	}
}

func (*letsService) Stop(s service.Service) error {
	logrus.Info("Stop service")
	go func(){
		time.Sleep(time.Second/10)
		os.Exit(0)
	}()
	return nil
}
