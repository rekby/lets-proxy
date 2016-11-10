package main

import (
	"flag"
	"github.com/Sirupsen/logrus"
	"io"
	"net"
	"time"
)

var (
	inPort            = flag.Int("in-port", 1443, "")
	targetPort        = flag.Int("target-port", 80, "")
	targetConnTimeout = flag.Duration("target-conn-timeout", time.Second, "")
)

func main() {
	logrus.SetLevel(logrus.DebugLevel)
	tcpAddr := &net.TCPAddr{}
	tcpAddr.Port = *inPort
	logrus.Errorf("Start listen: %v", tcpAddr)

	listener, err := net.ListenTCP("tcp", tcpAddr)
	logrus.Debug(listener.Addr())
	logrus.Debugf("%#v", listener)
	if err != nil {
		panic(err)
	}
	for {
		tcpConn, err := listener.AcceptTCP()
		if err != nil {
			panic(err)
		}
		go handleTcpConnection(tcpConn)
	}
}

func handleTcpConnection(in *net.TCPConn){
	target, err := getTargetConn(in)
	if err != nil {
		logrus.Errorf("Can't get target IP/port for '%v': %v", target.String(),err)
		return
	}
	startProxy(target, in)
}

func getTargetConn(in *net.TCPConn) (targetAddr net.TCPAddr, err error) {
	targetAddrP, err := net.ResolveTCPAddr("tcp", in.LocalAddr().String())
	if err != nil {
		logrus.Errorf("Can't resolve local addr '%v': %v", in.LocalAddr().String(), err)
		return net.TCPAddr{}, err
	}
	targetAddrP.Port = *targetPort
	return *targetAddrP, nil
}

func startProxy(targetAddr net.TCPAddr, in net.Conn) {
	logrus.Infof("Start proxy connection from '%v' to'%v'", in.RemoteAddr().String(), targetAddr.String())

	targetConnCommon, err := net.DialTimeout("tcp", targetAddr.String(), *targetConnTimeout)
	if err != nil {
		logrus.Warnf("Can't connect to target '%v': %v", targetAddr.String(), err)
		return
	}

	targetConn := targetConnCommon.(*net.TCPConn)
	go func() {
		io.Copy(in, targetConn)
		in.Close()
		targetConn.Close()
	}()
	go func() {
		io.Copy(targetConn, in)
		in.Close()
		targetConn.Close()
	}()
}
