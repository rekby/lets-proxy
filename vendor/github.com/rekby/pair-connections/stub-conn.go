package pairconnections

import (
	"net"
	"sync"
)

func CreateTCPPairConnections() (c1, c2 *net.TCPConn) {
	// empry port mean random port
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP:net.IPv4(127,0,0,1)})
	if err != nil {
		panic(err)
	}
	wg := &sync.WaitGroup{}
	wg.Add(2)

	go func() {
		var err1 error
		c1, err1 = listener.AcceptTCP()
		if err1 != nil {
			panic(err)
		}
		wg.Done()
	}()
	go func() {
		var err2 error
		c2, err2 = net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
		if err2 != nil {
			panic(err)
		}
		wg.Done()
	}()

	wg.Wait()
	listener.Close()

	c1.SetLinger(60)
	c2.SetLinger(60)
	return c1, c2
}
