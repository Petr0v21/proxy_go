package phoneagent

import (
	"net"
	"sync"
	"time"

	"tunnel-proxy/tunnel"
)

var (
	mu     sync.Mutex
	stopCh chan struct{}
)

func Start(pc1Addr string) {
	mu.Lock()
	defer mu.Unlock()

	if stopCh != nil {
		return
	}
	stopCh = make(chan struct{})

	go run(pc1Addr, stopCh)
}

func Stop() {
	mu.Lock()
	defer mu.Unlock()

	if stopCh == nil {
		return
	}
	close(stopCh)
	stopCh = nil
}

func run(pc1Addr string, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}

		c, err := net.DialTimeout("tcp", pc1Addr, 10*time.Second)
		if err != nil {
			sleepOrStop(2*time.Second, stop)
			continue
		}

		m := tunnel.NewAgentMux(c)

		for m.Alive() {
			select {
			case <-stop:
				_ = m.Close()
				return
			case <-time.After(1 * time.Second):
			}
		}

		sleepOrStop(2*time.Second, stop)
	}
}

func sleepOrStop(d time.Duration, stop <-chan struct{}) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-stop:
	case <-t.C:
	}
}
