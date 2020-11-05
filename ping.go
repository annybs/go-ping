package ping

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/icmp"
)

// Pinger @todo comment
type Pinger struct {
	Count    int
	Interval time.Duration

	address         string
	network         string
	originalAddress net.Addr

	ctx        context.Context
	done       chan bool
	statistics *Statistics
}

// Statistics @todo comment
type Statistics struct {
	PacketsLost     int
	PacketsReceived int
	PacketsSent     int
}

type packet struct {
	bytes []byte
	size  int
	ttl   int
}

// New @todo comment
func New(ctx context.Context, a net.Addr) (p *Pinger, err error) {
	network, address, err := resolve(a)
	if err != nil {
		return
	}

	p = &Pinger{
		Count:    -1,
		Interval: time.Second,

		address:         address,
		network:         network,
		originalAddress: a,

		ctx:        ctx,
		done:       make(chan bool, 1),
		statistics: newStatistics(),
	}
	return
}

// Run @todo comment
func (p *Pinger) Run() (s *Statistics, err error) {
	if err != nil {
		err = fmt.Errorf("Error resolving network address: %s", err)
		return
	}
	c, err := icmp.ListenPacket(p.network, p.address)
	if err != nil {
		err = fmt.Errorf("Error creating a packet listener: %s", err)
		return
	}
	defer c.Close()

	s = p.statistics

	defer func() {
		close(p.done)
	}()

	pkts := make(chan *packet, p.Count)
	defer func() {
		close(pkts)
	}()

	interval := time.NewTicker(p.Interval)
	defer func() {
		interval.Stop()
	}()

	for {
		select {
		case <-interval.C:
			if p.canSend() {
				err = p.send()
				if err != nil {
					err = fmt.Errorf("Error sending a packet: %s", err)
					return
				}
				pkts <- &packet{
					bytes: make([]byte, 512),
					size:  512,
					ttl:   0,
				}
			}
		case pkt := <-pkts:
			err = p.receive(pkt)
			if err != nil {
				err = fmt.Errorf("Error receiving a packet: %s", err)
				return
			}
			if !p.canReceive() {
				p.done <- true
			}
		case <-p.ctx.Done():
			err = p.ctx.Err()
			return
		case <-p.done:
			return
		}
	}
}

func (p *Pinger) canReceive() bool {
	fmt.Println("Receive")
	return p.Count < 0 || p.statistics.PacketsReceived < p.Count
}

func (p *Pinger) canSend() bool {
	fmt.Println("Send")
	return p.Count < 0 || p.statistics.PacketsSent < p.Count
}

func (p *Pinger) receive(pkt *packet) error {
	p.statistics.PacketsReceived++
	return nil
}

func (p *Pinger) send() error {
	p.statistics.PacketsSent++
	return nil
}

func isIPv4(ip net.IP) bool {
	return ip.To4() != nil
}

func isIPv6(ip net.IP) bool {
	return ip.To16() != nil
}

func newStatistics() *Statistics {
	return &Statistics{
		PacketsLost:     0,
		PacketsReceived: 0,
		PacketsSent:     0,
	}
}

func resolve(a net.Addr) (network, address string, err error) {
	switch {
	case a.Network() == "ip":
		address = a.String()
		ip := a.(*net.IPAddr).IP
		if isIPv4(ip) {
			network = "ip4:icmp"
		} else if isIPv6(ip) {
			network = "ip6:ipv6-icmp"
		} else {
			err = fmt.Errorf("Invalid address \"%s\"", a.String())
		}
	case a.Network() == "udp":
		address = a.String()
		ip := a.(*net.UDPAddr).IP
		if isIPv4(ip) {
			network = "udp4"
		} else if isIPv6(ip) {
			network = "udp6"
		} else {
			err = fmt.Errorf("Invalid address \"%s\"", a.String())
		}
	default:
		err = fmt.Errorf("Unsupported network type: \"%s\"", a.Network())
	}
	return
}
