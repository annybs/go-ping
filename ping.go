package ping

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Packet @todo comment
type Packet struct {
	bytes []byte
	size  int
	ttl   int
}

// Pinger @todo comment
type Pinger struct {
	// Number of packets to send. Default is -1 for no limit.
	Count int
	// Interval between packets sent. Default is 1 second.
	Interval time.Duration

	// Packet loss side effect. Called when a packet is lost. Default is nil.
	OnLost func()
	// Packet receiver side effect. Called when a packet is received. Default is nil.
	OnReceive func(*Packet)

	addr  net.Addr
	raddr *pingerDef

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

type pingerDef struct {
	address string
	network string

	messageType icmp.Type
	protocol    int
}

// New @todo comment
func New(ctx context.Context, a net.Addr) (p *Pinger, err error) {
	err = canPing()
	if err != nil {
		return
	}
	def, err := resolve(a)
	if err != nil {
		return
	}

	p = &Pinger{
		Count:    -1,
		Interval: time.Second,

		addr:  a,
		raddr: def,

		ctx:  ctx,
		done: make(chan bool, 1),
	}
	return
}

// Run @todo comment
func (p *Pinger) Run() (s *Statistics, err error) {
	c, err := icmp.ListenPacket(p.raddr.network, p.raddr.address)
	if err != nil {
		err = fmt.Errorf("Error creating a packet listener: %s", err)
		return
	}
	defer c.Close()

	defer func() {
		close(p.done)
	}()

	var pkts chan *Packet
	if p.Count == -1 {
		pkts = make(chan *Packet)
	} else if p.Count > 0 {
		pkts = make(chan *Packet, p.Count)
	} else {
		err = fmt.Errorf("Invalid Pinger.Count: must be -1 or >0")
		return
	}
	defer func() {
		close(pkts)
	}()

	interval := time.NewTicker(p.Interval)
	defer func() {
		interval.Stop()
	}()

	s = newStatistics()
	p.statistics = s

	for {
		select {
		case <-interval.C:
			if p.canSend() {
				err = p.send(c, pkts)
				if err != nil {
					err = fmt.Errorf("Error sending a packet: %s", err)
					p.lost()
					return
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

func canPing() (err error) {
	switch runtime.GOOS {
	case "darwin", "ios":
	case "linux":
	default:
		err = fmt.Errorf("ping not supported on %s", runtime.GOOS)
	}
	return
}

func (p *Pinger) canReceive() bool {
	return p.Count == -1 || p.statistics.PacketsReceived < p.Count
}

func (p *Pinger) canSend() bool {
	return p.Count == -1 || p.statistics.PacketsSent < p.Count
}

func (p *Pinger) lost() {
	p.statistics.PacketsLost++
	if p.OnLost != nil {
		p.OnLost()
	}
}

func (p *Pinger) receive(pkt *Packet) error {
	p.statistics.PacketsReceived++
	if p.OnReceive != nil {
		p.OnReceive(pkt)
	}
	return nil
}

func (p *Pinger) send(c *icmp.PacketConn, pkts chan<- *Packet) (err error) {
	msg := icmp.Message{
		Type: p.raddr.messageType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  p.statistics.PacketsSent + 1,
			Data: []byte("HELLO"),
		},
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return
	}
	p.statistics.PacketsSent++
	_, err = c.WriteTo(msgBytes, p.addr)
	if err != nil {
		return
	}

	rbytes := make([]byte, 512)
	n, _, err := c.ReadFrom(rbytes)
	if err != nil {
		return
	}

	pkts <- &Packet{
		bytes: rbytes,
		size:  n,
		ttl:   0,
	}
	return
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

func resolve(a net.Addr) (*pingerDef, error) {
	var network, address string
	var messageType icmp.Type
	var protocol int
	var err error

	switch a.Network() {
	case "ip":
		address = a.String()
		ip := a.(*net.IPAddr).IP
		switch {
		case isIPv4(ip):
			network = "ip4:icmp"
			messageType = ipv4.ICMPTypeExtendedEchoRequest
			protocol = 1
		case isIPv6(ip):
			network = "ip6:ipv6-icmp"
			messageType = ipv6.ICMPTypeEchoRequest
			protocol = 58
		default:
			err = fmt.Errorf("Invalid address \"%s\"", a.String())
		}
	// case "udp":
	// 	address = a.String()
	// 	ip := a.(*net.UDPAddr).IP
	// 	if isIPv4(ip) {
	// 		network = "udp4"
	// 	} else if isIPv6(ip) {
	// 		network = "udp6"
	// 	} else {
	// 		err = fmt.Errorf("Invalid address \"%s\"", a.String())
	// 	}
	default:
		err = fmt.Errorf("Unsupported network type: \"%s\"", a.Network())
	}

	if err != nil {
		return nil, err
	}

	return &pingerDef{
		address:     address,
		network:     network,
		messageType: messageType,
		protocol:    protocol,
	}, nil
}
