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
	err = canPing()
	if err != nil {
		return
	}
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

		ctx:  ctx,
		done: make(chan bool, 1),
	}
	return
}

// Run @todo comment
func (p *Pinger) Run() (s *Statistics, err error) {
	c, err := icmp.ListenPacket(p.network, p.address)
	if err != nil {
		err = fmt.Errorf("Error creating a packet listener: %s", err)
		return
	}
	defer c.Close()

	s = newStatistics()
	p.statistics = s

	defer func() {
		close(p.done)
	}()

	var pkts chan *packet
	if p.Count > -1 {
		pkts = make(chan *packet, p.Count)
	} else {
		pkts = make(chan *packet)
	}
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
				err = p.send(c, pkts)
				if err != nil {
					err = fmt.Errorf("Error sending a packet: %s", err)
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
	return p.Count < 0 || p.statistics.PacketsReceived < p.Count
}

func (p *Pinger) canSend() bool {
	return p.Count < 0 || p.statistics.PacketsSent < p.Count
}

func (p *Pinger) messageType() (t icmp.Type, err error) {
	switch p.network {
	case "ip4:icmp":
		t = ipv4.ICMPTypeExtendedEchoRequest
	case "ip6:ipv6-icmp":
		t = ipv6.ICMPTypeEchoRequest
	default:
		err = fmt.Errorf("Message type unknown")
	}
	return
}

func (p *Pinger) protocol() (proto int, err error) {
	switch p.network {
	case "ip4:icmp":
		proto = 1
	case "ip6:ipv6-icmp":
		proto = 58
	default:
		err = fmt.Errorf("Protocol unknown")
	}
	return
}

func (p *Pinger) receive(pkt *packet) error {
	p.statistics.PacketsReceived++
	return nil
}

func (p *Pinger) send(c *icmp.PacketConn, pkts chan<- *packet) (err error) {
	msgType, err := p.messageType()
	if err != nil {
		return
	}
	proto, err := p.protocol()
	if err != nil {
		return
	}

	msg := icmp.Message{
		Type: msgType,
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
	_, err = c.WriteTo(msgBytes, p.originalAddress)
	if err != nil {
		return
	}

	rbytes := make([]byte, 512)
	n, peer, err := c.ReadFrom(rbytes)
	if err != nil {
		return
	}
	rmsg, err := icmp.ParseMessage(proto, rbytes[:n])
	if err != nil {
		return
	}
	// switch rm.Type {
	// case ipv6.ICMPTypeEchoReply:

	// }

	// pkt := &packet{
	// 	bytes: make([]byte, 512),
	// 	size:  512,
	// 	ttl:   0,
	// }
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

func resolve(a net.Addr) (network, address string, err error) {
	switch a.Network() {
	case "ip":
		address = a.String()
		ip := a.(*net.IPAddr).IP
		if isIPv4(ip) {
			network = "ip4:icmp"
		} else if isIPv6(ip) {
			network = "ip6:ipv6-icmp"
		} else {
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
	return
}
