package ping

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	runInterval = 500 * time.Millisecond
	runTimeout  = 5 * time.Second
	udpTestPort = 9009
)

func TestIPv4(t *testing.T) {
	fmt.Println("Test IPv4 ping")
	a := &net.IPAddr{
		IP: net.ParseIP("127.0.0.1"),
	}
	_, err := pingOnce(a)
	assert.Nil(t, err)
}

func TestIPv4UDP(t *testing.T) {
	fmt.Println("Test IPv4 ping with UDP")

	// done := make(chan bool, 1)

	c, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.ParseIP("127.0.0.1"),
	})
	if err != nil {
		assert.Nil(t, err)
		return
	}
	defer c.Close()

	port := c.LocalAddr().(*net.UDPAddr).Port
	fmt.Printf("Simple UDP server listening on port %d\n", port)

	a := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: port,
	}
	_, err = pingOnce(a)
	assert.Nil(t, err)

	// <-done
}

func TestCancelIPv4(t *testing.T) {
	fmt.Println("Test cancel IPv4 endless ping")
	assert := assert.New(t)
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	a := &net.IPAddr{
		IP: net.ParseIP("127.0.0.1"),
	}
	stats, err := pingForever(ctx, a)
	assert.Equal("context deadline exceeded", err.Error())
	assert.Equal(int(runTimeout/runInterval), stats.PacketsSent)
}

func TestInaccessibleIPv4(t *testing.T) {
	fmt.Println("Test IPv4 ping to unreachable host")
	a := &net.IPAddr{
		IP: net.ParseIP("127.0.0.2"),
	}
	_, err := pingOnce(a)
	if err != nil {
		fmt.Println(err)
	}
	assert.NotNil(t, err)
}

func TestIPv6(t *testing.T) {
	fmt.Println("Test IPv6 ping")
	a := &net.IPAddr{
		IP: net.ParseIP("::1"),
	}
	_, err := pingOnce(a)
	assert.Nil(t, err)
}

func TestCancelIPv6(t *testing.T) {
	fmt.Println("Test cancel IPv6 endless ping")
	assert := assert.New(t)
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	a := &net.IPAddr{
		IP: net.ParseIP("::1"),
	}
	stats, err := pingForever(ctx, a)
	assert.Equal("context deadline exceeded", err.Error())
	assert.Equal(int(runTimeout/runInterval), stats.PacketsSent)
}

func TestInaccessibleIPv6(t *testing.T) {
	fmt.Println("Test IPv6 ping to unreachable host")
	a := &net.IPAddr{
		IP: net.ParseIP("::2"),
	}
	_, err := pingOnce(a)
	if err != nil {
		fmt.Println(err)
	}
	assert.NotNil(t, err)
}

// func TestUDPv4(t *testing.T) {
// 	a := &net.UDPAddr{
// 		IP:   net.ParseIP("127.0.0.1"),
// 		Port: 3000,
// 	}
// 	pingOnce(t, a)
// }

func (p *Pinger) logPacket(pkt *Packet) {
	fmt.Printf("Received %d bytes from %s\n", pkt.size, p.addr.String())
}

func pingForever(ctx context.Context, a net.Addr) (*Statistics, error) {
	p, err := New(ctx, a)
	if err != nil {
		return nil, err
	}
	// @todo fix to default -1; Pinger.send() needs to be refactored into a goroutine, currently just hangs
	p.Count = 20
	p.Interval = runInterval
	p.OnReceive = p.logPacket
	return p.Run()
}

func pingOnce(a net.Addr) (*Statistics, error) {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	p, err := New(ctx, a)
	if err != nil {
		return nil, err
	}
	p.Count = 1
	p.OnReceive = p.logPacket
	return p.Run()
}
