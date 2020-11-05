package ping

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIPv4(t *testing.T) {
	a := &net.IPAddr{
		IP: net.ParseIP("127.0.0.1"),
	}
	pingOnce(t, a)
}

func TestIPv6(t *testing.T) {
	a := &net.IPAddr{
		IP: net.ParseIP("::1"),
	}
	pingOnce(t, a)
}

// func TestUDPv4(t *testing.T) {
// 	a := &net.UDPAddr{
// 		IP:   net.ParseIP("127.0.0.1"),
// 		Port: 3000,
// 	}
// 	pingOnce(t, a)
// }

func pingOnce(t *testing.T, a net.Addr) {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	p, err := New(ctx, a)
	p.Count = 1
	_, err = p.Run()
	assert.Nil(t, err)
	assert.NotNil(t, nil)
}

// func startUDPServer(t *testing.T, a net.Addr) {
// }
