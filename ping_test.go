package ping

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPv4(t *testing.T) {
	ctx := context.Background()
	a := &net.IPAddr{
		IP: net.ParseIP("127.0.0.1"),
	}
	p, err := New(ctx, a)
	p.Count = 1
	_, err = p.Run()
	assert.Nil(t, err)
}
