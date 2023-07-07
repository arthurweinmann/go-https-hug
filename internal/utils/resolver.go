package utils

import (
	"context"
	"net"
	"time"
)

var GoogleResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{
			Timeout: 10 * time.Second,
		}
		return d.DialContext(ctx, network, "8.8.8.8:53")
	},
}
