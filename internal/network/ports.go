//go:build linux

package network

import (
	"fmt"
	"strconv"
	"strings"
)

// Port is one published port: host port -> container port.
type Port struct {
	Proto     string `json:"proto"`
	HostPort  int    `json:"hostPort"`
	Container int    `json:"containerPort"`
}

// ParsePort parses HOST:CONT[/tcp|udp] (and the single form PORT meaning PORT:PORT).
func ParsePort(s string) (Port, error) {
	bad := func(why string) (Port, error) {
		return Port{}, fmt.Errorf("invalid port mapping %q: %s; use HOST:CONTAINER, e.g. -p 8080:80 or -p 5353:53/udp", s, why)
	}
	spec, proto, _ := strings.Cut(s, "/")
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" && proto != "udp" {
		return bad("protocol must be tcp or udp")
	}
	parts := strings.Split(spec, ":")
	if len(parts) == 3 {
		return bad("binding a host IP is not supported")
	}
	if len(parts) < 1 || len(parts) > 2 {
		return bad("expected HOST:CONTAINER")
	}
	h, err := strconv.Atoi(parts[0])
	c := h
	if err == nil && len(parts) == 2 {
		c, err = strconv.Atoi(parts[1])
	}
	if err != nil || h < 1 || h > 65535 || c < 1 || c > 65535 {
		return bad("ports must be numbers in 1-65535")
	}
	return Port{Proto: proto, HostPort: h, Container: c}, nil
}
