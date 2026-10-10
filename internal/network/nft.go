//go:build linux

package network

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// Firewall is the packet-filter backend (NAT + port publishing). Only nftables is implemented;
// the interface exists so it can be replaced by a netlink-native version later.
type Firewall interface {
	// EnsureBase creates the minibox table/chains idempotently for the given subnet.
	EnsureBase(subnet string) error
	AddPort(p Port, ip string) error
	RemovePort(p Port) error
}

// Nft drives the `nft` binary. Everything lives in one `ip minibox` table, so it never
// touches other tables (docker, railway, ...) and `nft delete table ip minibox` removes it all.
type Nft struct{}

const nftTable = "minibox"

func nft(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.Error); ok {
			return fmt.Errorf("nft not found (%v); install nftables (apt install nftables) or use --network host|none", ee)
		}
		return fmt.Errorf("nft: %s", strings.TrimSpace(out.String()))
	}
	return nil
}

func (Nft) EnsureBase(subnet string) error {
	if exec.Command("nft", "list", "table", "ip", nftTable).Run() == nil {
		return nil
	}
	// `add table` is a no-op if it exists, so a concurrent creator is harmless.
	return nft(fmt.Sprintf(`
add table ip %[1]s
add map ip %[1]s hostports { type inet_proto . inet_service : ipv4_addr . inet_service; }
add chain ip %[1]s prerouting { type nat hook prerouting priority -100; policy accept; }
add chain ip %[1]s output { type nat hook output priority -100; policy accept; }
add chain ip %[1]s postrouting { type nat hook postrouting priority 100; policy accept; }
add chain ip %[1]s forward { type filter hook forward priority -10; policy accept; }
add rule ip %[1]s prerouting fib daddr type local dnat to meta l4proto . th dport map @hostports
add rule ip %[1]s output fib daddr type local dnat to meta l4proto . th dport map @hostports
add rule ip %[1]s postrouting ip saddr %[2]s oifname != "%[3]s" masquerade
add rule ip %[1]s postrouting ip saddr 127.0.0.0/8 oifname "%[3]s" masquerade
add rule ip %[1]s forward iifname "%[3]s" accept
add rule ip %[1]s forward oifname "%[3]s" ct state established,related accept
add rule ip %[1]s forward oifname "%[3]s" ct status dnat accept
add rule ip %[1]s forward oifname "%[3]s" iifname "%[3]s" accept
`, nftTable, subnet, BridgeName))
}

func (Nft) AddPort(p Port, ip string) error {
	err := nft(fmt.Sprintf("add element ip %s hostports { %s . %d : %s . %d }", nftTable, p.Proto, p.HostPort, ip, p.Container))
	if err != nil {
		return fmt.Errorf("publish %d/%s: %w (is the host port already published by another container?)", p.HostPort, p.Proto, err)
	}
	return nil
}

func (Nft) RemovePort(p Port) error {
	return nft(fmt.Sprintf("delete element ip %s hostports { %s . %d }", nftTable, p.Proto, p.HostPort))
}

// DeleteAll removes the whole minibox table (used by tests and `system prune --all` style cleanup).
func (Nft) DeleteAll() error {
	if exec.Command("nft", "list", "table", "ip", nftTable).Run() != nil {
		return nil
	}
	return nft("delete table ip " + nftTable)
}
