//go:build linux

// Package network implements container networking: none, host, bridge (veth + nftables), pasta.
package network

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
)

// Default bridge network. Overridable with MINIBOX_SUBNET (a /16../24 IPv4 CIDR; .1 is the gateway).
const (
	BridgeName    = "minibox0"
	DefaultSubnet = "172.30.0.0/16"
)

// IPAM hands out addresses from the bridge subnet. State lives in <Dir>/ipam.json under a flock,
// so concurrent CLI invocations are safe and leases survive between runs.
type IPAM struct {
	Dir    string
	Subnet netip.Prefix
}

type ipamState struct {
	Leases map[string]string `json:"leases"` // ip -> container id
}

// NewIPAM validates the subnet.
func NewIPAM(dir, subnet string) (*IPAM, error) {
	p, err := netip.ParsePrefix(subnet)
	if err != nil || !p.Addr().Is4() || p.Bits() < 16 || p.Bits() > 29 {
		return nil, fmt.Errorf("invalid subnet %q; use an IPv4 CIDR between /16 and /29, e.g. %s", subnet, DefaultSubnet)
	}
	return &IPAM{Dir: dir, Subnet: p.Masked()}, nil
}

// Gateway is the first host address (the bridge).
func (m *IPAM) Gateway() netip.Addr { return m.Subnet.Addr().Next() }

func (m *IPAM) locked(fn func(*ipamState) error) error {
	if err := os.MkdirAll(m.Dir, 0o755); err != nil {
		return err
	}
	lf, err := os.OpenFile(filepath.Join(m.Dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer lf.Close()
	if err := unix.Flock(int(lf.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	st := &ipamState{Leases: map[string]string{}}
	path := filepath.Join(m.Dir, "ipam.json")
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, st); err != nil {
			return fmt.Errorf("corrupt %s: %w; delete it if no containers use the bridge network", path, err)
		}
		if st.Leases == nil {
			st.Leases = map[string]string{}
		}
	}
	if err := fn(st); err != nil {
		return err
	}
	b, _ := json.Marshal(st)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Allocate leases the lowest free address for id (idempotent for the same id).
func (m *IPAM) Allocate(id string) (netip.Addr, error) {
	var out netip.Addr
	err := m.locked(func(st *ipamState) error {
		for ip, owner := range st.Leases {
			if owner == id {
				out = netip.MustParseAddr(ip)
				return nil
			}
		}
		bcast := lastAddr(m.Subnet)
		for a := m.Gateway().Next(); a.Less(bcast) && m.Subnet.Contains(a); a = a.Next() {
			if _, used := st.Leases[a.String()]; !used {
				st.Leases[a.String()] = id
				out = a
				return nil
			}
		}
		return fmt.Errorf("no free addresses left in %s; remove stopped containers (`minibox rm`) or run `minibox system prune`", m.Subnet)
	})
	return out, err
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	host := 32 - p.Bits()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= (1 << host) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// Release frees every lease held by id.
func (m *IPAM) Release(id string) error {
	return m.locked(func(st *ipamState) error {
		for ip, owner := range st.Leases {
			if owner == id {
				delete(st.Leases, ip)
			}
		}
		return nil
	})
}

// Leases returns ip -> id.
func (m *IPAM) Leases() (map[string]string, error) {
	var out map[string]string
	err := m.locked(func(st *ipamState) error {
		out = map[string]string{}
		for k, v := range st.Leases {
			out[k] = v
		}
		return nil
	})
	return out, err
}

// ReleaseExcept frees leases whose owner is not in keep (stale after crashes).
func (m *IPAM) ReleaseExcept(keep map[string]bool) (int, error) {
	n := 0
	err := m.locked(func(st *ipamState) error {
		var ips []string
		for ip, owner := range st.Leases {
			if !keep[owner] {
				ips = append(ips, ip)
			}
		}
		sort.Strings(ips)
		for _, ip := range ips {
			delete(st.Leases, ip)
			n++
		}
		return nil
	})
	return n, err
}
