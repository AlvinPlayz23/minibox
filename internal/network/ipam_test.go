//go:build linux

package network

import (
	"fmt"
	"os"
	"sync"
	"testing"
)

func TestIPAM(t *testing.T) {
	m, err := NewIPAM(t.TempDir(), "10.9.0.0/29") // hosts .1 gw, .2-.6 usable
	if err != nil {
		t.Fatal(err)
	}
	if m.Gateway().String() != "10.9.0.1" {
		t.Fatal(m.Gateway())
	}
	var got []string
	for i := 0; i < 5; i++ {
		a, err := m.Allocate(fmt.Sprint("c", i))
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, a.String())
	}
	if got[0] != "10.9.0.2" || got[4] != "10.9.0.6" {
		t.Fatalf("%v", got)
	}
	if _, err := m.Allocate("overflow"); err == nil {
		t.Fatal("allocated beyond the subnet (broadcast/exhaustion)")
	}
	if a, _ := m.Allocate("c2"); a.String() != "10.9.0.4" {
		t.Fatalf("not idempotent: %v", a)
	}
	m.Release("c1")
	if a, _ := m.Allocate("new"); a.String() != "10.9.0.3" {
		t.Fatalf("freed address not reused: %v", a)
	}
	n, _ := m.ReleaseExcept(map[string]bool{"c0": true})
	if n != 4 {
		t.Fatalf("stale release removed %d", n)
	}
	l, _ := m.Leases()
	if len(l) != 1 || l["10.9.0.2"] != "c0" {
		t.Fatalf("%v", l)
	}
}

func TestIPAMConcurrentUnique(t *testing.T) {
	m, _ := NewIPAM(t.TempDir(), "172.31.0.0/24")
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[string]bool{}
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a, err := m.Allocate(fmt.Sprint("c", i))
			mu.Lock()
			defer mu.Unlock()
			if err != nil || seen[a.String()] {
				t.Errorf("dup or error: %v %v", a, err)
			}
			seen[a.String()] = true
		}(i)
	}
	wg.Wait()
}

func TestIPAMBadSubnet(t *testing.T) {
	for _, s := range []string{"", "x", "10.0.0.0/8", "10.0.0.0/30", "::1/64"} {
		if _, err := NewIPAM(t.TempDir(), s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestParsePort(t *testing.T) {
	ok := map[string]Port{"8080:80": {"tcp", 8080, 80}, "53:53/udp": {"udp", 53, 53}, "80": {"tcp", 80, 80}}
	for in, want := range ok {
		if p, err := ParsePort(in); err != nil || p != want {
			t.Errorf("%q: %+v %v", in, p, err)
		}
	}
	for _, bad := range []string{"", "0:80", "70000:1", "a:b", "1:2:3", "127.0.0.1:80:80", "80:80/sctp", "80:"} {
		if _, err := ParsePort(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestResolvConf(t *testing.T) {
	// covered via file-based input
	f := t.TempDir() + "/r"
	writeFile(t, f, "search a.b\nnameserver 127.0.0.53\nnameserver fd12::10\nnameserver 9.9.9.9\noptions ndots:2\n")
	got := ResolvConf(f, true)
	if got != "search a.b\nnameserver 9.9.9.9\noptions ndots:2\n" {
		t.Errorf("%q", got)
	}
	writeFile(t, f, "nameserver 127.0.0.53\n")
	if got := ResolvConf(f, true); got != "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" {
		t.Errorf("%q", got)
	}
}

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestParsePortTrailingSlash(t *testing.T) {
	if _, err := ParsePort("5353:53/"); err == nil {
		t.Error("trailing / accepted as tcp")
	}
	if p, err := ParsePort("5353:53/udp"); err != nil || p.Proto != "udp" {
		t.Errorf("%+v %v", p, err)
	}
}
