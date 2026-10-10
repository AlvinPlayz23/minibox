//go:build linux

package network

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// Mode names.
const (
	None   = "none"
	Host   = "host"
	Bridge = "bridge"
	Pasta  = "pasta"
)

// Info records what was set up for one container, so cleanup works even after a crash.
type Info struct {
	Mode     string `json:"mode"`
	IP       string `json:"ip,omitempty"`
	Gateway  string `json:"gateway,omitempty"`
	Veth     string `json:"veth,omitempty"`
	Ports    []Port `json:"ports,omitempty"`
	PastaPid int    `json:"pastaPid,omitempty"`
	Message  string `json:"message,omitempty"` // fallback explanation shown to the user
}

// Manager sets up and tears down container networks under one MINIBOX_ROOT.
type Manager struct {
	Root string
	FW   Firewall
}

func (m *Manager) ipam() (*IPAM, error) {
	s := os.Getenv("MINIBOX_SUBNET")
	if s == "" {
		s = DefaultSubnet
	}
	return NewIPAM(filepath.Join(m.Root, "network"), s)
}

// DefaultMode picks bridge for root, pasta (if installed) otherwise host, and explains why.
func DefaultMode() (mode, why string) {
	if os.Geteuid() == 0 {
		return Bridge, ""
	}
	if _, err := exec.LookPath("pasta"); err == nil {
		return Pasta, "rootless: using pasta networking"
	}
	return Host, "rootless and `pasta` not found: using --network host (install passt for isolated networking)"
}

func vethName(id string) string { return "vb" + id[:10] }

func sysctl(path, val string) error { return os.WriteFile(path, []byte(val), 0o644) }

func (m *Manager) ensureBridge(ip *IPAM) (netlink.Link, error) {
	br, err := netlink.LinkByName(BridgeName)
	if err != nil {
		attrs := netlink.NewLinkAttrs()
		attrs.Name = BridgeName
		nb := &netlink.Bridge{LinkAttrs: attrs}
		if err := netlink.LinkAdd(nb); err != nil && !os.IsExist(err) {
			return nil, fmt.Errorf("create bridge %s (needs root/CAP_NET_ADMIN and the bridge kernel module): %w", BridgeName, err)
		}
		if br, err = netlink.LinkByName(BridgeName); err != nil {
			return nil, err
		}
	}
	addrs, _ := netlink.AddrList(br, netlink.FAMILY_V4)
	want := netip.PrefixFrom(ip.Gateway(), ip.Subnet.Bits()).String()
	have := false
	for _, a := range addrs {
		if a.IPNet.String() == want {
			have = true
		}
	}
	if !have {
		ad, _ := netlink.ParseAddr(want)
		if err := netlink.AddrAdd(br, ad); err != nil && !os.IsExist(err) {
			return nil, fmt.Errorf("address bridge %s: %w (does %s overlap an existing network? set MINIBOX_SUBNET)", BridgeName, err, ip.Subnet)
		}
	}
	if err := netlink.LinkSetUp(br); err != nil {
		return nil, err
	}
	_ = sysctl("/proc/sys/net/ipv4/ip_forward", "1")
	// Lets `curl localhost:PORT` reach published ports (locally generated traffic DNATed to the bridge).
	_ = sysctl("/proc/sys/net/ipv4/conf/"+BridgeName+"/route_localnet", "1")
	return br, nil
}

// Setup configures networking for the container whose init has pid (already in its own netns
// for none/bridge/pasta). hostname/ports come from the container config.
func (m *Manager) Setup(id string, pid int, mode string, ports []Port) (*Info, error) {
	info := &Info{Mode: mode, Ports: ports}
	switch mode {
	case Host:
		if len(ports) > 0 {
			return nil, fmt.Errorf("-p has no effect with --network host (the container already uses the host's ports)")
		}
		return info, nil
	case None:
		if len(ports) > 0 {
			return nil, fmt.Errorf("-p cannot be used with --network none")
		}
		return info, setLoopback(pid)
	case Pasta:
		return m.setupPasta(info, pid, ports)
	case Bridge:
	default:
		return nil, fmt.Errorf("unknown network mode %q; use bridge, host, none or pasta", mode)
	}
	ipam, err := m.ipam()
	if err != nil {
		return nil, err
	}
	fw := m.FW
	if fw == nil {
		fw = Nft{}
	}
	br, err := m.ensureBridge(ipam)
	if err != nil {
		return nil, err
	}
	if err := fw.EnsureBase(ipam.Subnet.String()); err != nil {
		return nil, err
	}
	addr, err := ipam.Allocate(id)
	if err != nil {
		return nil, err
	}
	info.IP, info.Gateway, info.Veth = addr.String(), ipam.Gateway().String(), vethName(id)
	fail := func(e error) (*Info, error) { m.Cleanup(id, info); return nil, e }

	nsh, err := netns.GetFromPid(pid)
	if err != nil {
		return fail(fmt.Errorf("open container netns: %w", err))
	}
	defer nsh.Close()
	peer := "vp" + id[:10]
	attrs := netlink.NewLinkAttrs()
	attrs.Name = info.Veth
	attrs.MasterIndex = br.Attrs().Index
	if old, err := netlink.LinkByName(info.Veth); err == nil { // stale from a crashed run
		_ = netlink.LinkDel(old)
	}
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: attrs, PeerName: peer}); err != nil {
		return fail(fmt.Errorf("create veth pair: %w", err))
	}
	host, err := netlink.LinkByName(info.Veth)
	if err != nil {
		return fail(err)
	}
	pl, err := netlink.LinkByName(peer)
	if err != nil {
		return fail(err)
	}
	if err := netlink.LinkSetNsFd(pl, int(nsh)); err != nil {
		return fail(fmt.Errorf("move veth into container netns: %w", err))
	}
	if err := netlink.LinkSetUp(host); err != nil {
		return fail(err)
	}
	h, err := netlink.NewHandleAt(nsh)
	if err != nil {
		return fail(err)
	}
	defer h.Close()
	cl, err := h.LinkByName(peer)
	if err != nil {
		return fail(err)
	}
	if err := h.LinkSetName(cl, "eth0"); err != nil {
		return fail(err)
	}
	if cl, err = h.LinkByName("eth0"); err != nil {
		return fail(err)
	}
	ad, _ := netlink.ParseAddr(netip.PrefixFrom(addr, ipam.Subnet.Bits()).String())
	if err := h.AddrAdd(cl, ad); err != nil {
		return fail(err)
	}
	if err := h.LinkSetUp(cl); err != nil {
		return fail(err)
	}
	if lo, err := h.LinkByName("lo"); err == nil {
		_ = h.LinkSetUp(lo)
	}
	if err := h.RouteAdd(&netlink.Route{Gw: net.ParseIP(info.Gateway), Scope: netlink.SCOPE_UNIVERSE}); err != nil {
		return fail(fmt.Errorf("default route: %w", err))
	}
	for i, p := range ports {
		if err := fw.AddPort(p, info.IP); err != nil {
			info.Ports = ports[:i] // only what we actually added is removed on cleanup
			return fail(err)
		}
	}
	return info, nil
}

func setLoopback(pid int) error {
	nsh, err := netns.GetFromPid(pid)
	if err != nil {
		return err
	}
	defer nsh.Close()
	h, err := netlink.NewHandleAt(nsh)
	if err != nil {
		return err
	}
	defer h.Close()
	lo, err := h.LinkByName("lo")
	if err != nil {
		return err
	}
	return h.LinkSetUp(lo)
}

func (m *Manager) setupPasta(info *Info, pid int, ports []Port) (*Info, error) {
	path, err := exec.LookPath("pasta")
	if err != nil {
		return nil, fmt.Errorf("--network pasta needs the `pasta` binary (apt install passt): %w", err)
	}
	args := []string{"--config-net", "--quiet", "--foreground", "--pid", "/dev/null"}
	for _, p := range ports {
		flag := "-t"
		if p.Proto == "udp" {
			flag = "-u"
		}
		args = append(args, flag, fmt.Sprintf("%d:%d", p.HostPort, p.Container))
	}
	args = append(args, "--netns", fmt.Sprintf("/proc/%d/ns/net", pid))
	cmd := exec.Command(path, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start pasta: %w", err)
	}
	info.PastaPid = cmd.Process.Pid
	go cmd.Wait()
	return info, nil
}

// Cleanup removes everything recorded in info. It is idempotent and safe after crashes.
func (m *Manager) Cleanup(id string, info *Info) {
	if info == nil {
		return
	}
	if info.PastaPid > 0 {
		_ = syscall.Kill(-info.PastaPid, syscall.SIGTERM)
		_ = syscall.Kill(info.PastaPid, syscall.SIGTERM)
	}
	if info.Mode != Bridge {
		return
	}
	fw := m.FW
	if fw == nil {
		fw = Nft{}
	}
	for _, p := range info.Ports {
		_ = fw.RemovePort(p)
	}
	if info.Veth != "" {
		if l, err := netlink.LinkByName(info.Veth); err == nil {
			_ = netlink.LinkDel(l)
		}
	}
	if ipam, err := m.ipam(); err == nil {
		_ = ipam.Release(id)
	}
}

// ---- files written into the container ----

// ResolvConf builds /etc/resolv.conf from the host's, dropping loopback and IPv6 nameservers
// that are unreachable from a bridged container; falls back to public resolvers.
func ResolvConf(hostFile string, bridged bool) string {
	b, _ := os.ReadFile(hostFile)
	var out []string
	n := 0
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "nameserver":
			if len(f) < 2 {
				continue
			}
			ip := net.ParseIP(f[1])
			if bridged && (ip == nil || ip.IsLoopback() || ip.To4() == nil) {
				continue
			}
			out = append(out, l)
			n++
		case "search", "options":
			out = append(out, l)
		}
	}
	if n == 0 && bridged {
		out = append(out, "nameserver 1.1.1.1", "nameserver 8.8.8.8")
	}
	return strings.Join(out, "\n") + "\n"
}

// HostsFile builds /etc/hosts.
func HostsFile(hostname, ip string) string {
	s := "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n"
	if ip != "" {
		s += ip + "\t" + hostname + "\n"
	} else {
		s += "127.0.0.1\t" + hostname + "\n"
	}
	return s
}

// WriteFiles writes resolv.conf and hosts under dir and returns [src, dst] bind pairs.
func WriteFiles(dir, hostname string, info *Info) ([][2]string, error) {
	resolv := ResolvConf("/etc/resolv.conf", info.Mode == Bridge)
	if info.Mode == None {
		resolv = ""
	}
	files := map[string]string{"resolv.conf": resolv, "hosts": HostsFile(hostname, info.IP)}
	var binds [][2]string
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			return nil, err
		}
		binds = append(binds, [2]string{p, "/etc/" + name})
	}
	return binds, nil
}

// IPAMForPrune exposes the IPAM for stale-lease cleanup.
func (m *Manager) IPAMForPrune() (*IPAM, error) { return m.ipam() }
