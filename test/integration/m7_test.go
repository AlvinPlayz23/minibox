//go:build integration

package integration

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func netLeaks(t *testing.T) {
	t.Helper()
	if out, _ := exec.Command("ip", "-o", "link").Output(); strings.Contains(string(out), " vb") {
		t.Errorf("leaked veth: %s", out)
	}
	if out, _ := exec.Command("nft", "list", "table", "ip", "minibox").Output(); strings.Contains(string(out), "elements") {
		t.Errorf("leaked published port: %s", out)
	}
	if b, err := os.ReadFile(os.Getenv("MINIBOX_ROOT") + "/network/ipam.json"); err == nil && strings.Contains(string(b), `"172.`) {
		t.Errorf("leaked IP lease: %s", b)
	}
}

func TestM7BridgeDNSInternetAndFiles(t *testing.T) {
	m5Root(t)
	out, err := mb(t, "run", "--rm", "alpine", "sh", "-c", "ip -4 addr show eth0; cat /etc/hosts; ip route")
	if err != nil || !strings.Contains(out, "172.30.0.") || !strings.Contains(out, "default via 172.30.0.1") {
		t.Fatalf("bridge config: %v\n%s", err, out)
	}
	if c, err := exec.Command("sh", "-c", "getent hosts example.com").Output(); err == nil && len(c) > 0 {
		out, err := mb(t, "run", "--rm", "alpine", "sh", "-c", "nslookup example.com >/dev/null && ping -c1 -W3 1.1.1.1 >/dev/null && echo NET-OK")
		if err != nil || !strings.Contains(out, "NET-OK") {
			t.Fatalf("internet/DNS: %v %s", err, out)
		}
	}
	netLeaks(t)
}

func TestM7TwoContainersAndPortPublish(t *testing.T) {
	m5Root(t)
	// Server replies once per connection.
	if o, err := mb(t, "run", "-d", "--name", "srv", "-p", "18080:80", "alpine", "sh", "-c", "while true; do echo reply | nc -l -p 80; done"); err != nil {
		t.Fatalf("%v %s", err, o)
	}
	time.Sleep(700 * time.Millisecond)
	if o, err := exec.Command("bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/18080; timeout 2 cat <&3").CombinedOutput(); err != nil || !strings.Contains(string(o), "reply") {
		t.Fatalf("host -> published port: %v %q", err, o)
	}
	ip, _ := exec.Command("sh", "-c", "jq -r .ip $MINIBOX_ROOT/containers/*/net.json").Output()
	o, err := mb(t, "run", "--rm", "alpine", "sh", "-c", "nc -w2 "+strings.TrimSpace(string(ip))+" 80 </dev/null")
	if err != nil || !strings.Contains(o, "reply") {
		t.Fatalf("container -> container: %v %q", err, o)
	}
	if o, err := mb(t, "run", "-d", "-p", "18080:80", "alpine", "sleep", "5"); err == nil {
		t.Errorf("duplicate host port accepted: %s", o)
	}
	mb(t, "rm", "-f", "srv")
	netLeaks(t)
	leaked(t)
}

func TestM7NoneAndHost(t *testing.T) {
	m5Root(t)
	out, _ := mb(t, "run", "--rm", "--network", "none", "alpine", "sh", "-c", "ip -o link | grep -c eth0")
	if strings.TrimSpace(out) != "0" {
		t.Errorf("none mode has eth0: %q", out)
	}
	out, _ = mb(t, "run", "--rm", "--network", "host", "alpine", "sh", "-c", "ip -o link | grep -c minibox0")
	if strings.TrimSpace(out) == "0" {
		t.Errorf("host mode does not see host links: %q", out)
	}
	if _, err := mb(t, "run", "--rm", "-p", "80:80", "--network", "none", "alpine", "true"); err == nil {
		t.Error("-p with none accepted")
	}
	netLeaks(t)
}

func TestM7KillShimCleansNetwork(t *testing.T) {
	m5Root(t)
	mb(t, "run", "-d", "-p", "18081:80", "alpine", "sleep", "1000")
	exec.Command("pkill", "-9", "-f", "^/proc/self/exe shim").Run()
	time.Sleep(300 * time.Millisecond)
	mb(t, "system", "prune")
	netLeaks(t)
	leaked(t)
}
