//go:build integration

package integration

import (
	"net"
	"strings"
	"testing"
	"time"
)

func needNet(t *testing.T) {
	c, err := net.DialTimeout("tcp", "registry-1.docker.io:443", 5*time.Second)
	if err != nil {
		t.Skip("no network to Docker Hub")
	}
	c.Close()
}

func TestM6PullRunFromCleanStore(t *testing.T) {
	needNet(t)
	t.Setenv("MINIBOX_ROOT", t.TempDir())
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"run", "--rm", "alpine", "echo", "hi"}, "hi"},
		{[]string{"run", "--rm", "busybox", "echo", "hi"}, "hi"},
		{[]string{"run", "--rm", "debian:stable-slim", "cat", "/etc/os-release"}, "Debian"},
	} {
		out, err := mb(t, c.args...)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%v: want %q: %v\n%s", c.args, c.want, err, out)
		}
	}
	if out, _ := mb(t, "images"); !strings.Contains(out, "alpine") || !strings.Contains(out, "debian") {
		t.Fatalf("images: %s", out)
	}
	if out, err := mb(t, "rmi", "busybox"); err != nil || !strings.Contains(out, "Untagged") {
		t.Fatalf("rmi: %v %s", err, out)
	}
	if out, _ := mb(t, "images"); strings.Contains(out, "busybox") {
		t.Fatalf("rmi left image: %s", out)
	}
	if out, err := mb(t, "rmi", "nonexistent"); err == nil {
		t.Fatalf("rmi of missing image succeeded: %s", out)
	}
	leaked(t)
}
