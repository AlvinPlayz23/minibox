//go:build integration

package integration

import (
	"strings"
	"testing"
)

func TestM8CapsSeccompNoNewPrivs(t *testing.T) {
	m5Root(t)
	out, err := mb(t, "run", "--rm", "--network", "none", "alpine", "grep", "-E", "CapEff|CapBnd|NoNewPrivs", "/proc/self/status")
	if err != nil {
		t.Fatal(err, out)
	}
	for _, want := range []string{"CapEff:\t00000000a80425fb", "CapBnd:\t00000000a80425fb", "NoNewPrivs:\t1"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// mount is blocked by seccomp and by the dropped CAP_SYS_ADMIN.
	out, _ = mb(t, "run", "--rm", "--network", "none", "alpine", "sh", "-c", "mkdir -p /m; mount -t tmpfs x /m 2>&1; echo rc=$?")
	if !strings.Contains(out, "rc=1") || !strings.Contains(strings.ToLower(out), "permission denied") {
		t.Errorf("mount not blocked: %s", out)
	}
	out, _ = mb(t, "run", "--rm", "--network", "none", "alpine", "unshare", "-m", "true")
	if !strings.Contains(out, "not permitted") {
		t.Errorf("unshare not blocked: %s", out)
	}
	// --cap-add SYS_ADMIN re-enables mount.
	out, _ = mb(t, "run", "--rm", "--network", "none", "--cap-add", "SYS_ADMIN", "alpine", "sh", "-c", "mkdir -p /m; mount -t tmpfs x /m && echo mounted")
	if !strings.Contains(out, "mounted") {
		t.Errorf("cap-add SYS_ADMIN: %s", out)
	}
	// --cap-drop ALL
	out, _ = mb(t, "run", "--rm", "--network", "none", "--cap-drop", "ALL", "alpine", "grep", "CapEff", "/proc/self/status")
	if !strings.Contains(out, "0000000000000000") {
		t.Errorf("cap-drop ALL: %s", out)
	}
	// exec'd processes are hardened too
	mb(t, "run", "-d", "--network", "none", "--name", "h", "alpine", "sleep", "100")
	out, _ = mb(t, "exec", "h", "sh", "-c", "grep -E 'CapEff|NoNewPrivs' /proc/self/status; mkdir -p /m; mount -t tmpfs x /m 2>&1")
	if !strings.Contains(out, "a80425fb") || !strings.Contains(out, "NoNewPrivs:\t1") || !strings.Contains(strings.ToLower(out), "denied") {
		t.Errorf("exec not hardened: %s", out)
	}
	mb(t, "rm", "-f", "h")
}

func TestM8ReadOnlyAndUser(t *testing.T) {
	m5Root(t)
	out, _ := mb(t, "run", "--rm", "--network", "none", "--read-only", "alpine", "sh", "-c", "touch /x 2>&1; echo rc=$?")
	if !strings.Contains(out, "Read-only file system") {
		t.Errorf("read-only: %s", out)
	}
	out, _ = mb(t, "run", "--rm", "--network", "none", "-u", "1000", "alpine", "sh", "-c", "id -u; grep CapEff /proc/self/status")
	if !strings.Contains(out, "1000") || !strings.Contains(out, "CapEff:\t0000000000000000") {
		t.Errorf("-u: %s", out)
	}
	// A no-op user switch (root while already root) must not require the
	// dropped SETGID/SETUID capabilities.
	out, err := mb(t, "run", "--rm", "--network", "none", "-u", "root", "--cap-drop", "SETGID", "--cap-drop", "SETUID", "alpine", "id", "-u")
	if err != nil || strings.TrimSpace(out) != "0" {
		t.Errorf("-u root with dropped SETGID/SETUID: %v %q", err, out)
	}
	out, err = mb(t, "run", "--rm", "--network", "none", "alpine", "sh", "-c", "cat /proc/kcore; echo rc=$?")
	if err == nil && strings.Contains(out, "ELF") {
		t.Errorf("/proc/kcore readable: %q", out)
	}
	// The rc= marker proves cat actually ran: a startup failure before exec
	// must fail this test instead of passing vacuously.
	if !strings.Contains(out, "rc=") {
		t.Errorf("/proc/kcore check never ran: %q (err=%v)", out, err)
	}
	leaked(t)
}
