//go:build integration

package integration

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func mb(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command("../../bin/minibox", args...).CombinedOutput()
	return string(out), err
}

func leaked(t *testing.T) {
	t.Helper()
	ents, _ := os.ReadDir("/sys/fs/cgroup/minibox")
	for _, e := range ents {
		if len(e.Name()) == 64 {
			t.Errorf("leaked cgroup %s", e.Name())
		}
	}
}

func TestMemoryLimitOOM(t *testing.T) {
	t.Setenv("MINIBOX_ROOT", t.TempDir())
	out, err := mb(t, "run-raw", "--memory", "50m", "../../rootfs", "/bin/sh", "-c",
		`x=$(head -c 120000000 /dev/zero | tr "\0" a); echo survived`)
	if err == nil || !strings.Contains(out, "OOM-killed") || strings.Contains(out, "survived") {
		t.Fatalf("expected OOM kill, got err=%v out=%q", err, out)
	}
	leaked(t)
}

func TestPidsLimit(t *testing.T) {
	t.Setenv("MINIBOX_ROOT", t.TempDir())
	out, _ := mb(t, "run-raw", "--pids-limit", "10", "../../rootfs", "/bin/sh", "-c",
		`for i in 1 2 3 4 5 6 7 8 9 10 11 12; do sleep 2 & done; wait`)
	if !strings.Contains(out, "can't fork") {
		t.Fatalf("fork not limited: %q", out)
	}
	leaked(t)
}
