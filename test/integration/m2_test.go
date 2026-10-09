//go:build integration

package integration

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func run(t *testing.T, script string) string {
	t.Helper()
	root := os.Getenv("MINIBOX_TEST_ROOTFS")
	if root == "" {
		root = "../../rootfs"
	}
	out, err := exec.Command("../../bin/minibox", "run-raw", root, "/bin/sh", "-c", script).CombinedOutput()
	if err != nil {
		t.Logf("exit: %v", err)
	}
	return string(out)
}

func TestRootfsIsolation(t *testing.T) {
	t.Setenv("MINIBOX_ROOT", t.TempDir())
	out := run(t, `ps | wc -l; echo x >/dev/null && echo null-ok; head -c1 /dev/urandom | wc -c; touch /sys/x 2>&1; ls /.oldroot 2>&1`)
	for _, want := range []string{"null-ok", "Read-only file system", "No such file or directory"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if m, _ := os.ReadFile("/proc/self/mountinfo"); strings.Contains(string(m), "minibox") {
		t.Error("leaked mounts")
	}
}
