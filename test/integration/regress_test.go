//go:build integration

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

const rootfs = "../../rootfs"

func needRootfs(t *testing.T) {
	if _, err := os.Stat(rootfs + "/bin/busybox"); err != nil {
		t.Skip("run bench/fetch-rootfs.sh first")
	}
}

func TestExitCodesAndStdin(t *testing.T) {
	needRootfs(t)
	t.Setenv("MINIBOX_ROOT", t.TempDir())
	cases := []struct {
		args []string
		want int
	}{
		{[]string{rootfs, "/bin/sh", "-c", "exit 42"}, 42},
		{[]string{rootfs, "/bin/sh", "-c", "kill -9 $$"}, 0}, // PID 1 cannot be killed from inside its own namespace
		{[]string{rootfs, "nosuchcmd"}, 126},
		{[]string{rootfs, "/bin/true"}, 0},
		{[]string{"/nonexistent", "/bin/true"}, 125},
	}
	for _, c := range cases {
		_, err := mb(t, append([]string{"run-raw"}, c.args...)...)
		got := 0
		if ee, ok := err.(*exec.ExitError); ok {
			got = ee.ExitCode()
		}
		if got != c.want {
			t.Errorf("%v: exit %d want %d", c.args, got, c.want)
		}
	}
	cmd := exec.Command("../../bin/minibox", "run-raw", rootfs, "/bin/cat")
	cmd.Stdin = strings.NewReader("piped data")
	if out, err := cmd.CombinedOutput(); err != nil || string(out) != "piped data" {
		t.Errorf("stdin: %v %q", err, out)
	}
	leaked(t)
}

func TestSupervisorSignalForwarded(t *testing.T) {
	needRootfs(t)
	t.Setenv("MINIBOX_ROOT", t.TempDir())
	// A shell that traps TERM so it behaves as a well-behaved PID 1.
	cmd := exec.Command("../../bin/minibox", "run-raw", rootfs, "/bin/sh", "-c", "trap 'exit 7' TERM; while :; do sleep 1; done")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	cmd.Process.Signal(os.Signal(sigterm))
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 7 {
			t.Errorf("want exit 7 from trap, got %v", err)
		}
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatal("SIGTERM was not forwarded to the container")
	}
	leaked(t)
}

func TestHostIsolationFromInside(t *testing.T) {
	needRootfs(t)
	t.Setenv("MINIBOX_ROOT", t.TempDir())
	host, _ := os.Hostname()
	out, err := mb(t, "run-raw", rootfs, "/bin/sh", "-c", `hostname; ls /proc | grep -c '^[0-9]'; ls /.oldroot 2>&1; ls /sys/class/net`)
	if err != nil {
		t.Fatal(err, out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if lines[0] != "minibox" || lines[0] == host {
		t.Errorf("hostname %q", lines[0])
	}
	if lines[1] != "2" && lines[1] != "3" { // sh + ls + grep pipeline members
		t.Errorf("container sees %s processes", lines[1])
	}
	if got, _ := os.Hostname(); got != host {
		t.Error("host hostname changed")
	}
	if strings.Contains(out, "eth0") || strings.Contains(out, "lo\n") && strings.Contains(out, "docker0") {
		t.Errorf("host network visible: %s", out)
	}
	leaked(t)
}

func TestCPULimitThrottles(t *testing.T) {
	needRootfs(t)
	t.Setenv("MINIBOX_ROOT", t.TempDir())
	work := "i=0; while [ $i -lt 300000 ]; do i=$((i+1)); done"
	timeit := func(extra ...string) time.Duration {
		st := time.Now()
		args := append([]string{"run-raw"}, extra...)
		if out, err := mb(t, append(args, rootfs, "/bin/sh", "-c", work)...); err != nil {
			t.Fatal(err, out)
		}
		return time.Since(st)
	}
	free, limited := timeit(), timeit("--cpus", "0.25")
	if limited < free*2 {
		t.Errorf("--cpus 0.25 not throttling: free=%v limited=%v", free, limited)
	}
	leaked(t)
}

func TestParallelAndSequentialRunsLeaveNothing(t *testing.T) {
	needRootfs(t)
	t.Setenv("MINIBOX_ROOT", t.TempDir())
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out, err := mb(t, "run-raw", "--memory", "64m", "--pids-limit", "50", rootfs, "/bin/sh", "-c", fmt.Sprintf("echo %d", i))
			if err != nil || strings.TrimSpace(out) != fmt.Sprint(i) {
				errs <- fmt.Sprintf("%d: %v %q", i, err, out)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	for i := 0; i < 100; i++ {
		if out, err := mb(t, "run-raw", rootfs, "/bin/true"); err != nil {
			t.Fatalf("run %d: %v %s", i, err, out)
		}
	}
	leaked(t)
	if m, _ := os.ReadFile("/proc/self/mountinfo"); strings.Contains(string(m), "/app/rootfs") {
		t.Error("rootfs mount leaked into host namespace")
	}
	if ents, _ := os.ReadDir(os.Getenv("MINIBOX_ROOT") + "/run"); len(ents) != 0 {
		t.Errorf("%d lock files left", len(ents))
	}
}

var sigterm = syscallSIGTERM
