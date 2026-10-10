//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// m5Root returns a fresh MINIBOX_ROOT with the rootfs loaded as image "alpine".
func m5Root(t *testing.T) {
	t.Helper()
	needRootfs(t)
	t.Setenv("MINIBOX_ROOT", t.TempDir())
	tar := exec.Command("tar", "-C", rootfs, "-c", ".")
	load := exec.Command("../../bin/minibox", "load", "alpine")
	pipe, _ := tar.StdoutPipe()
	load.Stdin = pipe
	if err := tar.Start(); err != nil {
		t.Fatal(err)
	}
	if out, err := load.CombinedOutput(); err != nil {
		t.Fatalf("load: %v %s", err, out)
	}
	tar.Wait()
	t.Cleanup(func() {
		out, _ := mb(t, "ps", "-a", "--json")
		var rows []struct{ ID string }
		json.Unmarshal([]byte(out), &rows)
		for _, r := range rows {
			mb(t, "rm", "-f", r.ID)
		}
		mb(t, "system", "prune")
	})
}

func TestM5DetachedLifecycle(t *testing.T) {
	m5Root(t)
	out, err := mb(t, "run", "-d", "--name", "web", "alpine", "sh", "-c", "echo hello; sleep 1000")
	if err != nil {
		t.Fatalf("run -d: %v %s", err, out)
	}
	time.Sleep(500 * time.Millisecond)
	if ps, _ := mb(t, "ps"); !strings.Contains(ps, "web") || !strings.Contains(ps, "Up") {
		t.Fatalf("ps: %s", ps)
	}
	if l, _ := mb(t, "logs", "web"); strings.TrimSpace(l) != "hello" {
		t.Fatalf("logs: %q", l)
	}
	if o, err := mb(t, "exec", "web", "sh", "-c", "echo in-$(hostname)"); err != nil || !strings.HasPrefix(o, "in-") {
		t.Fatalf("exec: %v %q", err, o)
	}
	if _, err := mb(t, "exec", "web", "sh", "-c", "exit 3"); err == nil || err.(*exec.ExitError).ExitCode() != 3 {
		t.Fatalf("exec exit code: %v", err)
	}
	if o, _ := mb(t, "rm", "web"); !strings.Contains(o, "running") {
		t.Fatalf("rm of running container must refuse: %q", o)
	}
	start := time.Now()
	if o, err := mb(t, "stop", "web"); err != nil {
		t.Fatalf("stop: %v %s", err, o)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("stop took %v; init should forward SIGTERM", time.Since(start))
	}
	if ps, _ := mb(t, "ps", "-a"); !strings.Contains(ps, "Exited") {
		t.Fatalf("ps -a: %s", ps)
	}
	if _, err := mb(t, "rm", "web"); err != nil {
		t.Fatal(err)
	}
	leaked(t)
}

func TestM5StopEscalatesToKill(t *testing.T) {
	m5Root(t)
	mb(t, "run", "-d", "--init=false", "--name", "s", "alpine", "sleep", "1000")
	start := time.Now()
	if o, err := mb(t, "stop", "-t", "1", "s"); err != nil {
		t.Fatalf("%v %s", err, o)
	}
	if d := time.Since(start); d < time.Second || d > 5*time.Second {
		t.Errorf("stop took %v, want ~1s then SIGKILL", d)
	}
	leaked(t)
}

func TestM5ExitCodeAndRm(t *testing.T) {
	m5Root(t)
	_, err := mb(t, "run", "--rm", "alpine", "sh", "-c", "exit 42")
	if err == nil || err.(*exec.ExitError).ExitCode() != 42 {
		t.Fatalf("exit code: %v", err)
	}
	if ps, _ := mb(t, "ps", "-a"); strings.Count(ps, "\n") != 1 {
		t.Fatalf("--rm left a container: %s", ps)
	}
	leaked(t)
}

func TestM5KillShimThenPrune(t *testing.T) {
	m5Root(t)
	mb(t, "run", "-d", "--name", "k", "alpine", "sleep", "1000")
	exec.Command("pkill", "-9", "-f", "^/proc/self/exe shim").Run()
	time.Sleep(300 * time.Millisecond)
	if ps, _ := mb(t, "ps", "-a"); !strings.Contains(ps, "Dead") {
		t.Fatalf("expected Dead: %s", ps)
	}
	if _, err := mb(t, "system", "prune"); err != nil {
		t.Fatal(err)
	}
	leaked(t)
	mb(t, "rm", "k")
}

func TestM5HundredSequentialRuns(t *testing.T) {
	m5Root(t)
	for i := 0; i < 100; i++ {
		if o, err := mb(t, "run", "--rm", "alpine", "true"); err != nil {
			t.Fatalf("run %d: %v %s", i, err, o)
		}
	}
	ents, _ := os.ReadDir(os.Getenv("MINIBOX_ROOT") + "/containers")
	for _, e := range ents {
		if e.IsDir() {
			t.Errorf("leftover container dir %s", e.Name())
		}
	}
	leaked(t)
}

func TestM5SigtermForegroundAndUser(t *testing.T) {
	m5Root(t)
	cmd := exec.Command("../../bin/minibox", "run", "--rm", "alpine", "sleep", "1000")
	cmd.Start()
	time.Sleep(500 * time.Millisecond)
	cmd.Process.Signal(syscallSIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		t.Fatal("SIGTERM did not stop the foreground container")
	}
	if o, _ := mb(t, "run", "--rm", "-u", "1000:1000", "alpine", "id", "-u"); strings.TrimSpace(o) != "1000" {
		t.Errorf("-u: %q", o)
	}
	leaked(t)
}

func TestM5TTY(t *testing.T) {
	m5Root(t)
	cmd := exec.Command("python3", "../tools/ptydrive.py", "run")
	cmd.Env = append(os.Environ(), "B="+mustAbs(t, "../../bin/minibox"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pty run: %v %s", err, out)
	}
	cmd = exec.Command("python3", "../tools/ptydrive.py", "exec")
	cmd.Env = append(os.Environ(), "B="+mustAbs(t, "../../bin/minibox"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pty exec: %v %s", err, out)
	}
	leaked(t)
}
