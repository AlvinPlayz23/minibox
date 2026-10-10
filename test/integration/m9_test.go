//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// cmdDir runs minibox in dir (compose file discovery + project naming need the cwd).
func cmdDir(t *testing.T, dir, arg string) string {
	t.Helper()
	bin, err := filepath.Abs("../../bin/minibox")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, arg)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "MINIBOX_ROOT="+os.Getenv("MINIBOX_ROOT"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("minibox %s in %s: %v\n%s", arg, dir, err, out)
	}
	return string(out)
}

func TestM9Volumes(t *testing.T) {
	m5Root(t)
	// Bind mount.
	host := t.TempDir()
	os.WriteFile(filepath.Join(host, "f.txt"), []byte("bind-data"), 0o644)
	out, err := mb(t, "run", "--rm", "--network", "none", "-v", host+":/data", "alpine", "cat", "/data/f.txt")
	if err != nil || strings.TrimSpace(out) != "bind-data" {
		t.Fatalf("bind: %v %q", err, out)
	}
	// Read-only bind.
	out, _ = mb(t, "run", "--rm", "--network", "none", "-v", host+":/data:ro", "alpine", "sh", "-c", "echo x > /data/nope 2>&1; echo rc=$?")
	if !strings.Contains(out, "Read-only") {
		t.Fatalf("ro bind: %q", out)
	}
	// Named volume persists across containers.
	mb(t, "run", "--rm", "--network", "none", "-v", "m9data:/data", "alpine", "sh", "-c", "echo kept > /data/f")
	out, err = mb(t, "run", "--rm", "--network", "none", "-v", "m9data:/data", "alpine", "cat", "/data/f")
	if err != nil || strings.TrimSpace(out) != "kept" {
		t.Fatalf("named volume: %v %q", err, out)
	}
	if out, _ := mb(t, "volume", "ls"); !strings.Contains(out, "m9data") {
		t.Fatalf("volume ls: %q", out)
	}
	// In-use refusal.
	mb(t, "run", "-d", "--network", "none", "--name", "m9holder", "-v", "m9data:/data", "alpine", "sleep", "60")
	if out, err := mb(t, "volume", "rm", "m9data"); err == nil {
		t.Fatalf("removed in-use volume: %q", out)
	}
	mb(t, "rm", "-f", "m9holder")
	if _, err := mb(t, "volume", "rm", "m9data"); err != nil {
		t.Fatal(err)
	}
	// Tmpfs.
	out, err = mb(t, "run", "--rm", "--network", "none", "--tmpfs", "/run:size=32m", "alpine", "sh", "-c", "mount | grep ' /run ' && echo TMPFS-OK")
	if err != nil || !strings.Contains(out, "TMPFS-OK") {
		t.Fatalf("tmpfs: %v %q", err, out)
	}
	// Bad specs rejected.
	for _, args := range [][]string{
		{"run", "--rm", "-v", "relative", "alpine", "true"},
		{"run", "--rm", "-v", "/src:/dst:bogus", "alpine", "true"},
		{"run", "--rm", "--tmpfs", "relative", "alpine", "true"},
	} {
		if _, err := mb(t, args...); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
	netLeaks(t)
	leaked(t)
}

func TestM9Build(t *testing.T) {
	m5Root(t)
	ctx := t.TempDir()
	os.WriteFile(filepath.Join(ctx, "app.txt"), []byte("hello-build"), 0o644)
	os.WriteFile(filepath.Join(ctx, "Dockerfile"), []byte("FROM alpine\nENV GREETING=hi\nWORKDIR /srv\nCOPY app.txt /srv/\nRUN echo built > /srv/marker && cat /srv/app.txt\nCMD [\"cat\", \"/srv/marker\"]\n"), 0o644)
	out, err := mb(t, "build", "-t", "myapp:1.0", ctx)
	if err != nil || !strings.Contains(out, "myapp:1.0") {
		t.Fatalf("build: %v %s", err, out)
	}
	out, err = mb(t, "run", "--rm", "--network", "none", "myapp:1.0")
	if err != nil || strings.TrimSpace(out) != "built" {
		t.Fatalf("run built image: %v %q", err, out)
	}
	// Rebuild hits the cache.
	out, _ = mb(t, "build", "-t", "myapp:1.0", ctx)
	if !strings.Contains(out, "cached") {
		t.Fatalf("expected cached rebuild: %q", out)
	}
	// Unsupported instructions fail clearly.
	os.WriteFile(filepath.Join(ctx, "Dockerfile"), []byte("FROM alpine\nADD x /y\n"), 0o644)
	if out, err := mb(t, "build", "-t", "bad:1", ctx); err == nil {
		t.Fatalf("ADD accepted: %q", out)
	}
	os.WriteFile(filepath.Join(ctx, "Dockerfile"), []byte("RUN echo no-from\n"), 0o644)
	if _, err := mb(t, "build", "-t", "bad:2", ctx); err == nil {
		t.Fatal("missing FROM accepted")
	}
	netLeaks(t)
	leaked(t)
}

func TestM9UpDown(t *testing.T) {
	m5Root(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "minibox.yml"), []byte(`services:
  web:
    image: alpine
    command: sh -c 'sleep 60'
    environment:
      - A=1
    volumes:
      - updata:/data
    network: none
    restart: unless-stopped
`), 0o644)
	cmdDir(t, dir, "up")
	base := filepath.Base(dir)
	out, err := mb(t, "ps")
	if err != nil || !strings.Contains(out, base+"_web") {
		t.Fatalf("up: %v %q", err, out)
	}
	out, _ = mb(t, "exec", base+"_web", "env")
	if !strings.Contains(out, "A=1") {
		t.Fatalf("up env: %q", out)
	}
	cmdDir(t, dir, "down")
	if out, _ := mb(t, "ps", "-a"); strings.Contains(out, base+"_web") {
		t.Fatalf("down left containers: %q", out)
	}
	netLeaks(t)
	leaked(t)
}

func TestM9SystemdHealthRestart(t *testing.T) {
	m5Root(t)
	if _, err := mb(t, "run", "--rm", "--network", "none", "--restart", "bogus", "alpine", "true"); err == nil {
		t.Fatal("bad --restart accepted")
	}
	mb(t, "run", "-d", "--network", "none", "--name", "m9srv", "--restart", "always", "--health-cmd", "sh -c 'exit 0'", "alpine", "sleep", "60")
	out, _ := mb(t, "systemd", "m9srv")
	if !strings.Contains(out, "Restart=always") || !strings.Contains(out, "ExecStart=") || !strings.Contains(out, "sleep 60") {
		t.Fatalf("systemd: %q", out)
	}
	if out, err := mb(t, "healthcheck", "m9srv"); err != nil || !strings.Contains(out, "healthy") {
		t.Fatalf("healthcheck: %v %q", err, out)
	}
	mb(t, "rm", "-f", "m9srv")
	netLeaks(t)
	leaked(t)
}
