//go:build linux

// Package runtime implements the re-exec pattern: the parent launches
// /proc/self/exe with new namespaces; the child ("init") sets up the
// rootfs and execs the user command.
package runtime

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"

	"minibox/internal/cgroup"
	"minibox/internal/state"
)

// RunRaw runs cmd in new PID/mount/UTS/IPC/net namespaces chrooted into rootfs.
// Returns the child's exit code.
func RunRaw(rootfs string, cmd []string, lim cgroup.Limits) (int, error) {
	st, err := os.Stat(rootfs)
	if err != nil || !st.IsDir() {
		return 125, fmt.Errorf("rootfs %q is not a directory; extract an Alpine minirootfs there first (see bench/fetch-rootfs.sh)", rootfs)
	}
	abs, err := absPath(rootfs)
	if err != nil {
		return 125, err
	}
	id, err := newID()
	if err != nil {
		return 125, err
	}
	lock, err := state.HoldLock(id)
	if err != nil {
		return 125, fmt.Errorf("lock container: %w; check that MINIBOX_ROOT (%s) is writable", err, state.Root())
	}
	defer state.Release(id, lock)
	cg, err := cgroup.Create(id, lim)
	if err != nil {
		return 125, err
	}
	defer cg.Remove()
	fd, err := cg.OpenFD()
	if err != nil {
		return 125, err
	}
	defer unix.Close(fd)
	c := exec.Command("/proc/self/exe", append([]string{"init", abs}, cmd...)...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWIPC | syscall.CLONE_NEWNET,
		Pdeathsig:   syscall.SIGKILL,
		UseCgroupFD: true,
		CgroupFD:    fd,
	}
	if err := c.Start(); err != nil {
		return 125, fmt.Errorf("start container (need root or CAP_SYS_ADMIN): %w", err)
	}
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for s := range sigs {
			_ = c.Process.Signal(s)
		}
	}()
	err = c.Wait()
	signal.Stop(sigs)
	if ev := cg.MemoryEvents(); ev.OOMKill > 0 {
		fmt.Fprintf(os.Stderr, "minibox: container was OOM-killed (%d process(es) killed; memory limit %d bytes); raise --memory\n", ev.OOMKill, lim.MemoryBytes)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return ee.ExitCode(), nil
	}
	return 0, err
}

// Init runs inside the new namespaces as PID 1: args = ROOTFS CMD...
func Init(args []string) error {
	if len(args) < 2 {
		return errors.New("init: missing arguments")
	}
	rootfs, cmd := args[0], args[1:]
	// Make mounts private so nothing propagates to the host.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make / private: %w", err)
	}
	if err := unix.Sethostname([]byte("minibox")); err != nil {
		return fmt.Errorf("sethostname: %w", err)
	}
	if err := setupRootfs(rootfs); err != nil {
		return err
	}
	path, err := lookPath(cmd[0])
	if err != nil {
		return err
	}
	return unix.Exec(path, cmd, []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "TERM=" + os.Getenv("TERM")})
}

func lookPath(name string) (string, error) {
	if len(name) > 0 && name[0] == '/' {
		return name, nil
	}
	for _, d := range []string{"/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"} {
		p := d + "/" + name
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("%q not found in container PATH; use an absolute path", name)
}

func absPath(p string) (string, error) {
	if len(p) > 0 && p[0] == '/' {
		return p, nil
	}
	wd, err := os.Getwd()
	return wd + "/" + p, err
}

func newID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Prune removes cgroups and lock files of containers whose supervisor is gone.
func Prune() (int, error) {
	if err := cgroup.Check(); err != nil {
		return 0, err
	}
	n := 0
	for _, id := range cgroup.List() {
		if state.IsAlive(id) {
			continue
		}
		if err := cgroup.RemovePath(cgroup.Base() + "/" + id); err != nil {
			return n, err
		}
		state.Release(id, nil)
		n++
	}
	return n, nil
}
