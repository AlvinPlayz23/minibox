//go:build linux

// Package runtime implements the re-exec pattern: the parent launches
// /proc/self/exe with new namespaces; the child ("init") sets up the
// rootfs and execs the user command.
package runtime

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

// RunRaw runs cmd in new PID/mount/UTS/IPC/net namespaces chrooted into rootfs.
// Returns the child's exit code.
func RunRaw(rootfs string, cmd []string) (int, error) {
	st, err := os.Stat(rootfs)
	if err != nil || !st.IsDir() {
		return 125, fmt.Errorf("rootfs %q is not a directory; extract an Alpine minirootfs there first (see bench/fetch-rootfs.sh)", rootfs)
	}
	abs, err := absPath(rootfs)
	if err != nil {
		return 125, err
	}
	c := exec.Command("/proc/self/exe", append([]string{"init", abs}, cmd...)...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWIPC | syscall.CLONE_NEWNET,
		Pdeathsig: syscall.SIGKILL,
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
	if err := unix.Chroot(rootfs); err != nil {
		return fmt.Errorf("chroot %s: %w", rootfs, err)
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	// /proc so ps shows only this PID namespace (mount ns is private; dies with it).
	_ = os.MkdirAll("/proc", 0o555)
	if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NOEXEC|unix.MS_NODEV, ""); err != nil {
		return fmt.Errorf("mount /proc: %w", err)
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
