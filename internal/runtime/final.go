//go:build linux

package runtime

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"minibox/internal/security"
)

// resolveUser maps "uid[:gid]" or "name[:group]" to ids using the container's /etc/passwd and /etc/group.
func ResolveUser(u string) (uid, gid int, err error) {
	us, gs, _ := strings.Cut(u, ":")
	if n, e := strconv.Atoi(us); e == nil {
		uid, gid = n, n
		if f, e := os.Open("/etc/passwd"); e == nil {
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				if p := strings.Split(sc.Text(), ":"); len(p) > 3 && p[2] == us {
					gid, _ = strconv.Atoi(p[3])
				}
			}
		}
	} else {
		found := false
		if f, e := os.Open("/etc/passwd"); e == nil {
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				if p := strings.Split(sc.Text(), ":"); len(p) > 3 && p[0] == us {
					uid, _ = strconv.Atoi(p[2])
					gid, _ = strconv.Atoi(p[3])
					found = true
				}
			}
		}
		if !found {
			return 0, 0, fmt.Errorf("user %q not found in the container's /etc/passwd; use a numeric uid", us)
		}
	}
	if gs != "" {
		if n, e := strconv.Atoi(gs); e == nil {
			gid = n
		} else {
			found := false
			if f, e := os.Open("/etc/group"); e == nil {
				defer f.Close()
				sc := bufio.NewScanner(f)
				for sc.Scan() {
					if p := strings.Split(sc.Text(), ":"); len(p) > 2 && p[0] == gs {
						gid, _ = strconv.Atoi(p[2])
						found = true
					}
				}
			}
			if !found {
				return 0, 0, fmt.Errorf("group %q not found in the container's /etc/group; use a numeric gid", gs)
			}
		}
	}
	return uid, gid, nil
}

// DropUser switches to the given user (after the rootfs is in place).
func DropUser(user string) error {
	if user == "" {
		return nil
	}
	uid, gid, err := ResolveUser(user)
	if err != nil {
		return err
	}
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid %d: %w", gid, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid %d: %w", uid, err)
	}
	return nil
}

// Harden applies capability limits, no_new_privs and the seccomp profile to the calling
// (locked) thread, so that everything it forks or execs inherits them. With a non-root user the
// capabilities vanish at setuid; SETUID/SETGID stay in the bounding set until then.
func Harden(caps []string, seccomp bool, user string) error {
	keep := append([]string(nil), caps...)
	if user != "" && user != "0" && user != "root" {
		keep = append(keep, "SETUID", "SETGID")
	}
	if caps != nil {
		if err := security.ApplyCaps(keep); err != nil {
			return err
		}
	}
	if err := security.NoNewPrivs(); err != nil {
		return err
	}
	if seccomp {
		return security.ApplySeccomp(caps)
	}
	return nil
}

// execFinal runs the user command: directly (execve) or, with spec.Init, as a child of
// a minimal PID 1 that reaps orphans and forwards signals.
func execFinal(spec *InitSpec, path string) error {
	goruntime.LockOSThread() // capability and no_new_privs state is per-thread: exec/fork from this one
	if err := Harden(spec.Caps, spec.Seccomp, spec.User); err != nil {
		return err
	}
	if !spec.Init {
		if spec.TTY {
			if _, err := unix.Setsid(); err != nil {
				return fmt.Errorf("setsid: %w", err)
			}
			if err := unix.IoctlSetInt(0, unix.TIOCSCTTY, 0); err != nil {
				return fmt.Errorf("set controlling tty: %w", err)
			}
		}
		if err := DropUser(spec.User); err != nil {
			return err
		}
		return unix.Exec(path, spec.Cmd, spec.Env)
	}
	// Signals must be caught before forking so none is lost.
	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT,
		syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGCHLD)
	attr := &syscall.ProcAttr{Env: spec.Env, Files: []uintptr{0, 1, 2}}
	if spec.TTY {
		attr.Sys = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	}
	// The user switch must only affect the child: do it via credentials.
	if spec.User != "" {
		uid, gid, err := ResolveUser(spec.User)
		if err != nil {
			return err
		}
		if attr.Sys == nil {
			attr.Sys = &syscall.SysProcAttr{}
		}
		attr.Sys.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}}
	}
	pid, err := syscall.ForkExec(path, spec.Cmd, attr)
	if err != nil {
		return fmt.Errorf("exec %s: %w", path, err)
	}
	for s := range sigs {
		if s != syscall.SIGCHLD {
			_ = syscall.Kill(pid, s.(syscall.Signal))
			continue
		}
		for {
			var ws syscall.WaitStatus
			p, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
			if p <= 0 || err != nil {
				break
			}
			if p == pid {
				if ws.Signaled() {
					os.Exit(128 + int(ws.Signal()))
				}
				os.Exit(ws.ExitStatus())
			}
		}
	}
	return nil
}

// ExecSpec is passed to the exec helper on fd 3.
type ExecSpec struct {
	Pid     int // container init pid (host view)
	Cmd     []string
	Env     []string
	Workdir string
	User    string
	TTY     bool
	Caps    []string
	Seccomp bool
}

// ExecInit is the hidden `exec-init` helper: it enters the container's ipc/uts/net/pid
// namespaces and root (via /proc/PID/root; setns(mnt) is impossible from a multithreaded
// Go process, see docs/DECISIONS.md) and runs the command as a child inside the PID namespace.
func ExecInit() (int, error) {
	f := os.NewFile(3, "spec")
	var spec ExecSpec
	if err := jsonDecode(f, &spec); err != nil {
		return 125, fmt.Errorf("exec-init: read spec: %w", err)
	}
	f.Close()
	if len(spec.Cmd) == 0 {
		return 125, fmt.Errorf("exec-init: no command")
	}
	pid := strconv.Itoa(spec.Pid)
	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	prewarmThreads()
	var fds []int
	for _, ns := range []struct {
		name string
		flag int
	}{{"ipc", unix.CLONE_NEWIPC}, {"uts", unix.CLONE_NEWUTS}, {"net", unix.CLONE_NEWNET}, {"pid", unix.CLONE_NEWPID}} {
		fd, err := unix.Open("/proc/"+pid+"/ns/"+ns.name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return 125, fmt.Errorf("open %s namespace of pid %d: %w; is the container still running?", ns.name, spec.Pid, err)
		}
		defer unix.Close(fd)
		fds = append(fds, fd)
		_ = ns.flag
	}
	root, err := unix.Open("/proc/"+pid+"/root", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 125, fmt.Errorf("open root of pid %d: %w; is the container still running?", spec.Pid, err)
	}
	for i, ns := range []int{unix.CLONE_NEWIPC, unix.CLONE_NEWUTS, unix.CLONE_NEWNET, unix.CLONE_NEWPID} {
		if err := unix.Setns(fds[i], ns); err != nil {
			return 125, fmt.Errorf("setns: %w", err)
		}
	}
	if err := unix.Fchdir(root); err != nil {
		return 125, err
	}
	if err := unix.Chroot("."); err != nil {
		return 125, fmt.Errorf("chroot into container: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return 125, err
	}
	if spec.Workdir != "" {
		if err := unix.Chdir(spec.Workdir); err != nil {
			return 125, fmt.Errorf("chdir %s: %w", spec.Workdir, err)
		}
	}
	path, err := lookPath(spec.Cmd[0], spec.Env)
	if err != nil {
		return 127, err
	}
	goruntime.LockOSThread()
	if err := Harden(spec.Caps, spec.Seccomp, spec.User); err != nil {
		return 125, err
	}
	attr := &syscall.ProcAttr{Env: spec.Env, Files: []uintptr{0, 1, 2}}
	sys := &syscall.SysProcAttr{}
	if spec.TTY {
		sys.Setsid, sys.Setctty, sys.Ctty = true, true, 0
	}
	if spec.User != "" {
		uid, gid, err := ResolveUser(spec.User)
		if err != nil {
			return 125, err
		}
		sys.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}}
	}
	attr.Sys = sys
	cpid, err := syscall.ForkExec(path, spec.Cmd, attr)
	if err != nil {
		return 126, fmt.Errorf("exec %s: %w", path, err)
	}
	go func() {
		for s := range sigs {
			_ = syscall.Kill(cpid, s.(syscall.Signal))
		}
	}()
	var ws syscall.WaitStatus
	for {
		if _, err := syscall.Wait4(cpid, &ws, 0, nil); err != syscall.EINTR {
			break
		}
	}
	if ws.Signaled() {
		return 128 + int(ws.Signal()), nil
	}
	return ws.ExitStatus(), nil
}

func jsonDecode(f *os.File, v any) error { return json.NewDecoder(f).Decode(v) }

// prewarmThreads makes the Go runtime create a few OS threads now. After setns(CLONE_NEWPID)
// the kernel refuses clone(CLONE_THREAD) in this process (EINVAL), so the runtime must be
// able to reuse idle threads for everything that follows.
func prewarmThreads() {
	var wg sync.WaitGroup
	prev := goruntime.GOMAXPROCS(4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ts := unix.Timespec{Nsec: 5_000_000}
			_ = unix.Nanosleep(&ts, nil)
		}()
	}
	wg.Wait()
	goruntime.GOMAXPROCS(prev)
}
