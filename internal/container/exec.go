//go:build linux

package container

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"minibox/internal/cgroup"
	"minibox/internal/network"
	"minibox/internal/pty"
	"minibox/internal/runtime"
	"minibox/internal/state"
)

// ExecOptions describes a command run inside a running container.
type ExecOptions struct {
	Cmd         []string
	Env         []string // appended to the container's env
	Workdir     string
	User        string
	TTY         bool
	Interactive bool
}

// Exec runs a command in the container's namespaces and cgroup and returns its exit code.
func Exec(c *Container, o ExecOptions) (int, error) {
	_ = c.Refresh()
	if !c.Running() {
		return 125, fmt.Errorf("container %s is not running (status: %s); start one with `minibox run -d` first", short(c.Config.ID), c.DisplayStatus())
	}
	spec := runtime.ExecSpec{Pid: c.State.Pid, Cmd: o.Cmd, Env: dedupEnv(append(append([]string(nil), c.Config.Env...), o.Env...)),
		Workdir: o.Workdir, User: o.User, TTY: o.TTY, Caps: c.Config.Caps, Seccomp: c.Config.Seccomp}
	if spec.Workdir == "" {
		spec.Workdir = c.Config.Workdir
	}
	if spec.User == "" {
		spec.User = c.Config.User
	}
	if os.Geteuid() != 0 {
		return 125, errors.New("exec is not supported rootless yet (joining the user namespace needs a single-threaded helper); use `minibox run` with the command directly")
	}
	cg := &cgroup.Cgroup{Path: cgroup.Base() + "/" + c.Config.ID}
	fd, err := cg.OpenFD()
	if err != nil {
		return 125, fmt.Errorf("open container cgroup: %w", err)
	}
	defer unix.Close(fd)
	specR, specW, err := os.Pipe()
	if err != nil {
		return 125, err
	}
	defer specR.Close()
	sb, _ := json.Marshal(spec)

	cmd := exec.Command("/proc/self/exe", "exec-init")
	cmd.ExtraFiles = []*os.File{specR}
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	var master, slave *os.File
	if o.TTY {
		if !pty.IsTerminal(0) {
			return 125, errors.New("the input device is not a TTY; drop -t or run from a terminal")
		}
		if master, slave, err = pty.Open(); err != nil {
			return 125, err
		}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	} else {
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if o.Interactive {
			cmd.Stdin = os.Stdin
		}
	}
	if err := cmd.Start(); err != nil {
		return 125, fmt.Errorf("start exec helper: %w", err)
	}
	if slave != nil {
		slave.Close()
	}
	go func() { specW.Write(sb); specW.Close() }()
	var restore func()
	var outDone chan struct{}
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGWINCH)
	stop := make(chan struct{})
	if master != nil {
		pty.CopySize(0, master)
		restore, _ = pty.MakeRaw(0)
		go io.Copy(master, os.Stdin)
		outDone = make(chan struct{})
		go func() { io.Copy(os.Stdout, master); close(outDone) }()
	}
	go func() {
		for {
			select {
			case s := <-sigs:
				if s == syscall.SIGWINCH {
					if master != nil {
						pty.CopySize(0, master)
					}
					continue
				}
				_ = cmd.Process.Signal(s)
			case <-stop:
				return
			}
		}
	}()
	werr := cmd.Wait()
	signal.Stop(sigs)
	close(stop)
	if outDone != nil {
		select {
		case <-outDone:
		case <-time.After(200 * time.Millisecond):
		}
		master.Close()
	}
	if restore != nil {
		restore()
	}
	var ee *exec.ExitError
	if errors.As(werr, &ee) {
		return ee.ExitCode(), nil
	}
	return 0, werr
}

// dedupEnv keeps the last value of each key, preserving first-seen order,
// so -e overrides win over the container's configured values.
func dedupEnv(env []string) []string {
	idx := map[string]int{}
	var out []string
	for _, e := range env {
		k, _, _ := strings.Cut(e, "=")
		if i, ok := idx[k]; ok {
			out[i] = e
			continue
		}
		idx[k] = len(out)
		out = append(out, e)
	}
	return out
}

// Prune finalises dead containers and removes leftover cgroups, lock files and
// half-created container directories. Returns the number of things cleaned.
func Prune() (int, error) {
	if os.Geteuid() == 0 {
		if err := cgroup.Check(); err != nil {
			return 0, err
		}
	}
	n := 0
	for _, c := range List() {
		if c.Reconcile() {
			n++
		}
	}
	if ents, _ := os.ReadDir(containersDir()); ents != nil {
		// Create() makes the directory before writing state.json; without the
		// creation lock a concurrent Create looks abandoned here. Serialize
		// with container creation before treating a missing state as garbage.
		l, err := globalLock()
		if err != nil {
			return n, fmt.Errorf("lock %s: %w", containersDir(), err)
		}
		for _, e := range ents {
			if !e.IsDir() {
				continue
			}
			if _, err := os.Stat(statePath(e.Name())); err == nil || state.IsAlive(e.Name()) {
				continue
			}
			if err := os.RemoveAll(Dir(e.Name())); err != nil {
				unlock(l)
				return n, err
			}
			n++
		}
		unlock(l)
	}
	// Leases and published ports of containers that no longer exist.
	keep := map[string]bool{}
	for _, c := range List() {
		if c.State.Status == "running" || c.State.Status == "created" {
			keep[c.Config.ID] = true
		}
	}
	ipam, err := (&network.Manager{Root: state.Root()}).IPAMForPrune()
	if err != nil {
		return n, fmt.Errorf("load IPAM state: %w", err)
	}
	if k, err := ipam.ReleaseExcept(keep); err != nil {
		return n, fmt.Errorf("release stale leases: %w", err)
	} else if k > 0 {
		n += k
	}
	for _, id := range cgroupList() {
		if state.IsAlive(id) {
			continue
		}
		if !state.HasLock(id) && cgroup.HasProcs(cgroup.Base()+"/"+id) {
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

func cgroupList() []string {
	if os.Geteuid() != 0 {
		return nil
	}
	return cgroup.List()
}
