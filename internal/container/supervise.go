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
	"syscall"
	"time"

	"minibox/internal/cgroup"
	"minibox/internal/image"
	"minibox/internal/network"
	"minibox/internal/pty"
	"minibox/internal/runtime"
	"minibox/internal/state"
	"minibox/internal/storage"
)

// Mode selects where the container's stdio goes.
type Mode int

const (
	Foreground Mode = iota // attached to this process's stdio / terminal
	Shim                   // detached: output goes to the log file
)

func (c *Container) initSpec() (runtime.InitSpec, error) {
	var spec runtime.InitSpec
	cfg := c.Config
	if cfg.Image != "" {
		st := &image.Store{Root: state.Root()}
		img, err := st.GetImage(cfg.Image)
		if err != nil {
			return spec, err
		}
		cd := &storage.ContainerDirs{Base: Dir(cfg.ID)}
		for _, d := range []string{"upper", "work", "merged"} {
			if err := os.MkdirAll(Dir(cfg.ID)+"/"+d, 0o755); err != nil {
				return spec, err
			}
		}
		cd.Upper, cd.Work, cd.Merged = Dir(cfg.ID)+"/upper", Dir(cfg.ID)+"/work", Dir(cfg.ID)+"/merged"
		if spec, err = runtime.BuildSpec(st, img, cd); err != nil {
			return spec, err
		}
	} else {
		spec.Rootfs = cfg.Rootfs
	}
	spec.Cmd, spec.Env, spec.Workdir = cfg.Cmd, cfg.Env, cfg.Workdir
	spec.Hostname, spec.User, spec.TTY, spec.Init = cfg.Hostname, cfg.User, cfg.TTY, cfg.Init
	spec.Caps, spec.Seccomp, spec.ReadOnly, spec.Mounts = cfg.Caps, cfg.Seccomp, cfg.ReadOnly, cfg.Mounts
	return spec, nil
}

// Supervise starts the container and blocks until it exits, then records the result and
// cleans up. ready (optional) is called once with the start error (nil on success).
// It returns the container's exit code.
func (c *Container) Supervise(mode Mode, ready func(error)) (code int, err error) {
	notified := false
	notify := func(e error) {
		if ready != nil && !notified {
			notified = true
			ready(e)
		}
	}
	id := c.Config.ID
	fail := func(e error) (int, error) {
		notify(e)
		_ = c.UpdateState(func(s *State) {
			s.Status, s.ExitCode, s.Error, s.FinishedAt = "exited", 125, e.Error(), time.Now().UTC()
		})
		if c.Config.Rm {
			os.RemoveAll(Dir(id))
		}
		return 125, e
	}
	// Hold the liveness lock before any initialization: otherwise a startup
	// lasting over 30 seconds looks abandoned to Reconcile, which could mark
	// the container exited (and delete it with --rm) while we are starting it.
	// A lock conflict means another supervisor may own this container, so
	// report it without touching state or files.
	lock, err := state.HoldLock(id)
	if err != nil {
		e := fmt.Errorf("lock container: %w; is it already running?", err)
		notify(e)
		return 125, e
	}
	defer state.Release(id, lock)
	spec, err := c.initSpec()
	if err != nil {
		return fail(err)
	}
	var cg *cgroup.Cgroup
	if os.Geteuid() == 0 {
		if cg, err = cgroup.Create(id, c.Config.Limits); err != nil {
			return fail(err)
		}
		defer cg.Remove()
	} else if l := c.Config.Limits; l.MemoryBytes > 0 || l.CPUs > 0 || l.PidsLimit > 0 {
		return fail(errors.New("--memory/--cpus/--pids-limit need root (cgroup v2 delegation is not supported yet); run with sudo or drop the limit"))
	}

	var in, out, errf *os.File
	var master *os.File
	var logw io.WriteCloser
	var pumps []chan struct{}
	closeAfterStart := []*os.File{}
	switch {
	case c.Config.TTY:
		m, s, e := pty.Open()
		if e != nil {
			return fail(e)
		}
		master = m
		in, out, errf = s, s, s
		closeAfterStart = append(closeAfterStart, s)
	case mode == Shim:
		null, e := os.Open(os.DevNull)
		if e != nil {
			return fail(e)
		}
		in = null
		closeAfterStart = append(closeAfterStart, null)
	case c.Config.Interactive:
		in = os.Stdin
	default:
		null, e := os.Open(os.DevNull)
		if e != nil {
			return fail(e)
		}
		in = null
		closeAfterStart = append(closeAfterStart, null)
	}
	if mode == Shim {
		logw, err = newLogWriter(logPath(id))
		if err != nil {
			return fail(err)
		}
		defer logw.Close()
		if master == nil {
			pr, pw, e := os.Pipe()
			if e != nil {
				return fail(e)
			}
			out, errf = pw, pw
			closeAfterStart = append(closeAfterStart, pw)
			done := make(chan struct{})
			pumps = append(pumps, done)
			go func() { io.Copy(logw, pr); pr.Close(); close(done) }()
		} else {
			done := make(chan struct{})
			pumps = append(pumps, done)
			go func() { io.Copy(logw, master); close(done) }()
		}
	} else if master == nil {
		out, errf = os.Stdout, os.Stderr
	}

	mode0 := c.Config.Network
	if mode0 == "" {
		mode0 = network.None
	}
	cmd, send, err := runtime.Spawn(cg, mode0 == network.Host, in, out, errf)
	for _, f := range closeAfterStart {
		f.Close()
	}
	if err != nil {
		if master != nil {
			master.Close()
		}
		return fail(err)
	}
	// The init stage is blocked waiting for its spec: set up networking from outside first.
	t0 := time.Now()
	info, nerr := (&network.Manager{Root: state.Root()}).Setup(id, cmd.Process.Pid, mode0, c.Config.Ports)
	if nerr == nil {
		var binds [][2]string
		if binds, nerr = network.WriteFiles(Dir(id), c.Config.Hostname, info); nerr == nil {
			spec.Binds = binds
		}
	}
	if info != nil {
		b, e := json.Marshal(info)
		if e != nil {
			_ = cmd.Process.Kill()
			cmd.Wait()
			if master != nil {
				master.Close()
			}
			return fail(fmt.Errorf("encode network info: %w", e))
		}
		// The lease, veth and port rules already exist at this point: if the
		// record of them cannot be persisted, roll everything back now instead
		// of leaking it (cleanupNetwork would find no net.json later).
		if e := os.WriteFile(netPath(id), b, 0o644); e != nil {
			(&network.Manager{Root: state.Root()}).Cleanup(id, info)
			_ = cmd.Process.Kill()
			cmd.Wait()
			if master != nil {
				master.Close()
			}
			return fail(fmt.Errorf("record network setup: %w", e))
		}
	}
	defer cleanupNetwork(id)
	if nerr != nil {
		_ = cmd.Process.Kill()
		cmd.Wait()
		if master != nil {
			master.Close()
		}
		return fail(fmt.Errorf("network setup (%s): %w", mode0, nerr))
	}
	if os.Getenv("MINIBOX_TRACE") != "" {
		fmt.Fprintf(os.Stderr, "minibox: trace: network setup (%s) took %v\n", mode0, time.Since(t0))
	}
	send(spec)

	var restore func()
	if master != nil && mode == Foreground {
		if !pty.IsTerminal(0) {
			_ = cmd.Process.Kill()
			cmd.Wait()
			master.Close()
			return fail(errors.New("the input device is not a TTY; drop -t or run from a terminal"))
		}
		pty.CopySize(0, master)
		restore, _ = pty.MakeRaw(0)
		go io.Copy(master, os.Stdin)
		done := make(chan struct{})
		pumps = append(pumps, done)
		go func() { io.Copy(os.Stdout, master); close(done) }()
	}

	_ = c.UpdateState(func(s *State) {
		s.Status, s.Pid, s.StartedAt, s.Error = "running", cmd.Process.Pid, time.Now().UTC(), ""
	})
	notify(nil)

	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGWINCH)
	stopSigs := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sigs:
				if s == syscall.SIGWINCH {
					if master != nil && mode == Foreground {
						pty.CopySize(0, master)
					}
					continue
				}
				_ = cmd.Process.Signal(s)
			case <-stopSigs:
				return
			}
		}
	}()

	werr := cmd.Wait()
	signal.Stop(sigs)
	close(stopSigs)
	if restore != nil {
		restore()
	}
	code = 0
	var ee *exec.ExitError
	if errors.As(werr, &ee) {
		code = ee.ExitCode()
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			code = 128 + int(ws.Signal())
		}
	}
	// Anything left in the cgroup (daemonised children) dies with the container.
	if cg != nil {
		_ = os.WriteFile(cg.Path+"/cgroup.kill", []byte("1"), 0o644)
	}
	if master != nil {
		// Let the pump drain what is already buffered, then close.
		for _, d := range pumps {
			select {
			case <-d:
			case <-time.After(200 * time.Millisecond):
			}
		}
		master.Close()
	} else {
		for _, d := range pumps {
			<-d
		}
	}
	cleanupNetwork(id) // before a --rm removal deletes net.json
	oom := cg != nil && cg.MemoryEvents().OOMKill > 0
	if oom && mode == Foreground {
		fmt.Fprintf(os.Stderr, "minibox: container was OOM-killed (memory limit %d bytes); raise --memory\n", c.Config.Limits.MemoryBytes)
	}
	_ = c.UpdateState(func(s *State) {
		s.Status, s.Pid, s.ExitCode, s.OOMKilled, s.FinishedAt = "exited", 0, code, oom, time.Now().UTC()
	})
	if c.Config.Rm {
		os.RemoveAll(Dir(id))
	}
	return code, nil
}
