//go:build linux

// Package cli implements the minibox subcommands.
package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"minibox/internal/cgroup"
	"minibox/internal/container"
	"minibox/internal/image"
	"minibox/internal/runtime"
	"minibox/internal/state"
)

func die(code int, format string, a ...any) {
	fmt.Fprintf(os.Stderr, "minibox: "+format+"\n", a...)
	os.Exit(code)
}

// listFlag collects repeated -e flags.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// expandShort rewrites combined bool short flags like -it into -i -t, stopping at the first
// positional argument. valued lists flags that consume the next argument.
func expandShort(args []string, letters string, valued ...string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" || !strings.HasPrefix(a, "-") || a == "-" {
			return append(out, args[i:]...)
		}
		name := strings.TrimLeft(a, "-")
		if !strings.Contains(a, "=") {
			for _, v := range valued {
				if name == v && i+1 < len(args) {
					out = append(out, a, args[i+1])
					i++
					goto next
				}
			}
		}
		if !strings.HasPrefix(a, "--") && len(a) > 2 && !strings.Contains(a, "=") {
			all := true
			for _, r := range a[1:] {
				if !strings.ContainsRune(letters, r) {
					all = false
				}
			}
			if all {
				for _, r := range a[1:] {
					out = append(out, "-"+string(r))
				}
				continue
			}
		}
		out = append(out, a)
	next:
	}
	return out
}

func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 125
}

// Run implements `minibox run [flags] IMAGE [CMD...]`.
func Run(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var env listFlag
	detach := fs.Bool("d", false, "run in the background and print the container id")
	fs.BoolVar(detach, "detach", false, "")
	rm := fs.Bool("rm", false, "remove the container when it exits")
	name := fs.String("name", "", "container name")
	inter := fs.Bool("i", false, "keep stdin open")
	tty := fs.Bool("t", false, "allocate a pseudo-terminal")
	fs.Var(&env, "e", "set environment variable KEY=VAL (repeatable)")
	workdir := fs.String("w", "", "working directory inside the container")
	user := fs.String("u", "", "user (uid[:gid] or name[:group])")
	mem := fs.String("memory", "", "memory limit, e.g. 64m")
	cpus := fs.Float64("cpus", 0, "CPU limit, e.g. 0.5")
	pids := fs.Int64("pids-limit", 0, "max number of processes")
	host := fs.String("hostname", "", "container hostname (default: short container id)")
	initF := fs.Bool("init", true, "run a tiny init as PID 1 (reaps zombies, forwards signals)")
	rootfs := fs.String("rootfs", "", "run a plain directory rootfs instead of an image (dev)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage: minibox run [flags] IMAGE [CMD...]
  -d/--detach  --rm  --name NAME  -i  -t  (-it)  -e KEY=VAL  -w DIR  -u USER
  --memory 64m  --cpus 0.5  --pids-limit N  --hostname NAME  --init=false  --rootfs DIR`)
	}
	fs.Parse(expandShort(args, "dit", "e", "w", "u", "memory", "cpus", "pids-limit", "hostname", "name", "rootfs"))
	if fs.NArg() < 1 && *rootfs == "" {
		fs.Usage()
		os.Exit(2)
	}
	cfg := container.Config{Name: *name, Interactive: *inter || *tty, TTY: *tty, Init: *initF, Rm: *rm,
		Detach: *detach, Workdir: *workdir, User: *user, Hostname: *host}
	rest := fs.Args()
	var imgCfg image.Config
	if *rootfs != "" {
		abs, err := filepath.Abs(*rootfs)
		if err != nil {
			die(125, "%v", err)
		}
		if st, err := os.Stat(abs); err != nil || !st.IsDir() {
			die(125, "--rootfs %q is not a directory", *rootfs)
		}
		cfg.Rootfs = abs
		imgCfg.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	} else {
		st := &image.Store{Root: state.Root()}
		img, err := st.GetImage(rest[0])
		if err != nil {
			die(125, "%v", err)
		}
		cfg.Image, imgCfg, rest = rest[0], img.Config, rest[1:]
		if *workdir == "" {
			cfg.Workdir = img.Config.WorkingDir
		}
		if *user == "" {
			cfg.User = img.Config.User
		}
	}
	if len(rest) == 0 {
		rest = imgCfg.Cmd
	}
	cfg.Cmd = append(append([]string(nil), imgCfg.Entrypoint...), rest...)
	if len(cfg.Cmd) == 0 {
		die(125, "no command: the image has no default command; pass one: minibox run IMAGE CMD...")
	}
	cfg.Env = runtime.MergeEnv(append(append([]string(nil), imgCfg.Env...), env...))
	cfg.Env = dedupEnv(cfg.Env)
	if *mem != "" {
		b, err := cgroup.ParseSize(*mem)
		if err != nil {
			die(2, "--memory: %v", err)
		}
		cfg.Limits.MemoryBytes = b
	}
	cfg.Limits.CPUs, cfg.Limits.PidsLimit = *cpus, *pids
	id, err := image.NewID()
	if err != nil {
		die(125, "%v", err)
	}
	cfg.ID = id
	if cfg.Hostname == "" {
		cfg.Hostname = id[:12]
	}
	c, err := container.Create(cfg)
	if err != nil {
		die(125, "%v", err)
	}
	if *detach {
		runDetached(c)
		return
	}
	code, err := c.Supervise(container.Foreground, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "minibox: %v\n", err)
	}
	os.Exit(code)
}

// dedupEnv keeps the last value of each key, preserving first-seen order.
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

func runDetached(c *container.Container) {
	r, w, err := os.Pipe()
	if err != nil {
		die(125, "%v", err)
	}
	cmd := exec.Command("/proc/self/exe", "shim", c.Config.ID)
	cmd.ExtraFiles = []*os.File{w}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		die(125, "start shim: %v", err)
	}
	w.Close()
	msg, _ := io.ReadAll(r)
	if len(msg) > 0 {
		die(125, "%s", msg)
	}
	go cmd.Wait()
	fmt.Println(c.Config.ID)
}

// Shim is the hidden detached supervisor (`minibox shim ID`); fd 3 reports readiness.
func Shim(args []string) {
	ready := os.NewFile(3, "ready")
	if len(args) != 1 {
		os.Exit(2)
	}
	c, err := container.Load(args[0])
	if err != nil {
		fmt.Fprintf(ready, "load container: %v", err)
		os.Exit(125)
	}
	// Tiny heap: the shim just shuffles bytes.
	code, _ := c.Supervise(container.Shim, func(e error) {
		if e != nil {
			fmt.Fprint(ready, e.Error())
		}
		ready.Close()
	})
	os.Exit(code)
}

// ExecInit is the hidden `exec-init` helper.
func ExecInit() {
	code, err := runtime.ExecInit()
	if err != nil {
		fmt.Fprintf(os.Stderr, "minibox exec: %v\n", err)
	}
	os.Exit(code)
}

func human(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d seconds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

func statusText(c *container.Container) string {
	switch s := c.DisplayStatus(); s {
	case "running":
		return "Up " + strings.TrimSuffix(human(c.State.StartedAt), " ago")
	case "exited":
		t := fmt.Sprintf("Exited (%d) %s", c.State.ExitCode, human(c.State.FinishedAt))
		if c.State.OOMKilled {
			t += " [OOM-killed]"
		}
		return t
	case "dead":
		return "Dead (supervisor gone; run `minibox system prune`)"
	default:
		return strings.ToUpper(s[:1]) + s[1:]
	}
}

// Ps implements `minibox ps [-a] [--json]`.
func Ps(args []string) {
	fs := flag.NewFlagSet("ps", flag.ExitOnError)
	all := fs.Bool("a", false, "show all containers (default: running only)")
	js := fs.Bool("json", false, "output JSON")
	fs.Parse(args)
	type row struct {
		ID      string    `json:"id"`
		Name    string    `json:"name"`
		Image   string    `json:"image"`
		Command string    `json:"command"`
		Created time.Time `json:"created"`
		Status  string    `json:"status"`
		Detail  string    `json:"statusText"`
		Pid     int       `json:"pid,omitempty"`
	}
	rows := []row{}
	for _, c := range container.List() {
		if !*all && c.DisplayStatus() != "running" {
			continue
		}
		img := c.Config.Image
		if img == "" {
			img = c.Config.Rootfs
		}
		rows = append(rows, row{c.Config.ID, c.Config.Name, img, strings.Join(c.Config.Cmd, " "), c.Config.Created,
			c.DisplayStatus(), statusText(c), c.State.Pid})
	}
	if *js {
		b, _ := json.MarshalIndent(rows, "", "  ")
		fmt.Println(string(b))
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(w, "CONTAINER ID\tIMAGE\tCOMMAND\tCREATED\tSTATUS\tNAMES")
	for _, r := range rows {
		cmd := r.Command
		if len(cmd) > 24 {
			cmd = cmd[:23] + "…"
		}
		fmt.Fprintf(w, "%s\t%s\t\"%s\"\t%s\t%s\t%s\n", container.Short(r.ID), r.Image, cmd, human(r.Created), r.Detail, r.Name)
	}
	w.Flush()
}

func resolveAll(refs []string) []*container.Container {
	var out []*container.Container
	failed := false
	for _, r := range refs {
		c, err := container.Resolve(r)
		if err != nil {
			fmt.Fprintf(os.Stderr, "minibox: %v\n", err)
			failed = true
			continue
		}
		out = append(out, c)
	}
	if failed {
		defer os.Exit(1)
	}
	return out
}

// Stop implements `minibox stop [-t SECS] CONTAINER...`.
func Stop(args []string) {
	fs := flag.NewFlagSet("stop", flag.ExitOnError)
	t := fs.Int("t", 10, "seconds to wait after SIGTERM before SIGKILL")
	fs.Parse(args)
	if fs.NArg() < 1 {
		die(2, "usage: minibox stop [-t SECS] CONTAINER...")
	}
	rc := 0
	for _, c := range resolveAll(fs.Args()) {
		if err := container.Stop(c, time.Duration(*t)*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "minibox: %v\n", err)
			rc = 1
			continue
		}
		fmt.Println(container.Short(c.Config.ID))
	}
	os.Exit(rc)
}

// Rm implements `minibox rm [-f] CONTAINER...`.
func Rm(args []string) {
	fs := flag.NewFlagSet("rm", flag.ExitOnError)
	f := fs.Bool("f", false, "force-remove a running container")
	fs.Parse(args)
	if fs.NArg() < 1 {
		die(2, "usage: minibox rm [-f] CONTAINER...")
	}
	rc := 0
	for _, c := range resolveAll(fs.Args()) {
		if err := container.Remove(c, *f); err != nil {
			fmt.Fprintf(os.Stderr, "minibox: %v\n", err)
			rc = 1
			continue
		}
		fmt.Println(container.Short(c.Config.ID))
	}
	os.Exit(rc)
}

// Logs implements `minibox logs [-f] CONTAINER`.
func Logs(args []string) {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	f := fs.Bool("f", false, "follow log output")
	fs.Parse(args)
	if fs.NArg() != 1 {
		die(2, "usage: minibox logs [-f] CONTAINER")
	}
	c, err := container.Resolve(fs.Arg(0))
	if err != nil {
		die(1, "%v", err)
	}
	if err := container.Logs(c, os.Stdout, *f); err != nil {
		die(1, "%v", err)
	}
}

// Exec implements `minibox exec [-it] [-e K=V] [-w DIR] [-u USER] CONTAINER CMD...`.
func Exec(args []string) {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	var env listFlag
	i := fs.Bool("i", false, "keep stdin open")
	t := fs.Bool("t", false, "allocate a pseudo-terminal")
	fs.Var(&env, "e", "set environment variable")
	w := fs.String("w", "", "working directory")
	u := fs.String("u", "", "user")
	fs.Parse(expandShort(args, "it", "e", "w", "u"))
	if fs.NArg() < 2 {
		die(2, "usage: minibox exec [-it] [-e K=V] [-w DIR] [-u USER] CONTAINER CMD...")
	}
	c, err := container.Resolve(fs.Arg(0))
	if err != nil {
		die(1, "%v", err)
	}
	code, err := container.Exec(c, container.ExecOptions{Cmd: fs.Args()[1:], Env: env, Workdir: *w, User: *u, TTY: *t, Interactive: *i || *t})
	if err != nil {
		fmt.Fprintf(os.Stderr, "minibox: %v\n", err)
	}
	os.Exit(code)
}

// Inspect implements `minibox inspect CONTAINER|IMAGE`.
func Inspect(args []string) {
	if len(args) != 1 {
		die(2, "usage: minibox inspect CONTAINER|IMAGE")
	}
	if c, err := container.Resolve(args[0]); err == nil {
		out := struct {
			Config container.Config `json:"config"`
			State  container.State  `json:"state"`
			Status string           `json:"status"`
		}{c.Config, c.State, c.DisplayStatus()}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return
	}
	st := &image.Store{Root: state.Root()}
	img, err := st.GetImage(args[0])
	if err != nil {
		die(1, "no such container or image %q; see `minibox ps -a` and `minibox images`", args[0])
	}
	b, _ := json.MarshalIndent(img, "", "  ")
	fmt.Println(string(b))
}

// Prune implements `minibox system prune`.
func Prune() {
	n, err := container.Prune()
	if err != nil {
		die(1, "prune: %v", err)
	}
	fmt.Printf("removed %d stale container resource(s) (cgroups, container dirs)\n", n)
}
