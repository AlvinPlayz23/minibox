//go:build linux

// Package cli implements the minibox subcommands.
package cli

import (
	"context"
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

	"minibox/internal/build"
	"minibox/internal/cgroup"
	"minibox/internal/compose"
	"minibox/internal/container"
	"minibox/internal/image"
	"minibox/internal/network"
	"minibox/internal/runtime"
	"minibox/internal/security"
	"minibox/internal/state"
	"minibox/internal/volume"
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
	var env, pubs, capAdd, capDrop, vols, tmpfs listFlag
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
	fs.Var(&pubs, "p", "publish a port HOST:CONTAINER[/udp] (repeatable)")
	netw := fs.String("network", "", "network mode: bridge (default as root), host, none, pasta")
	fs.Var(&capAdd, "cap-add", "add a Linux capability (repeatable), e.g. NET_ADMIN or ALL")
	fs.Var(&capDrop, "cap-drop", "drop a Linux capability (repeatable), e.g. NET_RAW or ALL")
	seccompF := fs.String("seccomp", "default", "seccomp profile: default or unconfined")
	readOnly := fs.Bool("read-only", false, "mount the container's root filesystem read-only")
	fs.Var(&vols, "v", "bind mount or named volume SRC:DST[:ro] (repeatable)")
	fs.Var(&vols, "volume", "same as -v")
	fs.Var(&tmpfs, "tmpfs", "tmpfs mount DST[:size=64m][,ro] (repeatable)")
	restart := fs.String("restart", "", "restart policy: no, always, on-failure[:N], unless-stopped")
	healthCmd := fs.String("health-cmd", "", "healthcheck command run by `minibox healthcheck NAME`")
	initF := fs.Bool("init", true, "run a tiny init as PID 1 (reaps zombies, forwards signals)")
	rootfs := fs.String("rootfs", "", "run a plain directory rootfs instead of an image (dev)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage: minibox run [flags] IMAGE [CMD...]
  -d/--detach  --rm  --name NAME  -i  -t  (-it)  -e KEY=VAL  -w DIR  -u USER
  -v SRC:DST[:ro]  --tmpfs DST[:size=64m][,ro]  -p HOST:CONT[/udp]  --network bridge|host|none|pasta
  --restart no|always|on-failure[:N]|unless-stopped  --health-cmd "CMD..."
  --cap-add CAP  --cap-drop CAP  --seccomp default|unconfined  --read-only
  --memory 64m  --cpus 0.5  --pids-limit N  --hostname NAME  --init=false  --rootfs DIR`)
	}
	fs.Parse(expandShort(args, "dit", "e", "p", "v", "volume", "tmpfs", "w", "u", "cap-add", "cap-drop", "seccomp", "restart", "health-cmd", "network", "memory", "cpus", "pids-limit", "hostname", "name", "rootfs"))
	if fs.NArg() < 1 && *rootfs == "" {
		fs.Usage()
		os.Exit(2)
	}
	cfg := container.Config{Name: *name, Interactive: *inter || *tty, TTY: *tty, Init: *initF, Rm: *rm,
		Detach: *detach, Workdir: *workdir, User: *user, Hostname: *host}
	rest := fs.Args()
	var unlock func()
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
		var err error
		unlock, err = st.RLock()
		if err != nil {
			die(125, "lock image store: %v", err)
		}
		img, err := st.GetImage(rest[0])
		if err != nil {
			if _, perr := image.ParseReference(rest[0]); perr != nil {
				die(125, "%v", perr)
			}
			fmt.Fprintf(os.Stderr, "Unable to find image %q locally\n", rest[0])
			if img, err = st.Pull(context.Background(), image.NewClient(), rest[0], os.Stderr); err != nil {
				die(125, "pull %s: %v", rest[0], err)
			}
		}
		cfg.Image, imgCfg, rest = img.Name, img.Config, rest[1:]
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
	var cerr error
	if cfg.Caps, cerr = security.ResolveCaps(capAdd, capDrop); cerr != nil {
		die(2, "%v", cerr)
	}
	if *seccompF != "default" && *seccompF != "unconfined" {
		die(2, "--seccomp must be default or unconfined")
	}
	cfg.Seccomp, cfg.ReadOnly = *seccompF == "default", *readOnly
	if cfg.Restart, cerr = normalizeRestart(*restart); cerr != nil {
		die(2, "%v", cerr)
	}
	if *healthCmd != "" {
		cfg.HealthCmd = build.SplitArgs(*healthCmd)
		if len(cfg.HealthCmd) == 0 {
			die(2, "--health-cmd is empty")
		}
	}
	for _, v := range vols {
		m, err := runtime.ParseVolume(v, func(name string) (string, error) {
			return volume.Ensure(state.Root(), name)
		})
		if err != nil {
			die(2, "%v", err)
		}
		cfg.Mounts = append(cfg.Mounts, m)
	}
	for _, t := range tmpfs {
		m, err := runtime.ParseTmpfs(t)
		if err != nil {
			die(2, "%v", err)
		}
		cfg.Mounts = append(cfg.Mounts, m)
	}
	cfg.Network = *netw
	if cfg.Network == "" {
		var why string
		if cfg.Network, why = network.DefaultMode(); why != "" {
			fmt.Fprintln(os.Stderr, "minibox:", why)
		}
	}
	if cfg.Network == network.Bridge && os.Geteuid() != 0 {
		var why string
		cfg.Network, why = network.DefaultMode()
		fmt.Fprintf(os.Stderr, "minibox: bridge networking needs root; falling back to %s (%s)\n", cfg.Network, why)
	}
	for _, p := range pubs {
		pm, err := network.ParsePort(p)
		if err != nil {
			die(2, "%v", err)
		}
		cfg.Ports = append(cfg.Ports, pm)
	}
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
	if unlock != nil {
		unlock()
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
	st := &image.Store{Root: state.Root()}
	res, err := st.GC(true)
	switch {
	case err != nil:
		die(1, "prune images: %v", err)
	case res == nil:
		fmt.Println("skipped image cleanup: a pull or run is in progress")
	default:
		fmt.Printf("removed %d unused layer(s), %d compressed blob(s), %d temp file(s)\n", res.Layers, res.Blobs, res.Temp)
	}
}

func peakRSS() string {
	b, _ := os.ReadFile("/proc/self/status")
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmHWM:") {
			return strings.TrimSpace(strings.TrimPrefix(l, "VmHWM:"))
		}
	}
	return "unknown"
}

// Pull implements `minibox pull [--stats] IMAGE`.
func Pull(args []string) {
	fs := flag.NewFlagSet("pull", flag.ExitOnError)
	stats := fs.Bool("stats", false, "print duration and peak RSS")
	q := fs.Bool("q", false, "quiet: no progress output")
	fs.Parse(args)
	if fs.NArg() != 1 {
		die(2, "usage: minibox pull [-q] [--stats] IMAGE")
	}
	var log io.Writer = os.Stderr
	if *q {
		log = io.Discard
	}
	t0 := time.Now()
	st := &image.Store{Root: state.Root()}
	img, err := st.Pull(context.Background(), image.NewClient(), fs.Arg(0), log)
	if err != nil {
		die(1, "pull %s: %v", fs.Arg(0), err)
	}
	fmt.Println(img.Name)
	if *stats {
		fmt.Fprintf(os.Stderr, "pulled in %v, peak RSS %s, %d layer(s), %d MB compressed\n", time.Since(t0).Round(time.Millisecond), peakRSS(), len(img.Layers), img.Size>>20)
	}
}

// Images implements `minibox images [--json]`.
func Images(args []string) {
	fs := flag.NewFlagSet("images", flag.ExitOnError)
	js := fs.Bool("json", false, "output JSON")
	fs.Parse(args)
	st := &image.Store{Root: state.Root()}
	imgs, err := st.ListImages()
	if err != nil {
		die(1, "%v", err)
	}
	if *js {
		if imgs == nil {
			imgs = []*image.Image{}
		}
		b, _ := json.MarshalIndent(imgs, "", "  ")
		fmt.Println(string(b))
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(w, "REPOSITORY\tTAG\tIMAGE ID\tCREATED\tSIZE")
	for _, img := range imgs {
		ref, _ := image.ParseReference(img.Name)
		repo, tag := ref.Registry+"/"+ref.Repo, ref.Tag
		if ref.Registry == "docker.io" {
			repo = strings.TrimPrefix(ref.Repo, "library/")
		}
		if ref.Digest != "" {
			tag = "<none>"
		}
		id := img.Digest
		if id == "" && len(img.Layers) > 0 {
			id = img.Layers[len(img.Layers)-1].DiffID
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%.1fMB\n", repo, tag, shortID(id), human(img.Created), float64(img.Size)/1e6)
	}
	w.Flush()
}

func shortID(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// normalizeRestart validates --restart no|always|on-failure[:N]|unless-stopped.
func normalizeRestart(s string) (string, error) {
	if s == "" || s == "no" {
		return "", nil
	}
	if s == "always" || s == "unless-stopped" || s == "on-failure" {
		return s, nil
	}
	if rest, ok := strings.CutPrefix(s, "on-failure:"); ok {
		n := 0
		for _, r := range rest {
			if r < '0' || r > '9' {
				return "", fmt.Errorf("invalid --restart %q; use no, always, on-failure[:N] or unless-stopped", s)
			}
			n = n*10 + int(r-'0')
		}
		if rest == "" || n <= 0 {
			return "", fmt.Errorf("invalid --restart %q; on-failure count must be a positive number", s)
		}
		return s, nil
	}
	return "", fmt.Errorf("invalid --restart %q; use no, always, on-failure[:N] or unless-stopped", s)
}

// Systemd implements `minibox systemd [-o DIR] CONTAINER`: writes a unit file that
// runs the container foreground with the same image/command/flags (no daemon needed).
// Systemd implements `minibox systemd [-o DIR] CONTAINER`: writes a unit file that
// runs the container foreground with the same image/command/flags (no daemon needed).
func Systemd(args []string) {
	fs := flag.NewFlagSet("systemd", flag.ExitOnError)
	out := fs.String("o", "", "output directory (default: print to stdout)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		die(2, "usage: minibox systemd [-o DIR] CONTAINER")
	}
	c, err := container.Resolve(fs.Arg(0))
	if err != nil {
		die(1, "%v", err)
	}
	bin, err := os.Executable()
	if err != nil {
		bin = "minibox"
	}
	cfg := c.Config
	var argv []string
	argv = append(argv, "run", "--rm", "--network", cfg.Network)
	if cfg.Name != "" {
		argv = append(argv, "--name", cfg.Name)
	}
	for _, e := range cfg.Env {
		argv = append(argv, "-e", e)
	}
	for _, p := range cfg.Ports {
		argv = append(argv, "-p", fmt.Sprintf("%d:%d/%s", p.HostPort, p.Container, p.Proto))
	}
	for _, m := range cfg.Mounts {
		switch m.Type {
		case "bind":
			s := m.Src + ":" + m.Dst
			if m.RO {
				s += ":ro"
			}
			argv = append(argv, "-v", s)
		case "tmpfs":
			s := m.Dst
			if m.Size != "" || m.RO {
				s += ":"
				if m.Size != "" {
					s += "size=" + m.Size
				}
				if m.RO {
					if m.Size != "" {
						s += ","
					}
					s += "ro"
				}
			}
			argv = append(argv, "--tmpfs", s)
		}
	}
	if cfg.Workdir != "" {
		argv = append(argv, "-w", cfg.Workdir)
	}
	if cfg.User != "" {
		argv = append(argv, "-u", cfg.User)
	}
	if cfg.Hostname != "" {
		argv = append(argv, "--hostname", cfg.Hostname)
	}
	if cfg.ReadOnly {
		argv = append(argv, "--read-only")
	}
	if !cfg.Seccomp {
		argv = append(argv, "--seccomp", "unconfined")
	}
	if len(cfg.Caps) > 0 {
		argv = append(argv, "--cap-drop", "ALL", "--cap-add", strings.Join(cfg.Caps, ","))
	}
	// Fix up the cap-add above: emit one flag per capability.
	var final []string
	for i := 0; i < len(argv); i++ {
		if argv[i] == "--cap-add" && i+1 < len(argv) {
			for _, cp := range strings.Split(argv[i+1], ",") {
				final = append(final, "--cap-add", cp)
			}
			i++
			continue
		}
		final = append(final, argv[i])
	}
	argv = final
	if cfg.Limits.MemoryBytes > 0 {
		argv = append(argv, "--memory", fmt.Sprintf("%d", cfg.Limits.MemoryBytes))
	}
	if cfg.Limits.CPUs > 0 {
		argv = append(argv, "--cpus", fmt.Sprintf("%g", cfg.Limits.CPUs))
	}
	if cfg.Limits.PidsLimit > 0 {
		argv = append(argv, "--pids-limit", fmt.Sprintf("%d", cfg.Limits.PidsLimit))
	}
	argv = append(argv, cfg.Image)
	argv = append(argv, cfg.Cmd...)
	quoted := make([]string, 0, len(argv)+1)
	quoted = append(quoted, shellQuote(bin))
	for _, a := range argv {
		quoted = append(quoted, shellQuote(a))
	}
	restart := "no"
	if cfg.Restart != "" {
		restart = cfg.Restart
	}
	sysRestart := "no"
	if restart == "always" || restart == "unless-stopped" || strings.HasPrefix(restart, "on-failure") {
		sysRestart = "always"
	}
	name := cfg.Name
	if name == "" {
		name = container.Short(cfg.ID)
	}
	unit := fmt.Sprintf(`[Unit]
Description=minibox container %s
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s
Restart=%s
RestartSec=2

[Install]
WantedBy=multi-user.target
`, name, strings.Join(quoted, " "), sysRestart)
	if *out == "" {
		fmt.Print(unit)
		return
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		die(1, "%v", err)
	}
	p := filepath.Join(*out, "minibox-"+name+".service")
	if err := os.WriteFile(p, []byte(unit), 0o644); err != nil {
		die(1, "%v", err)
	}
	fmt.Println(p)
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '_' || r == '-' || r == '.' || r == '/' || r == ':' || r == '=') {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// Healthcheck implements `minibox healthcheck CONTAINER`: runs the container's
// --health-cmd inside it and reports healthy/unhealthy via exit code.
func Healthcheck(args []string) {
	if len(args) != 1 {
		die(2, "usage: minibox healthcheck CONTAINER")
	}
	c, err := container.Resolve(args[0])
	if err != nil {
		die(1, "%v", err)
	}
	if len(c.Config.HealthCmd) == 0 {
		die(1, "container %s has no healthcheck configured (use `minibox run --health-cmd \"CMD...\"`)", container.Short(c.Config.ID))
	}
	code, err := container.Exec(c, container.ExecOptions{Cmd: c.Config.HealthCmd})
	if err != nil {
		fmt.Fprintf(os.Stderr, "minibox: %v\n", err)
	}
	if code == 0 {
		fmt.Println("healthy")
	} else {
		fmt.Printf("unhealthy (exit %d)\n", code)
	}
	os.Exit(code)
}

// Volume implements `minibox volume ls|create|rm|inspect|prune`.
func Volume(args []string) {
	if len(args) < 1 {
		die(2, "usage: minibox volume ls|create|rm|inspect|prune ...")
	}
	root := state.Root()
	switch args[0] {
	case "ls":
		fs := flag.NewFlagSet("volume ls", flag.ExitOnError)
		js := fs.Bool("json", false, "output JSON")
		fs.Parse(args[1:])
		infos := volume.List(root)
		if *js {
			if infos == nil {
				infos = []volume.Info{}
			}
			b, _ := json.MarshalIndent(infos, "", "  ")
			fmt.Println(string(b))
			return
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
		fmt.Fprintln(w, "VOLUME NAME\tMOUNTPOINT\tCREATED")
		for _, v := range infos {
			fmt.Fprintf(w, "%s\t%s\t%s\n", v.Name, v.Path, human(v.Created))
		}
		w.Flush()
	case "create":
		if len(args) != 2 {
			die(2, "usage: minibox volume create NAME")
		}
		p, err := volume.Ensure(root, args[1])
		if err != nil {
			die(1, "%v", err)
		}
		fmt.Println(args[1] + "\t" + p)
	case "rm":
		if len(args) < 2 {
			die(2, "usage: minibox volume rm NAME...")
		}
		inUse := volumesInUse(root)
		rc := 0
		for _, n := range args[1:] {
			if id, ok := inUse[n]; ok {
				fmt.Fprintf(os.Stderr, "minibox: volume %q is in use by container %s; remove the container first\n", n, id)
				rc = 1
				continue
			}
			if err := volume.Remove(root, n); err != nil {
				fmt.Fprintf(os.Stderr, "minibox: %v\n", err)
				rc = 1
				continue
			}
			fmt.Println(n)
		}
		os.Exit(rc)
	case "inspect":
		if len(args) != 2 {
			die(2, "usage: minibox volume inspect NAME")
		}
		infos := volume.List(root)
		for _, v := range infos {
			if v.Name == args[1] {
				b, _ := json.MarshalIndent(v, "", "  ")
				fmt.Println(string(b))
				return
			}
		}
		die(1, "no such volume %q; list volumes with `minibox volume ls`", args[1])
	case "prune":
		inUse := volumesInUse(root)
		n := 0
		for _, v := range volume.List(root) {
			if inUse[v.Name] != "" {
				continue
			}
			if err := volume.Remove(root, v.Name); err == nil {
				n++
			}
		}
		fmt.Printf("removed %d unused volume(s)\n", n)
	default:
		die(2, "usage: minibox volume ls|create|rm|inspect|prune ...")
	}
}

// volumesInUse maps volume name -> short container id for volumes referenced by any container.
func volumesInUse(root string) map[string]string {
	out := map[string]string{}
	vroot := volume.Dir(root)
	for _, c := range container.List() {
		for _, m := range c.Config.Mounts {
			if m.Type != "bind" || m.Src == "" {
				continue
			}
			rel, err := filepath.Rel(vroot, m.Src)
			if err != nil || strings.HasPrefix(rel, "..") {
				continue
			}
			name := strings.Split(rel, string(os.PathSeparator))[0]
			if name != "" && name != "." {
				if _, ok := out[name]; !ok {
					out[name] = container.Short(c.Config.ID)
				}
			}
		}
	}
	return out
}

// Rmi implements `minibox rmi IMAGE...`.
func Rmi(args []string) {
	if len(args) < 1 {
		die(2, "usage: minibox rmi IMAGE...")
	}
	st := &image.Store{Root: state.Root()}
	inUse := map[string]string{}
	for _, c := range container.List() {
		inUse[c.Config.Image] = container.Short(c.Config.ID)
	}
	rc := 0
	for _, a := range args {
		ref, err := image.ParseReference(a)
		if err == nil {
			if id, ok := inUse[ref.Name()]; ok {
				fmt.Fprintf(os.Stderr, "minibox: image %s is used by container %s; remove it first (`minibox rm %s`)\n", a, id, id)
				rc = 1
				continue
			}
		}
		name, err := st.RemoveImage(a)
		if err != nil {
			fmt.Fprintf(os.Stderr, "minibox: %v\n", err)
			rc = 1
			continue
		}
		fmt.Println("Untagged:", name)
	}
	if res, err := st.GC(false); err == nil && res != nil && res.Layers > 0 {
		fmt.Printf("Removed %d unused layer(s)\n", res.Layers)
	}
	os.Exit(rc)
}

// Build implements `minibox build [-t NAME] [-f Dockerfile] [--build-arg K=V] PATH`.
func Build(args []string) {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	tag := fs.String("t", "", "name for the built image (e.g. myapp:1.0)")
	fs.StringVar(tag, "tag", "", "")
	dockerfile := fs.String("f", "", "Dockerfile to build from (default PATH/Dockerfile)")
	fs.StringVar(dockerfile, "file", "", "")
	var buildArgs listFlag
	fs.Var(&buildArgs, "build-arg", "build-time variable K=V (repeatable, for ARG)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: minibox build -t NAME [-f Dockerfile] [--build-arg K=V] PATH")
	}
	fs.Parse(args)
	if *tag == "" {
		die(2, "no target name: use `minibox build -t NAME PATH`")
	}
	ctxDir := "."
	if fs.NArg() > 1 {
		die(2, "usage: minibox build -t NAME [-f Dockerfile] [--build-arg K=V] PATH")
	}
	if fs.NArg() == 1 {
		ctxDir = fs.Arg(0)
	}
	abs, err := filepath.Abs(ctxDir)
	if err != nil {
		die(125, "%v", err)
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		die(125, "build context %q is not a directory", ctxDir)
	}
	argMap := map[string]string{}
	for _, a := range buildArgs {
		k, v, ok := strings.Cut(a, "=")
		if !ok || k == "" {
			die(2, "bad --build-arg %q; use K=V", a)
		}
		argMap[k] = v
	}
	df := *dockerfile
	if df == "" {
		df = filepath.Join(abs, "Dockerfile")
	}
	img, err := build.Build(context.Background(), build.Options{
		ContextDir: abs, Dockerfile: df, Tag: *tag, BuildArgs: argMap, Log: os.Stderr,
	})
	if err != nil {
		die(1, "build: %v", err)
	}
	fmt.Println(img.Name)
}

// defaultComposeFile finds the compose file: -f flag or minibox.yml/minibox.yaml/compose.yml.
func defaultComposeFile(flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	for _, n := range []string{"minibox.yml", "minibox.yaml", "compose.yml", "compose.yaml"} {
		if _, err := os.Stat(n); err == nil {
			return n, nil
		}
	}
	return "", fmt.Errorf("no compose file found; pass -f FILE or create minibox.yml")
}

// Up implements `minibox up [-f FILE] [-p PROJECT] [-d]`.
func Up(args []string) {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	file := fs.String("f", "", "compose file (default minibox.yml)")
	project := fs.String("p", "", "project name (default: compose file's directory name)")
	detach := fs.Bool("d", true, "run in background (foreground is not supported; always detached)")
	fs.Parse(args)
	_ = detach
	f, err := defaultComposeFile(*file)
	if err != nil {
		die(1, "%v", err)
	}
	data, err := os.ReadFile(f)
	if err != nil {
		die(1, "read %s: %v", f, err)
	}
	proj, err := compose.Parse(data)
	if err != nil {
		die(2, "%s: %v", f, err)
	}
	projName := *project
	if projName == "" {
		abs, _ := filepath.Abs(filepath.Dir(f))
		projName = filepath.Base(abs)
	}
	for _, svc := range proj.Services {
		if err := upOne(svc, projName); err != nil {
			die(1, "%s: %v", svc.Name, err)
		}
	}
}

func upOne(svc compose.Service, projName string) error {
	name := projName + "_" + svc.Name
	st := &image.Store{Root: state.Root()}
	unlock, err := st.RLock()
	if err != nil {
		return fmt.Errorf("lock image store: %w", err)
	}
	img, err := st.GetImage(svc.Image)
	if err != nil {
		if _, perr := image.ParseReference(svc.Image); perr != nil {
			unlock()
			return perr
		}
		fmt.Fprintf(os.Stderr, "Unable to find image %q locally\n", svc.Image)
		if img, err = st.Pull(context.Background(), image.NewClient(), svc.Image, os.Stderr); err != nil {
			unlock()
			return err
		}
	}
	unlock()
	cfg := container.Config{Name: name, Init: true, Detach: true}
	cfg.Image = img.Name
	cmd := svc.Command
	if len(cmd) == 0 {
		cmd = img.Config.Cmd
	}
	cfg.Cmd = append(append([]string(nil), img.Config.Entrypoint...), cmd...)
	if len(cfg.Cmd) == 0 {
		return fmt.Errorf("service %q: image %s has no default command; set `command:`", svc.Name, svc.Image)
	}
	env := append(append([]string(nil), img.Config.Env...), svc.Environment...)
	// Bare KEY entries pass through the host environment.
	for i, e := range env {
		if !strings.Contains(e, "=") {
			v, ok := os.LookupEnv(e)
			if !ok {
				return fmt.Errorf("service %q: environment variable %q is not set on the host; use KEY=VALUE", svc.Name, e)
			}
			env[i] = e + "=" + v
		}
	}
	cfg.Env = runtime.MergeEnv(env)
	cfg.Env = dedupEnv(cfg.Env)
	cfg.Workdir = svc.Workdir
	if cfg.Workdir == "" {
		cfg.Workdir = img.Config.WorkingDir
	}
	cfg.User = svc.User
	if cfg.User == "" {
		cfg.User = img.Config.User
	}
	cfg.Network = svc.Network
	if cfg.Network == "" {
		var why string
		if cfg.Network, why = network.DefaultMode(); why != "" {
			fmt.Fprintln(os.Stderr, "minibox:", why)
		}
	}
	switch cfg.Network {
	case network.Bridge, network.Host, network.None, network.Pasta:
	default:
		return fmt.Errorf("service %q: unknown network mode %q; use bridge, host, none or pasta", svc.Name, svc.Network)
	}
	if cfg.Restart, err = normalizeRestart(svc.Restart); err != nil {
		return fmt.Errorf("service %q: %w", svc.Name, err)
	}
	for _, p := range svc.Ports {
		pm, err := network.ParsePort(p)
		if err != nil {
			return fmt.Errorf("service %q: %w", svc.Name, err)
		}
		cfg.Ports = append(cfg.Ports, pm)
	}
	for _, v := range svc.Volumes {
		m, err := runtime.ParseVolume(v, func(vname string) (string, error) {
			return volume.Ensure(state.Root(), vname)
		})
		if err != nil {
			return fmt.Errorf("service %q: %w", svc.Name, err)
		}
		cfg.Mounts = append(cfg.Mounts, m)
	}
	if cfg.Caps, err = security.ResolveCaps(nil, nil); err != nil {
		return err
	}
	cfg.Seccomp = true
	id, err := image.NewID()
	if err != nil {
		return err
	}
	cfg.ID = id
	if cfg.Hostname == "" {
		cfg.Hostname = svc.Hostname
		if cfg.Hostname == "" {
			cfg.Hostname = id[:12]
		}
	}
	c, err := container.Create(cfg)
	if err != nil {
		return err
	}
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd2 := exec.Command("/proc/self/exe", "shim", c.Config.ID)
	cmd2.ExtraFiles = []*os.File{w}
	cmd2.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd2.Start(); err != nil {
		return fmt.Errorf("start shim: %w", err)
	}
	w.Close()
	msg, _ := io.ReadAll(r)
	if len(msg) > 0 {
		return fmt.Errorf("%s", msg)
	}
	go cmd2.Wait()
	fmt.Printf("%s  %s\n", name, c.Config.ID[:12])
	return nil
}

// Down implements `minibox down [-f FILE] [-p PROJECT]`.
func Down(args []string) {
	fs := flag.NewFlagSet("down", flag.ExitOnError)
	file := fs.String("f", "", "compose file (default minibox.yml)")
	project := fs.String("p", "", "project name (default: compose file's directory name)")
	fs.Parse(args)
	f, err := defaultComposeFile(*file)
	if err != nil {
		die(1, "%v", err)
	}
	data, err := os.ReadFile(f)
	if err != nil {
		die(1, "read %s: %v", f, err)
	}
	proj, err := compose.Parse(data)
	if err != nil {
		die(2, "%s: %v", f, err)
	}
	projName := *project
	if projName == "" {
		abs, _ := filepath.Abs(filepath.Dir(f))
		projName = filepath.Base(abs)
	}
	rc := 0
	for _, svc := range proj.Services {
		name := projName + "_" + svc.Name
		c, err := container.Resolve(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "minibox: %s: %v\n", name, err)
			rc = 1
			continue
		}
		if err := container.Stop(c, 10*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "minibox: %s: %v\n", name, err)
			rc = 1
			continue
		}
		if err := container.Remove(c, false); err != nil {
			fmt.Fprintf(os.Stderr, "minibox: %s: %v\n", name, err)
			rc = 1
			continue
		}
		fmt.Println(name)
	}
	os.Exit(rc)
}
