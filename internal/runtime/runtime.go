//go:build linux

// Package runtime implements the re-exec pattern: the parent launches
// /proc/self/exe with new namespaces; the child ("init") sets up the
// rootfs and execs the user command.
package runtime

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"minibox/internal/cgroup"
	"minibox/internal/image"
	"minibox/internal/state"
	"minibox/internal/storage"
)

// RunOptions configures RunRaw.
type RunOptions struct {
	Rootfs string // plain directory rootfs (mutually exclusive with Image)
	Image  string // image name in the store
	Cmd    []string
	Limits cgroup.Limits
	Keep   bool // keep the container dir (upper layer) after exit, for inspection
}

// InitSpec is passed from the supervisor to the init stage as JSON on fd 3.
type InitSpec struct {
	Rootfs   string
	Overlay  *storage.Overlay
	Cmd      []string
	Env      []string
	Workdir  string
	Hostname string
	User     string      // "uid[:gid]" or a name from the container's /etc/passwd
	TTY      bool        // fd 0 is a pty slave to become the controlling terminal
	Binds    [][2]string // [host src, container dst] file bind mounts (resolv.conf, hosts)
	Init     bool        // stay as PID 1: reap zombies, forward signals, then exit with the child's status
}

// RunRaw runs a command in new PID/mount/UTS/IPC/net namespaces on a pivot_rooted
// rootfs: either a plain directory or an overlay of an image's layers.
// Returns the child's exit code.
func RunRaw(o RunOptions) (int, error) {
	lim, cmd := o.Limits, o.Cmd
	spec := InitSpec{Cmd: cmd, Env: []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "TERM=" + os.Getenv("TERM")}}
	id, err := newID()
	if err != nil {
		return 125, err
	}
	var cdirs *storage.ContainerDirs
	if o.Image != "" {
		st := &image.Store{Root: state.Root()}
		img, err := st.GetImage(o.Image)
		if err != nil {
			return 125, err
		}
		lowers, err := st.LowerDirs(img)
		if err != nil {
			return 125, err
		}
		cdirs, err = storage.NewContainerDirs(st.Root, id)
		if err != nil {
			return 125, err
		}
		if !o.Keep {
			defer cdirs.Remove()
		}
		ov := &storage.Overlay{Upper: cdirs.Upper, Work: cdirs.Work, Target: cdirs.Merged}
		for _, l := range lowers {
			ov.Lowers = append(ov.Lowers, storage.Lower{Dir: l.Dir, Short: l.Short})
		}
		spec.Overlay, spec.Rootfs = ov, cdirs.Merged
		spec.Env = mergeEnv(img.Config.Env)
		spec.Workdir = img.Config.WorkingDir
		if len(cmd) == 0 {
			cmd = img.Config.Cmd
		}
		spec.Cmd = append(append([]string(nil), img.Config.Entrypoint...), cmd...)
		if len(spec.Cmd) == 0 {
			return 125, fmt.Errorf("image %s has no default command; pass one: minibox run-raw --image %s CMD...", o.Image, o.Image)
		}
	} else {
		st, err := os.Stat(o.Rootfs)
		if err != nil || !st.IsDir() {
			return 125, fmt.Errorf("rootfs %q is not a directory; extract an Alpine minirootfs there first (see bench/fetch-rootfs.sh)", o.Rootfs)
		}
		if spec.Rootfs, err = absPath(o.Rootfs); err != nil {
			return 125, err
		}
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
	specR, specW, err := os.Pipe()
	if err != nil {
		return 125, err
	}
	defer specR.Close()
	sb, _ := json.Marshal(spec)
	c := exec.Command("/proc/self/exe", "init")
	c.ExtraFiles = []*os.File{specR} // becomes fd 3 in the child
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWIPC | syscall.CLONE_NEWNET,
		Pdeathsig:   syscall.SIGKILL,
		UseCgroupFD: true,
		CgroupFD:    fd,
	}
	if err := c.Start(); err != nil {
		specW.Close()
		return 125, fmt.Errorf("start container (need root or CAP_SYS_ADMIN): %w", err)
	}
	// Written concurrently: the spec can exceed the 64 KiB pipe buffer (many layers).
	go func() {
		specW.Write(sb)
		specW.Close()
	}()
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

// mergeEnv returns the container env: image env with defaults for PATH/HOME/TERM.
func mergeEnv(img []string) []string {
	env := append([]string(nil), img...)
	has := func(k string) bool {
		for _, e := range env {
			if len(e) > len(k) && e[:len(k)+1] == k+"=" {
				return true
			}
		}
		return false
	}
	if !has("PATH") {
		env = append(env, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	}
	if !has("HOME") {
		env = append(env, "HOME=/root")
	}
	if t := os.Getenv("TERM"); t != "" && !has("TERM") {
		env = append(env, "TERM="+t)
	}
	return env
}

// Init runs inside the new namespaces as PID 1; the spec arrives on fd 3.
func Init() error {
	f := os.NewFile(3, "spec")
	var spec InitSpec
	if err := json.NewDecoder(f).Decode(&spec); err != nil {
		return fmt.Errorf("init: read spec: %w", err)
	}
	f.Close()
	if len(spec.Cmd) == 0 {
		return errors.New("init: no command")
	}
	// Make mounts private so nothing propagates to the host.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make / private: %w", err)
	}
	if spec.Hostname == "" {
		spec.Hostname = "minibox"
	}
	if err := unix.Sethostname([]byte(spec.Hostname)); err != nil {
		return fmt.Errorf("sethostname: %w", err)
	}
	if spec.Overlay != nil {
		if err := spec.Overlay.Mount(); err != nil {
			return err
		}
	}
	for _, b := range spec.Binds {
		if err := bindFile(spec.Rootfs, b[0], b[1]); err != nil {
			return err
		}
	}
	if err := setupRootfs(spec.Rootfs); err != nil {
		return err
	}
	if spec.Workdir != "" {
		if err := unix.Chdir(spec.Workdir); err != nil {
			return fmt.Errorf("chdir %s: %w (WorkingDir from image config)", spec.Workdir, err)
		}
	}
	path, err := lookPath(spec.Cmd[0], spec.Env)
	if err != nil {
		return err
	}
	return execFinal(&spec, path)
}

func lookPath(name string, env []string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	path := "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, "PATH="); ok {
			path = v
		}
	}
	for _, d := range strings.Split(path, ":") {
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

// bindFile bind-mounts the host file src over rootfs+dst, creating dst if needed (a dangling
// or absolute symlink such as /etc/resolv.conf -> /run/... is replaced in the writable layer).
func bindFile(rootfs, src, dst string) error {
	target := rootfs + dst
	if fi, err := os.Lstat(target); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(target); err != nil {
			return fmt.Errorf("replace symlink %s: %w", dst, err)
		}
	}
	if _, err := os.Lstat(target); err != nil {
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("create %s in container: %w", dst, err)
		}
		f.Close()
	}
	if err := unix.Mount(src, target, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind %s onto %s: %w", src, dst, err)
	}
	return nil
}
