//go:build linux

// Package container implements container records, lifecycle and supervision.
package container

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"minibox/internal/cgroup"
	"minibox/internal/network"
	"minibox/internal/runtime"
	"minibox/internal/state"
)

// Config is the resolved, immutable runtime configuration (config.json).
type Config struct {
	ID          string          `json:"id"`
	Name        string          `json:"name,omitempty"`
	Image       string          `json:"image,omitempty"`
	Rootfs      string          `json:"rootfs,omitempty"` // plain-directory rootfs (dev; no image)
	Cmd         []string        `json:"cmd"`
	Env         []string        `json:"env"`
	Workdir     string          `json:"workdir,omitempty"`
	Hostname    string          `json:"hostname"`
	User        string          `json:"user,omitempty"`
	TTY         bool            `json:"tty,omitempty"`
	Interactive bool            `json:"interactive,omitempty"`
	Init        bool            `json:"init"`
	Rm          bool            `json:"rm,omitempty"`
	Detach      bool            `json:"detach,omitempty"`
	Mounts      []runtime.Mount `json:"mounts,omitempty"`
	Restart     string          `json:"restart,omitempty"`
	HealthCmd   []string        `json:"healthCmd,omitempty"`
	Caps        []string        `json:"caps"`
	Seccomp     bool            `json:"seccomp"`
	ReadOnly    bool            `json:"readOnly,omitempty"`
	Network     string          `json:"network"` // bridge, host, none, pasta
	Ports       []network.Port  `json:"ports,omitempty"`
	Limits      cgroup.Limits   `json:"limits"`
	Created     time.Time       `json:"created"`
}

// State is the mutable container state (state.json).
type State struct {
	Status     string    `json:"status"` // created, running, exited
	Pid        int       `json:"pid,omitempty"`
	ExitCode   int       `json:"exitCode"`
	OOMKilled  bool      `json:"oomKilled,omitempty"`
	Error      string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"startedAt,omitempty"`
	FinishedAt time.Time `json:"finishedAt,omitempty"`
}

// Container is a loaded container record.
type Container struct {
	Config Config
	State  State
}

func containersDir() string      { return filepath.Join(state.Root(), "containers") }
func Dir(id string) string       { return filepath.Join(containersDir(), id) }
func logPath(id string) string   { return filepath.Join(Dir(id), "log") }
func statePath(id string) string { return filepath.Join(Dir(id), "state.json") }

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// globalLock serialises create/name checks across CLI invocations.
func globalLock() (*os.File, error) {
	if err := os.MkdirAll(containersDir(), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(containersDir(), ".lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func unlock(f *os.File) { f.Close() }

// Create allocates the container directory, enforcing name uniqueness, and writes config and state.
func Create(cfg Config) (*Container, error) {
	l, err := globalLock()
	if err != nil {
		return nil, fmt.Errorf("lock %s: %w; check that MINIBOX_ROOT is writable", containersDir(), err)
	}
	defer unlock(l)
	if cfg.Name != "" {
		if !validName(cfg.Name) {
			return nil, fmt.Errorf("invalid container name %q; use letters, digits, '_', '.', '-' (and no leading '-')", cfg.Name)
		}
		for _, c := range List() {
			if c.Config.Name == cfg.Name {
				return nil, fmt.Errorf("container name %q is already used by %s; choose another --name or run `minibox rm %s`", cfg.Name, short(c.Config.ID), cfg.Name)
			}
		}
	}
	if err := os.MkdirAll(Dir(cfg.ID), 0o755); err != nil {
		return nil, err
	}
	cfg.Created = time.Now().UTC()
	c := &Container{Config: cfg, State: State{Status: "created"}}
	if err := writeJSON(filepath.Join(Dir(cfg.ID), "config.json"), cfg); err != nil {
		os.RemoveAll(Dir(cfg.ID))
		return nil, err
	}
	if err := writeJSON(statePath(cfg.ID), c.State); err != nil {
		os.RemoveAll(Dir(cfg.ID))
		return nil, err
	}
	return c, nil
}

func validName(n string) bool {
	if n == "" || n[0] == '-' || n[0] == '.' || len(n) > 128 {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-') {
			return false
		}
	}
	return len(n) != 64 || !isHex(n)
}

func isHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// Short returns the 12-char display id.
func Short(id string) string { return short(id) }

// Load reads a container by exact id.
func Load(id string) (*Container, error) {
	c := &Container{}
	b, err := os.ReadFile(filepath.Join(Dir(id), "config.json"))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &c.Config); err != nil {
		return nil, fmt.Errorf("corrupt config.json for %s: %w", short(id), err)
	}
	if b, err = os.ReadFile(statePath(id)); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &c.State); err != nil {
		return nil, fmt.Errorf("corrupt state.json for %s: %w", short(id), err)
	}
	return c, nil
}

// Refresh reloads the state from disk.
func (c *Container) Refresh() error {
	b, err := os.ReadFile(statePath(c.Config.ID))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &c.State)
}

// UpdateState applies fn to state.json under an exclusive flock.
func (c *Container) UpdateState(fn func(*State)) error {
	f, err := os.OpenFile(filepath.Join(Dir(c.Config.ID), "state.lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	if err := c.Refresh(); err != nil {
		return err
	}
	fn(&c.State)
	return writeJSON(statePath(c.Config.ID), c.State)
}

// List returns all containers, oldest first.
func List() []*Container {
	ents, _ := os.ReadDir(containersDir())
	var out []*Container
	for _, e := range ents {
		if !e.IsDir() || len(e.Name()) != 64 {
			continue
		}
		if c, err := Load(e.Name()); err == nil {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Config.Created.Before(out[j].Config.Created) })
	return out
}

// Resolve finds a container by name, full id, or unique id prefix.
func Resolve(ref string) (*Container, error) {
	if ref == "" {
		return nil, errors.New("empty container reference")
	}
	var match []*Container
	for _, c := range List() {
		if c.Config.Name == ref || c.Config.ID == ref {
			return c, nil
		}
		if strings.HasPrefix(c.Config.ID, ref) {
			match = append(match, c)
		}
	}
	switch len(match) {
	case 0:
		return nil, fmt.Errorf("no such container %q; list containers with `minibox ps -a`", ref)
	case 1:
		return match[0], nil
	}
	return nil, fmt.Errorf("container reference %q is ambiguous (%d matches); use more characters of the id", ref, len(match))
}

// DisplayStatus is the status including the "dead" case (supervisor gone while "running").
func (c *Container) DisplayStatus() string {
	if c.State.Status == "running" && !state.IsAlive(c.Config.ID) {
		return "dead"
	}
	return c.State.Status
}

// Running reports whether the supervisor is alive and the container is running.
func (c *Container) Running() bool { return c.DisplayStatus() == "running" }

// Reconcile finalises containers whose supervisor died: state becomes exited(137),
// the cgroup is removed and --rm containers are deleted. Returns true if it changed anything.
func netPath(id string) string { return filepath.Join(Dir(id), "net.json") }

// cleanupNetwork undoes recorded network setup (idempotent).
func cleanupNetwork(id string) {
	b, err := os.ReadFile(netPath(id))
	if err != nil {
		return
	}
	var info network.Info
	if json.Unmarshal(b, &info) == nil {
		(&network.Manager{Root: state.Root()}).Cleanup(id, &info)
	}
	os.Remove(netPath(id))
}

func (c *Container) Reconcile() bool {
	st := c.DisplayStatus()
	if st != "dead" && !(st == "created" && !state.IsAlive(c.Config.ID) && time.Since(c.Config.Created) > 30*time.Second) {
		return false
	}
	removeCgroup(c.Config.ID)
	cleanupNetwork(c.Config.ID)
	state.Release(c.Config.ID, nil)
	_ = c.UpdateState(func(s *State) {
		s.Status, s.Pid, s.ExitCode = "exited", 0, 137
		s.Error = "supervisor died; container was killed"
		s.FinishedAt = time.Now().UTC()
	})
	if c.Config.Rm {
		os.RemoveAll(Dir(c.Config.ID))
	}
	return true
}

// Remove deletes a stopped container. It refuses to remove a running one.
func Remove(c *Container, force bool) error {
	c.Reconcile()
	_ = c.Refresh()
	if c.Running() {
		if !force {
			return fmt.Errorf("container %s is running; stop it first (`minibox stop %s`) or use `minibox rm -f`", short(c.Config.ID), short(c.Config.ID))
		}
		if err := Stop(c, 0); err != nil {
			return err
		}
	}
	removeCgroup(c.Config.ID)
	cleanupNetwork(c.Config.ID)
	state.Release(c.Config.ID, nil)
	return os.RemoveAll(Dir(c.Config.ID))
}

func removeCgroup(id string) {
	if os.Geteuid() == 0 {
		_ = cgroup.RemovePath(cgroup.Base() + "/" + id)
	}
}
