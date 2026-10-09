//go:build linux

// Package cgroup manages cgroup v2 directories for containers.
package cgroup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const cgroup2Magic = 0x63677270

// Limits are the resource limits for a container; zero means unlimited.
type Limits struct {
	MemoryBytes int64
	CPUs        float64
	PidsLimit   int64
}

// Cgroup is one container's cgroup directory.
type Cgroup struct {
	Path   string
	Limits Limits
}

// MountPoint is where cgroup2 is mounted (overridable for tests).
func MountPoint() string {
	if v := os.Getenv("MINIBOX_CGROUP_MOUNT"); v != "" {
		return v
	}
	return "/sys/fs/cgroup"
}

// Base returns the parent directory holding all minibox cgroups.
func Base() string { return filepath.Join(MountPoint(), "minibox") }

// Check verifies the unified (v2) hierarchy is in use.
func Check() error {
	var st unix.Statfs_t
	if err := unix.Statfs(MountPoint(), &st); err != nil {
		return fmt.Errorf("cannot stat %s: %w; is cgroup2 mounted there?", MountPoint(), err)
	}
	if st.Type != cgroup2Magic {
		return fmt.Errorf("%s is not a cgroup v2 mount (cgroup v1 or hybrid hierarchy); minibox needs the unified hierarchy: boot with systemd.unified_cgroup_hierarchy=1", MountPoint())
	}
	return nil
}

// Create makes the cgroup, enabling needed controllers and applying limits.
func Create(id string, l Limits) (*Cgroup, error) {
	if err := Check(); err != nil {
		return nil, err
	}
	base := Base()
	if err := os.MkdirAll(base, 0o755); err != nil {
		return nil, fmt.Errorf("create %s (need root with cgroup write access): %w", base, err)
	}
	avail, _ := os.ReadFile(filepath.Join(MountPoint(), "cgroup.controllers"))
	have := strings.Fields(string(avail))
	need := map[string]bool{}
	if l.MemoryBytes > 0 {
		need["memory"] = true
	}
	if l.CPUs > 0 {
		need["cpu"] = true
	}
	if l.PidsLimit > 0 {
		need["pids"] = true
	}
	for c := range need {
		if !contains(have, c) {
			return nil, fmt.Errorf("cgroup controller %q is not available in %s/cgroup.controllers (have: %s)", c, MountPoint(), strings.Join(have, " "))
		}
		if err := os.WriteFile(filepath.Join(MountPoint(), "cgroup.subtree_control"), []byte("+"+c), 0o644); err != nil {
			return nil, fmt.Errorf("enable controller %s in %s: %w", c, MountPoint(), err)
		}
		if err := os.WriteFile(filepath.Join(base, "cgroup.subtree_control"), []byte("+"+c), 0o644); err != nil {
			return nil, fmt.Errorf("enable controller %s in %s: %w", c, base, err)
		}
	}
	cg := &Cgroup{Path: filepath.Join(base, id), Limits: l}
	if err := os.Mkdir(cg.Path, 0o755); err != nil {
		return nil, fmt.Errorf("create cgroup: %w", err)
	}
	w := func(f, v string) error {
		if err := os.WriteFile(filepath.Join(cg.Path, f), []byte(v), 0o644); err != nil {
			_ = cg.Remove()
			return fmt.Errorf("write %s=%s: %w", f, v, err)
		}
		return nil
	}
	if l.MemoryBytes > 0 {
		if err := w("memory.max", strconv.FormatInt(l.MemoryBytes, 10)); err != nil {
			return nil, err
		}
		// No swap, so the limit is enforced by OOM rather than by swapping.
		if _, err := os.Stat(filepath.Join(cg.Path, "memory.swap.max")); err == nil {
			if err := w("memory.swap.max", "0"); err != nil {
				return nil, err
			}
		}
	}
	if l.CPUs > 0 {
		const period = 100000
		if err := w("cpu.max", fmt.Sprintf("%d %d", int64(l.CPUs*period), period)); err != nil {
			return nil, err
		}
	}
	if l.PidsLimit > 0 {
		if err := w("pids.max", strconv.FormatInt(l.PidsLimit, 10)); err != nil {
			return nil, err
		}
	}
	return cg, nil
}

// OpenFD opens the cgroup directory for SysProcAttr.CgroupFD (CLONE_INTO_CGROUP).
func (c *Cgroup) OpenFD() (int, error) {
	return unix.Open(c.Path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
}

// Events holds selected memory.events counters.
type Events struct{ OOM, OOMKill int64 }

// MemoryEvents reads memory.events (zero values if the controller is off).
func (c *Cgroup) MemoryEvents() Events { return ReadEvents(c.Path) }

func ReadEvents(path string) Events {
	var e Events
	b, err := os.ReadFile(filepath.Join(path, "memory.events"))
	if err != nil {
		return e
	}
	for _, ln := range strings.Split(string(b), "\n") {
		f := strings.Fields(ln)
		if len(f) != 2 {
			continue
		}
		n, _ := strconv.ParseInt(f[1], 10, 64)
		switch f[0] {
		case "oom":
			e.OOM = n
		case "oom_kill":
			e.OOMKill = n
		}
	}
	return e
}

// Remove kills any remaining processes and removes the cgroup.
func (c *Cgroup) Remove() error { return RemovePath(c.Path) }

func RemovePath(path string) error {
	_ = os.WriteFile(filepath.Join(path, "cgroup.kill"), []byte("1"), 0o644)
	var err error
	for i := 0; i < 100; i++ {
		if err = os.Remove(path); err == nil || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fmt.Errorf("remove cgroup %s: %w", path, err)
}

// List returns all container cgroup names under Base.
func List() []string {
	ents, _ := os.ReadDir(Base())
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// ParseSize parses "64m", "1g", "512k", "1024" into bytes.
func ParseSize(s string) (int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return 0, errors.New("empty size; use e.g. 64m or 1g")
	}
	mult := int64(1)
	switch s[len(s)-1] {
	case 'k':
		mult = 1 << 10
	case 'm':
		mult = 1 << 20
	case 'g':
		mult = 1 << 30
	}
	if mult != 1 {
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid size %q; use a positive number with optional k/m/g suffix, e.g. 64m", s)
	}
	return n * mult, nil
}
