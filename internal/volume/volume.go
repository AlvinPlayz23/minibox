//go:build linux

// Package volume manages named volumes under $MINIBOX_ROOT/volumes/<name>/_data.
package volume

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Dir returns the volumes root.
func Dir(root string) string { return filepath.Join(root, "volumes") }

// DataDir returns the data dir path for a volume (may not exist).
func DataDir(root, name string) string { return filepath.Join(Dir(root), name, "_data") }

func validName(n string) bool {
	if n == "" || len(n) > 128 {
		return false
	}
	for i, r := range n {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-'
		if !ok || i == 0 && (r == '.' || r == '-') {
			return false
		}
	}
	return true
}

// Ensure creates the volume if needed and returns its data dir.
func Ensure(root, name string) (string, error) {
	if !validName(name) {
		return "", fmt.Errorf("invalid volume name %q; use letters, digits, '_', '.', '-' (not starting with '.' or '-')", name)
	}
	d := DataDir(root, name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", err
	}
	return d, nil
}

// Info describes one volume.
type Info struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	Created time.Time `json:"created"`
}

// List returns all volumes, oldest first. A missing volumes directory is
// empty; any other read error is reported instead of an empty result.
func List(root string) ([]Info, error) {
	ents, err := os.ReadDir(Dir(root))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list volumes in %s: %w", Dir(root), err)
	}
	var out []Info
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		p := DataDir(root, e.Name())
		st, err := os.Stat(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue // incomplete volume (crash mid-create); prune drops it
			}
			return nil, fmt.Errorf("stat volume %s: %w", e.Name(), err)
		}
		out = append(out, Info{Name: e.Name(), Path: p, Created: st.ModTime().UTC()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, nil
}

// Exists reports whether the volume exists.
func Exists(root, name string) bool {
	_, err := os.Stat(DataDir(root, name))
	return err == nil
}

// Remove deletes a volume. Callers check in-use first.
func Remove(root, name string) error {
	if !validName(name) {
		return fmt.Errorf("invalid volume name %q", name)
	}
	p := filepath.Join(Dir(root), name)
	if _, err := os.Stat(p); err != nil {
		return fmt.Errorf("no such volume %q; list volumes with `minibox volume ls`", name)
	}
	return os.RemoveAll(p)
}

// Lock serializes volume removal against volume creation and container
// registration: hold it across Ensure+container.Create (run/up) and across
// the in-use check + Remove (volume rm/prune). Otherwise a concurrent
// `volume rm` can pass its in-use check after `run` resolved the volume but
// before the container is registered, then delete the mount source.
func Lock(root string) (func(), error) {
	if err := os.MkdirAll(Dir(root), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(Dir(root), ".lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}

// IsNamedVolumeSource reports whether src looks like a named volume (not a host path).
func IsNamedVolumeSource(src string) bool {
	return src != "" && !strings.HasPrefix(src, "/") && !strings.HasPrefix(src, ".") && !strings.Contains(src, "/")
}
