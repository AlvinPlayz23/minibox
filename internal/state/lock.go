//go:build linux

// Package state holds per-container liveness locks under $MINIBOX_ROOT.
package state

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Root returns $MINIBOX_ROOT (default /var/lib/minibox, or ~/.local/share/minibox when not root).
func Root() string {
	if v := os.Getenv("MINIBOX_ROOT"); v != "" {
		if a, err := filepath.Abs(v); err == nil {
			return a
		}
		return v
	}
	if os.Geteuid() != 0 {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, ".local/share/minibox")
		}
	}
	return "/var/lib/minibox"
}

func lockPath(id string) string { return filepath.Join(Root(), "run", id+".lock") }

// HoldLock takes an exclusive flock for id; the kernel releases it if the holder dies (even kill -9).
func HoldLock(id string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(lockPath(id)), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath(id), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// IsAlive reports whether some process still holds id's lock.
func IsAlive(id string) bool {
	f, err := os.OpenFile(lockPath(id), os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return true
	}
	return false
}

// Release drops and deletes the lock.
func Release(id string, f *os.File) {
	_ = os.Remove(lockPath(id))
	if f != nil {
		f.Close()
	}
}

// HasLock reports whether a lock file for id exists under this root.
func HasLock(id string) bool {
	_, err := os.Stat(lockPath(id))
	return err == nil
}
