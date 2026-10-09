//go:build linux

package runtime

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type devNode struct {
	name  string
	major uint32
	minor uint32
}

var devNodes = []devNode{
	{"null", 1, 3}, {"zero", 1, 5}, {"full", 1, 7},
	{"random", 1, 8}, {"urandom", 1, 9}, {"tty", 5, 0},
}

// Paths hidden by bind-mounting /dev/null (files) or an empty ro tmpfs (dirs).
var maskedPaths = []string{
	"/proc/acpi", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
	"/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug",
	"/proc/scsi", "/sys/firmware",
}

// Paths remounted read-only.
var readonlyPaths = []string{
	"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
}

// setupRootfs mounts everything under rootfs, then pivot_roots into it.
func setupRootfs(rootfs string) error {
	// Mounts must be private (done by caller); a pivot target must be a mount point.
	if err := unix.Mount(rootfs, rootfs, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind rootfs onto itself: %w", err)
	}
	if err := mountSpecial(rootfs); err != nil {
		return err
	}
	if err := pivot(rootfs); err != nil {
		return err
	}
	return nil
}

func mountSpecial(root string) error {
	j := func(p string) string { return filepath.Join(root, p) }
	for _, d := range []string{"/proc", "/dev", "/sys"} {
		if err := os.MkdirAll(j(d), 0o755); err != nil {
			return err
		}
	}
	nsd := uintptr(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	if err := unix.Mount("proc", j("/proc"), "proc", nsd, ""); err != nil {
		return fmt.Errorf("mount /proc: %w", err)
	}
	if err := unix.Mount("sysfs", j("/sys"), "sysfs", nsd|unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("mount /sys (read-only): %w", err)
	}
	if err := unix.Mount("tmpfs", j("/dev"), "tmpfs", unix.MS_NOSUID|unix.MS_STRICTATIME, "mode=755,size=64k"); err != nil {
		return fmt.Errorf("mount /dev: %w", err)
	}
	for _, n := range devNodes {
		p := j("/dev/" + n.name)
		if err := unix.Mknod(p, unix.S_IFCHR|0o666, int(unix.Mkdev(n.major, n.minor))); err != nil {
			// Fall back to bind-mounting from the host (rootless case).
			if err2 := bindDev("/dev/"+n.name, p); err2 != nil {
				return fmt.Errorf("create /dev/%s: mknod: %v; bind: %w", n.name, err, err2)
			}
			continue
		}
		_ = os.Chmod(p, 0o666)
	}
	for _, d := range []string{"/dev/pts", "/dev/shm"} {
		if err := os.MkdirAll(j(d), 0o755); err != nil {
			return err
		}
	}
	if err := unix.Mount("devpts", j("/dev/pts"), "devpts", unix.MS_NOSUID|unix.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620"); err != nil {
		return fmt.Errorf("mount /dev/pts: %w", err)
	}
	if err := unix.Mount("shm", j("/dev/shm"), "tmpfs", nsd, "mode=1777,size=64m"); err != nil {
		return fmt.Errorf("mount /dev/shm: %w", err)
	}
	for src, dst := range map[string]string{
		"/proc/self/fd": "fd", "/proc/self/fd/0": "stdin", "/proc/self/fd/1": "stdout",
		"/proc/self/fd/2": "stderr", "pts/ptmx": "ptmx",
	} {
		_ = os.Symlink(src, j("/dev/"+dst))
	}
	for _, p := range maskedPaths {
		if err := maskPath(j(p)); err != nil {
			return fmt.Errorf("mask %s: %w", p, err)
		}
	}
	for _, p := range readonlyPaths {
		if err := readonlyPath(j(p)); err != nil {
			return fmt.Errorf("make %s read-only: %w", p, err)
		}
	}
	return nil
}

func bindDev(src, dst string) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_RDWR, 0o666)
	if err != nil {
		return err
	}
	f.Close()
	return unix.Mount(src, dst, "", unix.MS_BIND, "")
}

func maskPath(p string) error {
	st, err := os.Stat(p)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.IsDir() {
		return unix.Mount("tmpfs", p, "tmpfs", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=0")
	}
	return unix.Mount("/dev/null", p, "", unix.MS_BIND, "")
}

func readonlyPath(p string) error {
	if _, err := os.Stat(p); os.IsNotExist(err) {
		return nil
	}
	if err := unix.Mount(p, p, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return err
	}
	return unix.Mount("", p, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_REC|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "")
}

// pivot swaps the root to newroot and drops the old one. It uses
// pivot_root(".", ".") so no put_old directory is created inside the rootfs
// (which may be shared by concurrent containers); the old root is stacked
// under the new one and lazily unmounted.
func pivot(newroot string) error {
	fd, err := unix.Open(newroot, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open new root: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Fchdir(fd); err != nil {
		return fmt.Errorf("chdir new root: %w", err)
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	// The old root is now mounted on top of "." ; detach it.
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("unmount old root: %w", err)
	}
	return unix.Chdir("/")
}
