//go:build linux

// Package storage manages per-container directories and overlayfs mounts.
package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Lower is one read-only layer: its real dir and a short symlink path to it.
type Lower struct{ Dir, Short string }

// Overlay describes an overlayfs mount.
type Overlay struct {
	Lowers    []Lower // top-most first
	Upper     string
	Work      string
	Target    string
	UserXattr bool // rootless overlay (kernel 5.11+); used from M8
}

// maxOptLen is conservative: the kernel copies mount data into a single page (4096 bytes).
const maxOptLen = 4000

// ContainerDirs are the writable dirs of one container.
type ContainerDirs struct{ Base, Upper, Work, Merged string }

// NewContainerDirs creates containers/<id>/{upper,work,merged}.
func NewContainerDirs(root, id string) (*ContainerDirs, error) {
	b := filepath.Join(root, "containers", id)
	c := &ContainerDirs{Base: b, Upper: filepath.Join(b, "upper"), Work: filepath.Join(b, "work"), Merged: filepath.Join(b, "merged")}
	for _, d := range []string{c.Upper, c.Work, c.Merged} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			os.RemoveAll(b)
			return nil, err
		}
	}
	return c, nil
}

// Remove deletes the container's writable layer.
func (c *ContainerDirs) Remove() error { return os.RemoveAll(c.Base) }

func checkPath(p string) error {
	if strings.ContainsAny(p, ",:\\\x00") {
		return fmt.Errorf("path %q contains a character (, : \\) that overlayfs options cannot express; choose another MINIBOX_ROOT", p)
	}
	return nil
}

// Mount mounts the overlay at o.Target. Call it from inside the container's
// mount namespace so the mount disappears with the namespace (no host leaks).
func (o *Overlay) Mount() error {
	if len(o.Lowers) == 0 {
		return fmt.Errorf("overlay needs at least one lower layer")
	}
	for _, p := range []string{o.Upper, o.Work, o.Target} {
		if err := checkPath(p); err != nil {
			return err
		}
	}
	tail := ",upperdir=" + o.Upper + ",workdir=" + o.Work
	if o.UserXattr {
		tail += ",userxattr"
	}
	var lowers []string
	for _, l := range o.Lowers {
		if err := checkPath(l.Dir); err != nil {
			return err
		}
		lowers = append(lowers, l.Dir)
	}
	data := "lowerdir=" + strings.Join(lowers, ":") + tail
	if len(data) <= maxOptLen {
		return mount(o.Target, data)
	}
	// Too long: refer to layers via short symlinks, addressed relative to an
	// open directory fd so the prefix stays tiny: /proc/self/fd/N/<12 hex>.
	dirfd, err := unix.Open(filepath.Dir(o.Lowers[0].Short), unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open layer links dir: %w", err)
	}
	defer unix.Close(dirfd)
	lowers = lowers[:0]
	for _, l := range o.Lowers {
		lowers = append(lowers, fmt.Sprintf("/proc/self/fd/%d/%s", dirfd, filepath.Base(l.Short)))
	}
	data = "lowerdir=" + strings.Join(lowers, ":") + tail
	if len(data) > maxOptLen {
		// Last resort (Linux 6.8+): the new mount API appends one lowerdir+ at a
		// time, with no total length limit.
		if err := mountNewAPI(o); err != nil {
			return fmt.Errorf("image has too many layers (%d) for one classic overlayfs mount (option string %d bytes > %d) and the new mount API failed: %w", len(o.Lowers), len(data), maxOptLen, err)
		}
		return nil
	}
	return mount(o.Target, data)
}

// mountNewAPI mounts via fsopen/fsconfig/fsmount using "lowerdir+" (kernel >= 6.8).
func mountNewAPI(o *Overlay) error {
	fsfd, err := unix.Fsopen("overlay", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return fmt.Errorf("fsopen: %w", err)
	}
	defer unix.Close(fsfd)
	for _, l := range o.Lowers {
		if err := unix.FsconfigSetString(fsfd, "lowerdir+", l.Dir); err != nil {
			return fmt.Errorf("fsconfig lowerdir+ (needs Linux 6.8+): %w", err)
		}
	}
	if err := unix.FsconfigSetString(fsfd, "upperdir", o.Upper); err != nil {
		return fmt.Errorf("fsconfig upperdir: %w", err)
	}
	if err := unix.FsconfigSetString(fsfd, "workdir", o.Work); err != nil {
		return fmt.Errorf("fsconfig workdir: %w", err)
	}
	if o.UserXattr {
		if err := unix.FsconfigSetFlag(fsfd, "userxattr"); err != nil {
			return err
		}
	}
	if err := unix.FsconfigCreate(fsfd); err != nil {
		return fmt.Errorf("fsconfig create: %w", err)
	}
	mfd, err := unix.Fsmount(fsfd, unix.FSMOUNT_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("fsmount: %w", err)
	}
	defer unix.Close(mfd)
	if err := unix.MoveMount(mfd, "", unix.AT_FDCWD, o.Target, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return fmt.Errorf("move_mount: %w", err)
	}
	return nil
}

func mount(target, data string) error {
	if err := unix.Mount("overlay", target, "overlay", 0, data); err != nil {
		return fmt.Errorf("mount overlay at %s: %w (is overlayfs available? see /proc/filesystems; upper/work must be on a non-overlay filesystem)", target, err)
	}
	return nil
}
