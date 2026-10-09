//go:build linux

package image

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// ExtractOptions control layer extraction.
type ExtractOptions struct {
	// OpaqueXattr is set on directories carrying the OCI opaque marker
	// (".wh..wh..opq"). Default "trusted.overlay.opaque"; rootless overlay
	// uses "user.overlay.opaque".
	OpaqueXattr string
	// Privileged allows chown and mknod (normally euid==0).
	Privileged bool
}

// DefaultExtractOptions returns options for the current process.
func DefaultExtractOptions() ExtractOptions {
	return ExtractOptions{OpaqueXattr: "trusted.overlay.opaque", Privileged: os.Geteuid() == 0}
}

// ExtractTar unpacks an (uncompressed) tar stream into dir, which must exist.
//
// Safety model: every filesystem operation is performed relative to a
// directory file descriptor obtained by walking the path one component at a
// time with O_NOFOLLOW. A symlink in any parent component is an error, so a
// tar can never write outside dir, no matter how entries are ordered or what
// symlinks/hardlinks they define. Entry names containing ".." are rejected
// outright. Overlay-significant metadata (trusted.* xattrs, raw 0:0 char
// devices) cannot be smuggled in; whiteouts are only created from ".wh." entries.
func ExtractTar(dir string, r io.Reader, opts ExtractOptions) error {
	if opts.OpaqueXattr == "" {
		opts.OpaqueXattr = "trusted.overlay.opaque"
	}
	root, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open layer dir %s: %w", dir, err)
	}
	defer unix.Close(root)
	e := &extractor{root: root, opts: opts, dirs: map[string]*dirAttr{}, buf: make([]byte, 128<<10), lastFd: -1}
	defer e.dropCache()
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		if err := e.entry(h, tr); err != nil {
			return fmt.Errorf("tar entry %q: %w", h.Name, err)
		}
	}
	return e.applyDirs()
}

type dirAttr struct {
	parts    []string
	mode     uint32
	uid, gid int
	mtime    time.Time
	xattrs   map[string]string
}

type extractor struct {
	root int
	opts ExtractOptions
	dirs map[string]*dirAttr
	buf  []byte

	lastKey string
	lastFd  int
}

func (e *extractor) dropCache() {
	if e.lastFd >= 0 {
		unix.Close(e.lastFd)
	}
	e.lastFd, e.lastKey = -1, ""
}

// splitPath normalises a tar name into components, rejecting traversal.
func splitPath(name string) ([]string, error) {
	if strings.IndexByte(name, 0) >= 0 {
		return nil, errors.New("name contains NUL")
	}
	var out []string
	for _, p := range strings.Split(name, "/") {
		switch p {
		case "", ".":
		case "..":
			return nil, errors.New("path traversal (..) is not allowed")
		default:
			out = append(out, p)
		}
	}
	return out, nil
}

// openDir walks parts from the root without following symlinks. The caller owns the fd.
func (e *extractor) openDir(parts []string, create bool) (int, error) {
	cur, err := unix.Dup(e.root)
	if err != nil {
		return -1, err
	}
	for _, p := range parts {
		next, err := unix.Openat(cur, p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err == unix.ENOENT && create {
			if err = unix.Mkdirat(cur, p, 0o755); err == nil || err == unix.EEXIST {
				next, err = unix.Openat(cur, p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
		}
		unix.Close(cur)
		if err != nil {
			if err == unix.ELOOP || err == unix.ENOTDIR {
				return -1, fmt.Errorf("component %q is a symlink or not a directory; refusing to traverse", p)
			}
			return -1, fmt.Errorf("open %q: %w", p, err)
		}
		cur = next
	}
	return cur, nil
}

// parent returns a cached/fresh fd for the parent directory of an entry. Caller must not close it.
func (e *extractor) parent(parts []string, create bool) (int, error) {
	key := strings.Join(parts, "/")
	if e.lastFd >= 0 && e.lastKey == key {
		return e.lastFd, nil
	}
	fd, err := e.openDir(parts, create)
	if err != nil {
		return -1, err
	}
	e.dropCache()
	e.lastFd, e.lastKey = fd, key
	return fd, nil
}

// removeAt deletes name under dirfd (recursively for directories) without following symlinks.
func (e *extractor) removeAt(dirfd int, parts []string) error {
	full := strings.Join(parts, "/")
	// Cached fds / pending dir attrs under the removed path become stale.
	if e.lastFd >= 0 && (e.lastKey == full || strings.HasPrefix(e.lastKey, full+"/")) {
		e.dropCache()
	}
	for k := range e.dirs {
		if k == full || strings.HasPrefix(k, full+"/") {
			delete(e.dirs, k)
		}
	}
	return removeAt(dirfd, parts[len(parts)-1])
}

func removeAt(dirfd int, name string) error {
	err := unix.Unlinkat(dirfd, name, 0)
	if err == nil || err == unix.ENOENT {
		return nil
	}
	if err != unix.EISDIR && err != unix.EPERM {
		return err
	}
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	names, err := f.Readdirnames(-1)
	if err != nil {
		f.Close()
		return err
	}
	for _, n := range names {
		if err := removeAt(fd, n); err != nil {
			f.Close()
			return err
		}
	}
	f.Close()
	return unix.Unlinkat(dirfd, name, unix.AT_REMOVEDIR)
}

func (e *extractor) entry(h *tar.Header, r io.Reader) error {
	if h.Typeflag == tar.TypeXGlobalHeader {
		return nil
	}
	parts, err := splitPath(h.Name)
	if err != nil {
		return err
	}
	if len(parts) == 0 {
		if h.Typeflag == tar.TypeDir {
			e.recordDir(nil, h)
		}
		return nil
	}
	name := parts[len(parts)-1]
	if strings.HasPrefix(name, ".wh.") {
		return e.whiteout(parts, h)
	}
	pfd, err := e.parent(parts[:len(parts)-1], true)
	if err != nil {
		return err
	}
	mode := uint32(h.Mode) & 0o7777
	uid, gid := h.Uid, h.Gid
	ts := []unix.Timespec{unix.NsecToTimespec(h.ModTime.UnixNano()), unix.NsecToTimespec(h.ModTime.UnixNano())}

	switch h.Typeflag {
	case tar.TypeDir:
		if err := unix.Mkdirat(pfd, name, 0o755); err != nil {
			if err != unix.EEXIST {
				return err
			}
			var st unix.Stat_t
			if unix.Fstatat(pfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
				if err := e.removeAt(pfd, parts); err != nil {
					return err
				}
				if err := unix.Mkdirat(pfd, name, 0o755); err != nil {
					return err
				}
			}
		}
		e.recordDir(parts, h)
		return nil

	case tar.TypeReg, tar.TypeRegA:
		fd, err := unix.Openat(pfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err == unix.EEXIST {
			if err = e.removeAt(pfd, parts); err != nil {
				return err
			}
			fd, err = unix.Openat(pfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		}
		if err != nil {
			return err
		}
		f := os.NewFile(uintptr(fd), name)
		if _, err := io.CopyBuffer(f, io.LimitReader(r, h.Size), e.buf); err != nil {
			f.Close()
			return err
		}
		if e.opts.Privileged {
			if err := unix.Fchown(fd, uid, gid); err != nil {
				f.Close()
				return err
			}
		}
		if err := unix.Fchmod(fd, mode); err != nil {
			f.Close()
			return err
		}
		if err := setXattrsFd(fd, h); err != nil {
			f.Close()
			return err
		}
		_ = unix.UtimesNanoAt(fd, "", ts, unix.AT_EMPTY_PATH)
		return f.Close()

	case tar.TypeSymlink:
		if h.Linkname == "" || strings.IndexByte(h.Linkname, 0) >= 0 {
			return errors.New("invalid symlink target")
		}
		// Target is stored verbatim (absolute targets are normal in images);
		// it is never followed during extraction.
		if err := e.replace(pfd, parts, name, func(fd int) error { return unix.Symlinkat(h.Linkname, fd, name) }); err != nil {
			return err
		}
		if e.opts.Privileged {
			_ = unix.Fchownat(pfd, name, uid, gid, unix.AT_SYMLINK_NOFOLLOW)
		}
		_ = unix.UtimesNanoAt(pfd, name, ts, unix.AT_SYMLINK_NOFOLLOW)
		return nil

	case tar.TypeLink:
		tparts, err := splitPath(h.Linkname)
		if err != nil {
			return fmt.Errorf("hardlink target: %w", err)
		}
		if len(tparts) == 0 {
			return errors.New("hardlink target is empty")
		}
		tfd, err := e.openDir(tparts[:len(tparts)-1], false)
		if err != nil {
			return fmt.Errorf("hardlink target: %w", err)
		}
		defer unix.Close(tfd)
		tname := tparts[len(tparts)-1]
		return e.replace(pfd, parts, name, func(fd int) error {
			// flags=0: do not follow a symlink target; never leaves the layer dir.
			return unix.Linkat(tfd, tname, fd, name, 0)
		})

	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		if !e.opts.Privileged && h.Typeflag != tar.TypeFifo {
			return nil // cannot create device nodes unprivileged; skipped
		}
		if h.Typeflag == tar.TypeChar && h.Devmajor == 0 && h.Devminor == 0 {
			return errors.New("char device 0:0 is reserved for overlay whiteouts; use .wh. entries")
		}
		typ := uint32(unix.S_IFIFO)
		switch h.Typeflag {
		case tar.TypeChar:
			typ = unix.S_IFCHR
		case tar.TypeBlock:
			typ = unix.S_IFBLK
		}
		dev := int(unix.Mkdev(uint32(h.Devmajor), uint32(h.Devminor)))
		if err := e.replace(pfd, parts, name, func(fd int) error {
			return unix.Mknodat(fd, name, typ|(mode&0o777), dev)
		}); err != nil {
			return err
		}
		if e.opts.Privileged {
			_ = unix.Fchownat(pfd, name, uid, gid, unix.AT_SYMLINK_NOFOLLOW)
		}
		_ = unix.Fchmodat(pfd, name, mode, 0)
		return nil
	}
	return fmt.Errorf("unsupported tar entry type %q", h.Typeflag)
}

// replace runs create(pfd), removing a pre-existing entry first if needed.
func (e *extractor) replace(pfd int, parts []string, name string, create func(fd int) error) error {
	err := create(pfd)
	if err == unix.EEXIST {
		if err = e.removeAt(pfd, parts); err != nil {
			return err
		}
		err = create(pfd)
	}
	return err
}

func (e *extractor) recordDir(parts []string, h *tar.Header) {
	e.dirs[strings.Join(parts, "/")] = &dirAttr{
		parts: append([]string(nil), parts...),
		mode:  uint32(h.Mode) & 0o7777,
		uid:   h.Uid, gid: h.Gid, mtime: h.ModTime,
		xattrs: allowedXattrs(h),
	}
}

func (e *extractor) whiteout(parts []string, h *tar.Header) error {
	name := parts[len(parts)-1]
	dir := parts[:len(parts)-1]
	switch {
	case name == ".wh..wh..opq":
		fd, err := e.openDir(dir, true)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		if err := unix.Fsetxattr(fd, e.opts.OpaqueXattr, []byte("y"), 0); err != nil {
			return fmt.Errorf("mark %s opaque (%s): %w", strings.Join(dir, "/"), e.opts.OpaqueXattr, err)
		}
		return nil
	case strings.HasPrefix(name, ".wh..wh."):
		return nil // aufs/docker metadata (.wh..wh.plnk, .wh..wh.aufs): ignore
	}
	target := strings.TrimPrefix(name, ".wh.")
	if target == "" || target == "." || target == ".." {
		return fmt.Errorf("invalid whiteout name %q", name)
	}
	if !e.opts.Privileged {
		return errors.New("creating overlay whiteouts needs CAP_MKNOD (rootless layers are handled in M8)")
	}
	pfd, err := e.parent(dir, true)
	if err != nil {
		return err
	}
	// Overlay-native whiteout: char device 0:0 in the diff dir.
	err = unix.Mknodat(pfd, target, unix.S_IFCHR|0o000, 0)
	if err == unix.EEXIST {
		if err = e.removeAt(pfd, append(append([]string(nil), dir...), target)); err != nil {
			return err
		}
		err = unix.Mknodat(pfd, target, unix.S_IFCHR|0o000, 0)
	}
	return err
}

// allowedXattrs keeps only xattrs that are safe in a layer: file capabilities
// and user.*. In particular trusted.overlay.* (redirect/opaque/origin) from a
// tar are dropped, because they could re-route overlay lookups.
func allowedXattrs(h *tar.Header) map[string]string {
	var out map[string]string
	for k, v := range h.PAXRecords {
		n, ok := strings.CutPrefix(k, "SCHILY.xattr.")
		if !ok {
			continue
		}
		if n == "security.capability" || strings.HasPrefix(n, "user.") {
			if out == nil {
				out = map[string]string{}
			}
			out[n] = v
		}
	}
	return out
}

func setXattrsFd(fd int, h *tar.Header) error {
	for k, v := range allowedXattrs(h) {
		if err := unix.Fsetxattr(fd, k, []byte(v), 0); err != nil && err != unix.ENOTSUP && err != unix.EPERM {
			return fmt.Errorf("set xattr %s: %w", k, err)
		}
	}
	return nil
}

// applyDirs sets owner/mode/xattrs/mtime on directories, deepest first, after all children exist.
func (e *extractor) applyDirs() error {
	e.dropCache()
	list := make([]*dirAttr, 0, len(e.dirs))
	for _, d := range e.dirs {
		list = append(list, d)
	}
	sort.Slice(list, func(i, j int) bool { return len(list[i].parts) > len(list[j].parts) })
	for _, d := range list {
		fd, err := e.openDir(d.parts, false)
		if err != nil {
			return fmt.Errorf("finalize dir %q: %w", strings.Join(d.parts, "/"), err)
		}
		if e.opts.Privileged {
			if err := unix.Fchown(fd, d.uid, d.gid); err != nil {
				unix.Close(fd)
				return err
			}
		}
		err = unix.Fchmod(fd, d.mode)
		for k, v := range d.xattrs {
			if xerr := unix.Fsetxattr(fd, k, []byte(v), 0); xerr != nil && xerr != unix.ENOTSUP && xerr != unix.EPERM {
				err = xerr
			}
		}
		ts := []unix.Timespec{unix.NsecToTimespec(d.mtime.UnixNano()), unix.NsecToTimespec(d.mtime.UnixNano())}
		_ = unix.UtimesNanoAt(fd, "", ts, unix.AT_EMPTY_PATH)
		unix.Close(fd)
		if err != nil {
			return err
		}
	}
	return nil
}
