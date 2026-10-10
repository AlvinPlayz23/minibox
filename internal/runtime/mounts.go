//go:build linux

package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// Mount is a user-requested mount inside the container (-v, --tmpfs).
type Mount struct {
	Type string `json:"type"` // bind or tmpfs
	Src  string `json:"src,omitempty"`
	Dst  string `json:"dst"`
	RO   bool   `json:"ro,omitempty"`
	Size string `json:"size,omitempty"` // tmpfs size option, e.g. 64m
}

// ResolveInRoot resolves p (an absolute path as seen inside the container) under root,
// following symlinks *as if root were /*: an absolute symlink target or a ".." can never leave
// root. The result is a host path inside root. Missing trailing components are allowed.
//
// Correctness invariant: cur is always fully resolved (contains no symlinks) and missing
// holds only components known not to exist. A ".." therefore either pops a missing
// component (which cannot be a symlink) or climbs within resolved space — it can never
// climb "back" through a symlink into unvalidated territory.
func ResolveInRoot(root, p string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("container path %q must be absolute", p)
	}
	cur := "" // fully-resolved path inside root ("" = /)
	var missing []string
	links := 0
	pending := strings.Split(filepath.Clean(p), "/")
	for len(pending) > 0 {
		name := pending[0]
		pending = pending[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			if len(missing) > 0 {
				missing = missing[:len(missing)-1]
				continue
			}
			cur = filepath.Dir(cur)
			if cur == "." || cur == "/" {
				cur = ""
			}
			continue
		}
		if len(missing) > 0 {
			missing = append(missing, name)
			continue
		}
		fi, err := os.Lstat(root + cur + "/" + name)
		if err != nil {
			if os.IsNotExist(err) {
				missing = append(missing, name)
				continue
			}
			return "", err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			if links++; links > 40 {
				return "", errors.New("too many levels of symbolic links")
			}
			t, err := os.Readlink(root + cur + "/" + name)
			if err != nil {
				return "", err
			}
			if strings.HasPrefix(t, "/") {
				cur, missing = "", nil
			}
			pending = append(strings.Split(t, "/"), pending...)
			continue
		}
		cur += "/" + name
	}
	out := root + cur
	for _, m := range missing {
		out += "/" + m
	}
	return out, nil
}

// ParseVolume parses SRC:DST[:ro|rw] into a bind Mount. src that is not a host path
// (no leading /, ., and no / at all) is treated as a named volume: volumeData is
// called to resolve/create it. Dst must be absolute.
func ParseVolume(spec string, volumeData func(name string) (string, error)) (Mount, error) {
	bad := func(why string) (Mount, error) {
		return Mount{}, fmt.Errorf("invalid -v %q: %s; use SRC:DST[:ro], e.g. -v mydata:/data:ro or -v /host/dir:/data", spec, why)
	}
	parts := strings.Split(spec, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return bad("expected SRC:DST or SRC:DST:ro")
	}
	src, dst := parts[0], parts[1]
	ro := false
	if len(parts) == 3 {
		switch parts[2] {
		case "ro", "readonly":
			ro = true
		case "rw", "readwrite":
		default:
			return bad("third field must be ro or rw")
		}
	}
	if src == "" || dst == "" {
		return bad("empty source or destination")
	}
	if !filepath.IsAbs(dst) {
		return bad("destination must be an absolute path inside the container")
	}
	host := src
	if volumeData != nil && !filepath.IsAbs(src) && !strings.HasPrefix(src, ".") && !strings.Contains(src, "/") {
		var err error
		if host, err = volumeData(src); err != nil {
			return Mount{}, err
		}
	}
	return Mount{Type: "bind", Src: host, Dst: dst, RO: ro}, nil
}

// ParseTmpfs parses DST[:size=64m[,ro]] into a tmpfs Mount.
func ParseTmpfs(spec string) (Mount, error) {
	bad := func(why string) (Mount, error) {
		return Mount{}, fmt.Errorf("invalid --tmpfs %q: %s; use DST[:size=64m][,ro], e.g. --tmpfs /run:size=64m", spec, why)
	}
	dst, opts, _ := strings.Cut(spec, ":")
	if dst == "" {
		return bad("empty destination")
	}
	if !filepath.IsAbs(dst) {
		return bad("destination must be an absolute path inside the container")
	}
	m := Mount{Type: "tmpfs", Dst: dst}
	for _, o := range strings.Split(opts, ",") {
		switch {
		case o == "":
		case o == "ro":
			m.RO = true
		case o == "rw":
		case strings.HasPrefix(o, "size="):
			m.Size = strings.TrimPrefix(o, "size=")
			if m.Size == "" {
				return bad("empty size=")
			}
		default:
			return bad(fmt.Sprintf("unknown option %q (want size=.. or ro)", o))
		}
	}
	return m, nil
}

func applyMount(rootfs string, m Mount) error {
	target, err := ResolveInRoot(rootfs, m.Dst)
	if err != nil {
		return fmt.Errorf("mount destination %s: %w", m.Dst, err)
	}
	switch m.Type {
	case "tmpfs":
		if err := os.MkdirAll(target, 0o755); err != nil {
			return err
		}
		opts := "mode=1777"
		if m.Size != "" {
			opts += ",size=" + m.Size
		}
		flags := uintptr(unix.MS_NOSUID | unix.MS_NODEV)
		if m.RO {
			flags |= unix.MS_RDONLY
		}
		if err := unix.Mount("tmpfs", target, "tmpfs", flags, opts); err != nil {
			return fmt.Errorf("tmpfs on %s: %w", m.Dst, err)
		}
		return nil
	case "bind":
		st, err := os.Stat(m.Src)
		if err != nil {
			return fmt.Errorf("volume source %s: %w", m.Src, err)
		}
		if st.IsDir() {
			err = os.MkdirAll(target, 0o755)
		} else {
			if err = os.MkdirAll(filepath.Dir(target), 0o755); err == nil {
				if _, e := os.Lstat(target); e != nil {
					var f *os.File
					if f, err = os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
						f.Close()
					}
				}
			}
		}
		if err != nil {
			return fmt.Errorf("create mount point %s: %w", m.Dst, err)
		}
		if err := unix.Mount(m.Src, target, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("bind %s on %s: %w", m.Src, m.Dst, err)
		}
		if m.RO {
			// MS_REC clones nested mounts too, so a plain remount would leave
			// submounts writable under a ":ro" volume: remount every mount at
			// or below target read-only, deepest first.
			if err := remountRO(target); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("unknown mount type %q", m.Type)
}

// remountRO remounts target and every mount beneath it read-only, deepest first.
func remountRO(target string) error {
	subs, err := submounts(target)
	if err != nil {
		return fmt.Errorf("list mounts under %s: %w", target, err)
	}
	for _, m := range subs {
		if err := unix.Mount("", m, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
			return fmt.Errorf("make %s read-only: %w", m, err)
		}
	}
	if err := unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("make %s read-only: %w", target, err)
	}
	return nil
}

// submounts returns mount points at or below target, deepest first, parsed from
// /proc/self/mountinfo (field 5; octal escapes unescaped).
func submounts(target string) ([]string, error) {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		mp := unescapeMountpoint(f[4])
		if mp != target && !strings.HasPrefix(mp, target+"/") {
			continue
		}
		out = append(out, mp)
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out, nil
}

// unescapeMountpoint decodes the octal escapes mountinfo uses (space, tab,
// newline, backslash).
func unescapeMountpoint(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+4 <= len(s) {
			var v int
			if n, err := fmt.Sscanf(s[i+1:i+4], "%3o", &v); err == nil && n == 1 && v <= 255 {
				b.WriteByte(byte(v))
				i += 4
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
