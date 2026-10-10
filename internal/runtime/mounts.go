//go:build linux

package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
func ResolveInRoot(root, p string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("container path %q must be absolute", p)
	}
	cur := "" // path inside root, always clean and absolute ("" = /)
	pending := strings.Split(filepath.Clean(p), "/")
	for links := 0; len(pending) > 0; {
		name := pending[0]
		pending = pending[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			if cur == "." || cur == "/" {
				cur = ""
			}
			continue
		}
		next := cur + "/" + name
		fi, err := os.Lstat(root + next)
		if err != nil {
			if os.IsNotExist(err) {
				cur = next // does not exist yet: append the rest verbatim (cleaned, no symlinks can exist below)
				for _, rest := range pending {
					if rest == ".." {
						cur = filepath.Dir(cur)
						if cur == "/" || cur == "." {
							cur = ""
						}
					} else if rest != "" && rest != "." {
						cur += "/" + rest
					}
				}
				return root + cur, nil
			}
			return "", err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			if links++; links > 40 {
				return "", errors.New("too many levels of symbolic links")
			}
			t, err := os.Readlink(root + next)
			if err != nil {
				return "", err
			}
			if strings.HasPrefix(t, "/") {
				cur = ""
			}
			pending = append(strings.Split(t, "/"), pending...)
			continue
		}
		cur = next
	}
	return root + cur, nil
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
			if err := unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
				return fmt.Errorf("make %s read-only: %w", m.Dst, err)
			}
		}
		return nil
	}
	return fmt.Errorf("unknown mount type %q", m.Type)
}
