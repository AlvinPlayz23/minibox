//go:build linux

package image

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type ent struct {
	name, link string
	typ        byte
	body       string
	mode       int64
	uid, gid   int
	pax        map[string]string
	major, min int64
}

func mkTar(t testing.TB, ents []ent) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range ents {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Linkname: e.link, Typeflag: typ, Mode: e.mode, Uid: e.uid, Gid: e.gid,
			ModTime: time.Unix(1700000000, 0), PAXRecords: e.pax, Devmajor: e.major, Devminor: e.min}
		if typ == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if h.Mode == 0 {
			h.Mode = 0o644
			if typ == tar.TypeDir {
				h.Mode = 0o755
			}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	return b.Bytes()
}

// sandbox: <tmp>/layer (extraction target) next to <tmp>/canary and <tmp>/outside/.
func sandbox(t testing.TB) (base, layer string) {
	base = t.TempDir()
	layer = filepath.Join(base, "layer")
	os.Mkdir(layer, 0o755)
	os.Mkdir(filepath.Join(base, "outside"), 0o755)
	os.WriteFile(filepath.Join(base, "canary"), []byte("canary"), 0o644)
	return
}

func snapshot(t testing.TB, base string) []string {
	var out []string
	filepath.Walk(base, func(p string, fi os.FileInfo, err error) error {
		rel, _ := filepath.Rel(base, p)
		if rel == "." || rel == "layer" || strings.HasPrefix(rel, "layer"+string(filepath.Separator)) {
			return nil
		}
		out = append(out, rel)
		return nil
	})
	sort.Strings(out)
	return out
}

func assertContained(t testing.TB, base string) {
	t.Helper()
	got := strings.Join(snapshot(t, base), ",")
	if got != "canary,outside" {
		t.Fatalf("something was created outside the layer dir: %s", got)
	}
	if b, _ := os.ReadFile(filepath.Join(base, "canary")); string(b) != "canary" {
		t.Fatalf("canary modified: %q", b)
	}
}

func TestExtractRejectsEscapes(t *testing.T) {
	outside := "../outside" // relative to layer
	cases := map[string][]ent{
		"dotdot file":            {{name: "../outside/x", body: "pwn"}},
		"dotdot nested":          {{name: "a/../../outside/x", body: "pwn"}},
		"dotdot overwrite":       {{name: "../canary", body: "pwn"}},
		"dotdot dir":             {{name: "../outside/d", typ: tar.TypeDir}},
		"dotdot symlink name":    {{name: "../outside/l", typ: tar.TypeSymlink, link: "x"}},
		"write via rel symlink":  {{name: "l", typ: tar.TypeSymlink, link: outside}, {name: "l/x", body: "pwn"}},
		"write via abs symlink":  {{name: "l", typ: tar.TypeSymlink, link: "{OUT}"}, {name: "l/x", body: "pwn"}},
		"symlink chain":          {{name: "a", typ: tar.TypeSymlink, link: "b"}, {name: "b", typ: tar.TypeSymlink, link: outside}, {name: "a/x", body: "pwn"}},
		"mkdir via symlink":      {{name: "l", typ: tar.TypeSymlink, link: outside}, {name: "l/d", typ: tar.TypeDir}},
		"symlink via symlink":    {{name: "l", typ: tar.TypeSymlink, link: outside}, {name: "l/s", typ: tar.TypeSymlink, link: "q"}},
		"dir replaced by symlnk": {{name: "d", typ: tar.TypeDir}, {name: "d", typ: tar.TypeSymlink, link: outside}, {name: "d/x", body: "pwn"}},
		"hardlink dotdot":        {{name: "h", typ: tar.TypeLink, link: "../canary"}},
		"hardlink via symlink":   {{name: "l", typ: tar.TypeSymlink, link: outside}, {name: "h", typ: tar.TypeLink, link: "l/../canary"}},
		"hardlink thru symlink":  {{name: "l", typ: tar.TypeSymlink, link: ".."}, {name: "h", typ: tar.TypeLink, link: "l/canary"}},
		"whiteout dotdot":        {{name: "../outside/.wh.x"}},
		"whiteout via symlink":   {{name: "l", typ: tar.TypeSymlink, link: outside}, {name: "l/.wh.x"}},
		"opaque via symlink":     {{name: "l", typ: tar.TypeSymlink, link: outside}, {name: "l/.wh..wh..opq"}},
		"device 0:0":             {{name: "w", typ: tar.TypeChar, major: 0, min: 0}},
	}
	for name, ents := range cases {
		t.Run(name, func(t *testing.T) {
			base, layer := sandbox(t)
			for i := range ents {
				ents[i].link = strings.ReplaceAll(ents[i].link, "{OUT}", filepath.Join(base, "outside"))
			}
			// Errors are expected for most; the invariant is containment.
			_ = ExtractTar(layer, bytes.NewReader(mkTar(t, ents)), DefaultExtractOptions())
			assertContained(t, base)
		})
	}
}

// Where traversal is the *only* reason for failure we require an error.
func TestExtractErrorsOnTraversal(t *testing.T) {
	for name, ents := range map[string][]ent{
		"dotdot":   {{name: "../x", body: "1"}},
		"via link": {{name: "l", typ: tar.TypeSymlink, link: ".."}, {name: "l/x", body: "1"}},
		"hardlink": {{name: "h", typ: tar.TypeLink, link: "../canary"}},
	} {
		_, layer := sandbox(t)
		if err := ExtractTar(layer, bytes.NewReader(mkTar(t, ents)), DefaultExtractOptions()); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestExtractAbsoluteNamesAreRooted(t *testing.T) {
	base, layer := sandbox(t)
	if err := ExtractTar(layer, bytes.NewReader(mkTar(t, []ent{{name: "/etc/passwd", body: "x"}, {name: "./bin/", typ: tar.TypeDir}})), DefaultExtractOptions()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(layer, "etc/passwd")); err != nil {
		t.Fatal(err)
	}
	assertContained(t, base)
}

func TestExtractLegitSymlinksAndLinks(t *testing.T) {
	_, layer := sandbox(t)
	ents := []ent{
		{name: "bin", typ: tar.TypeDir},
		{name: "bin/busybox", body: "BB", mode: 0o755},
		{name: "bin/sh", typ: tar.TypeSymlink, link: "/bin/busybox"}, // absolute target is legitimate
		{name: "bin/ls", typ: tar.TypeLink, link: "bin/busybox"},
		{name: "etc", typ: tar.TypeDir, mode: 0o700},
		{name: "etc/shadow", body: "s", mode: 0o640},
		{name: "usr/up", typ: tar.TypeSymlink, link: "../../../../etc"}, // dangling/out-of-tree target allowed, never followed
		{name: "tmp", typ: tar.TypeDir, mode: 0o1777},
		{name: "suid", body: "x", mode: 0o4755},
		{name: "fifo", typ: tar.TypeFifo, mode: 0o600},
	}
	if err := ExtractTar(layer, bytes.NewReader(mkTar(t, ents)), DefaultExtractOptions()); err != nil {
		t.Fatal(err)
	}
	if l, _ := os.Readlink(filepath.Join(layer, "bin/sh")); l != "/bin/busybox" {
		t.Errorf("symlink = %q", l)
	}
	var a, b unix.Stat_t
	unix.Lstat(filepath.Join(layer, "bin/busybox"), &a)
	unix.Lstat(filepath.Join(layer, "bin/ls"), &b)
	if a.Ino != b.Ino || a.Nlink != 2 {
		t.Errorf("hardlink not shared: %d vs %d nlink=%d", a.Ino, b.Ino, a.Nlink)
	}
	chk := func(p string, want uint32) {
		var st unix.Stat_t
		if err := unix.Lstat(filepath.Join(layer, p), &st); err != nil {
			t.Fatal(p, err)
		}
		if st.Mode&07777 != want {
			t.Errorf("%s mode %o want %o", p, st.Mode&07777, want)
		}
	}
	chk("etc", 0o700)
	chk("etc/shadow", 0o640)
	chk("tmp", 0o1777)
	chk("suid", 0o4755)
	chk("bin/busybox", 0o755)
	var st unix.Stat_t
	unix.Lstat(filepath.Join(layer, "bin"), &st)
	if st.Mtim.Sec != 1700000000 {
		t.Errorf("dir mtime not preserved: %d", st.Mtim.Sec)
	}
	unix.Lstat(filepath.Join(layer, "fifo"), &st)
	if st.Mode&unix.S_IFMT != unix.S_IFIFO {
		t.Error("fifo missing")
	}
}

func TestExtractOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	_, layer := sandbox(t)
	ents := []ent{{name: "d", typ: tar.TypeDir, uid: 1234, gid: 4321, mode: 0o750}, {name: "d/f", body: "x", uid: 1000, gid: 2000},
		{name: "d/s", typ: tar.TypeSymlink, link: "f", uid: 7, gid: 8}}
	if err := ExtractTar(layer, bytes.NewReader(mkTar(t, ents)), DefaultExtractOptions()); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string][2]uint32{"d": {1234, 4321}, "d/f": {1000, 2000}, "d/s": {7, 8}} {
		var st unix.Stat_t
		unix.Lstat(filepath.Join(layer, p), &st)
		if st.Uid != want[0] || st.Gid != want[1] {
			t.Errorf("%s owner %d:%d want %v", p, st.Uid, st.Gid, want)
		}
	}
}

func TestExtractWhiteouts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	_, layer := sandbox(t)
	ents := []ent{
		{name: "etc", typ: tar.TypeDir},
		{name: "etc/.wh.gone"},
		{name: "var", typ: tar.TypeDir},
		{name: "var/.wh..wh..opq"},
		{name: "var/new", body: "n"},
		{name: "opq2/.wh..wh..opq"}, // opaque dir whose directory entry never appears
		{name: ".wh..wh.plnk"},      // aufs metadata ignored
	}
	if err := ExtractTar(layer, bytes.NewReader(mkTar(t, ents)), DefaultExtractOptions()); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Join(layer, "etc/gone"), &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR || st.Rdev != 0 {
		t.Errorf("whiteout not a 0:0 chardev: %v %+v", err, st)
	}
	for _, d := range []string{"var", "opq2"} {
		buf := make([]byte, 4)
		n, err := unix.Getxattr(filepath.Join(layer, d), "trusted.overlay.opaque", buf)
		if err != nil || string(buf[:n]) != "y" {
			t.Errorf("%s not opaque: %v", d, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(layer, ".wh..wh.plnk")); err == nil {
		t.Error("aufs metadata leaked")
	}
	if _, err := os.Lstat(filepath.Join(layer, "var/new")); err != nil {
		t.Error("file in opaque dir lost")
	}
}

func TestExtractXattrFiltering(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	_, layer := sandbox(t)
	ents := []ent{{name: "f", body: "x", pax: map[string]string{
		"SCHILY.xattr.user.k":                   "v",
		"SCHILY.xattr.trusted.overlay.redirect": "/etc",
		"SCHILY.xattr.trusted.overlay.opaque":   "y",
	}}, {name: "d", typ: tar.TypeDir, pax: map[string]string{"SCHILY.xattr.trusted.overlay.opaque": "y"}}}
	if err := ExtractTar(layer, bytes.NewReader(mkTar(t, ents)), DefaultExtractOptions()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if n, err := unix.Getxattr(filepath.Join(layer, "f"), "user.k", buf); err != nil || string(buf[:n]) != "v" {
		t.Errorf("user xattr lost: %v", err)
	}
	for _, p := range []string{"f", "d"} {
		for _, x := range []string{"trusted.overlay.redirect", "trusted.overlay.opaque"} {
			if _, err := unix.Getxattr(filepath.Join(layer, p), x, buf); err == nil {
				t.Errorf("%s: smuggled xattr %s present", p, x)
			}
		}
	}
}

func TestExtractReplacement(t *testing.T) {
	_, layer := sandbox(t)
	ents := []ent{
		{name: "a", typ: tar.TypeDir}, {name: "a/b", body: "1"}, {name: "a/c/d", body: "2"},
		{name: "a", body: "now a file"},                                                         // dir (non-empty) replaced by file
		{name: "x", body: "file"}, {name: "x", typ: tar.TypeDir}, {name: "x/y", body: "in dir"}, // file -> dir
		{name: "s", typ: tar.TypeSymlink, link: "t1"}, {name: "s", typ: tar.TypeSymlink, link: "t2"},
		{name: "f", body: "old"}, {name: "f", body: "new"},
	}
	if err := ExtractTar(layer, bytes.NewReader(mkTar(t, ents)), DefaultExtractOptions()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(layer, "a")); string(b) != "now a file" {
		t.Errorf("a = %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(layer, "x/y")); string(b) != "in dir" {
		t.Errorf("x/y = %q", b)
	}
	if l, _ := os.Readlink(filepath.Join(layer, "s")); l != "t2" {
		t.Errorf("s -> %q", l)
	}
	if b, _ := os.ReadFile(filepath.Join(layer, "f")); string(b) != "new" {
		t.Errorf("f = %q", b)
	}
}

func TestExtractLargeFileStreams(t *testing.T) {
	_, layer := sandbox(t)
	body := strings.Repeat("0123456789abcdef", 1<<16) // 1 MiB
	if err := ExtractTar(layer, bytes.NewReader(mkTar(t, []ent{{name: "big", body: body}})), DefaultExtractOptions()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(layer, "big")); string(b) != body {
		t.Error("content mismatch")
	}
}

func TestExtractTruncatedTar(t *testing.T) {
	_, layer := sandbox(t)
	data := mkTar(t, []ent{{name: "f", body: strings.Repeat("x", 5000)}})
	if err := ExtractTar(layer, bytes.NewReader(data[:1000]), DefaultExtractOptions()); err == nil {
		t.Error("truncated tar accepted")
	}
}

func FuzzExtract(f *testing.F) {
	f.Add(mkTar(f, []ent{{name: "a/b", body: "x"}, {name: "l", typ: tar.TypeSymlink, link: ".."}, {name: "l/c", body: "y"}}))
	f.Add(mkTar(f, []ent{{name: "d", typ: tar.TypeDir}, {name: "h", typ: tar.TypeLink, link: "../canary"}}))
	f.Add(mkTar(f, []ent{{name: "etc/.wh.x"}, {name: "etc/.wh..wh..opq"}, {name: "p", typ: tar.TypeSymlink, link: "/"}, {name: "p/q", body: "z"}}))
	f.Fuzz(func(t *testing.T, data []byte) {
		base, layer := sandbox(t)
		_ = ExtractTar(layer, bytes.NewReader(data), DefaultExtractOptions())
		assertContained(t, base)
	})
}

func TestSplitPath(t *testing.T) {
	for in, want := range map[string]string{"a/b": "a/b", "./a//b/": "a/b", "/abs/x": "abs/x", ".": "", "": ""} {
		got, err := splitPath(in)
		if err != nil || strings.Join(got, "/") != want {
			t.Errorf("%q -> %v,%v want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"..", "a/../b", "a/..", "x\x00y", "../../etc"} {
		if _, err := splitPath(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
