//go:build linux

package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveInRoot(t *testing.T) {
	root := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(root+"/etc", 0o755))
	must(os.MkdirAll(root+"/real/data", 0o755))
	must(os.Symlink("/real", root+"/link"))           // absolute: must stay inside root
	must(os.Symlink("../../../../etc", root+"/up"))   // relative escape attempt
	must(os.Symlink("/../../../../etc", root+"/up2")) // absolute with ..
	must(os.Symlink("/etc/passwd", root+"/etc/pw"))   // symlink to a missing file
	must(os.Symlink("loop2", root+"/loop1"))
	must(os.Symlink("loop1", root+"/loop2"))
	cases := map[string]string{
		"/etc":               "/etc",
		"/link/data":         "/real/data",
		"/link/data/new/x":   "/real/data/new/x",
		"/up":                "/etc",
		"/up/../../../etc":   "/etc",
		"/up2":               "/etc",
		"/../../..":          "",
		"/a/../b":            "/b",
		"/etc/pw":            "/etc/passwd",
		"/missing/../etc":    "/etc",
		"/link/../real/data": "/real/data",
	}
	for in, want := range cases {
		got, err := ResolveInRoot(root, in)
		if err != nil || got != root+want {
			t.Errorf("%q => %q, %v; want %q", in, got, err, root+want)
		}
		if rel, _ := filepath.Rel(root, got); len(rel) >= 2 && rel[:2] == ".." {
			t.Errorf("%q escaped root: %s", in, got)
		}
	}
	if _, err := ResolveInRoot(root, "/loop1"); err == nil {
		t.Error("symlink loop accepted")
	}
	if _, err := ResolveInRoot(root, "relative"); err == nil {
		t.Error("relative path accepted")
	}
}

func TestResolveInRootNoEscapeThroughMissing(t *testing.T) {
	root := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(root+"/etc", 0o755))
	// Existing absolute symlink: a ".." after a missing component must not
	// climb back through it onto the host.
	must(os.Symlink("/etc", root+"/a"))
	for _, in := range []string{"/missing/../a/evil", "/missing/../../a", "/x/y/../../a/evil/deep"} {
		got, err := ResolveInRoot(root, in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		// The resolved path must stay inside root, never name the host's /etc.
		if rel, _ := filepath.Rel(root, got); len(rel) >= 2 && rel[:2] == ".." {
			t.Errorf("%q escaped root: %s", in, got)
		}
		if got == "/etc/evil" || strings.HasPrefix(got, "/etc/") {
			t.Errorf("%q resolved to host path %s", in, got)
		}
	}
	got, err := ResolveInRoot(root, "/missing/../a/evil")
	if err != nil || got != root+"/etc/evil" {
		t.Errorf("got %q, %v; want %q", got, err, root+"/etc/evil")
	}
}

func TestUnescapeMountpoint(t *testing.T) {
	for in, want := range map[string]string{
		"/plain":          "/plain",
		"/with\\040space": "/with space",
		"/tab\\011x":      "/tab\tx",
		"/nl\\012x":       "/nl\nx",
		"/bs\\134x":       `/bs\x`,
		"/bad\\xyz":       `/bad\xyz`,
		"/trailing\\":     `/trailing\`,
		"/oct\\101bc":     "/octAbc",
	} {
		if got := unescapeMountpoint(in); got != want {
			t.Errorf("%q => %q, want %q", in, got, want)
		}
	}
}

func TestParseVolume(t *testing.T) {
	vol := func(name string) (string, error) { return "/vols/" + name, nil }
	ok := map[string]Mount{
		"/host:/data":        {Type: "bind", Src: "/host", Dst: "/data"},
		"/host:/data:ro":     {Type: "bind", Src: "/host", Dst: "/data", RO: true},
		"/host:/data:rw":     {Type: "bind", Src: "/host", Dst: "/data"},
		"mydata:/data":       {Type: "bind", Src: "/vols/mydata", Dst: "/data"},
		"mydata:/data:ro":    {Type: "bind", Src: "/vols/mydata", Dst: "/data", RO: true},
		"./rel:/data":        {Type: "bind", Src: "./rel", Dst: "/data"},
		"/f.txt:/etc/app:ro": {Type: "bind", Src: "/f.txt", Dst: "/etc/app", RO: true},
	}
	for in, want := range ok {
		got, err := ParseVolume(in, vol)
		if err != nil || got != want {
			t.Errorf("%q => %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "/onlyone", "a:b:c:d", ":/data", "/src:", "/src:relative", "/src:/d:bogus"} {
		if _, err := ParseVolume(bad, vol); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseTmpfs(t *testing.T) {
	m, err := ParseTmpfs("/run:size=64m")
	if err != nil || m != (Mount{Type: "tmpfs", Dst: "/run", Size: "64m"}) {
		t.Errorf("%+v %v", m, err)
	}
	m, err = ParseTmpfs("/tmp:size=10m,ro")
	if err != nil || !m.RO || m.Size != "10m" {
		t.Errorf("%+v %v", m, err)
	}
	for _, bad := range []string{"", "relative", "/d:bogus", "/d:size="} {
		if _, err := ParseTmpfs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
