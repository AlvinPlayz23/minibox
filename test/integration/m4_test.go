//go:build integration

package integration

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"minibox/internal/image"
)

type f struct {
	name, body, link string
	typ              byte
}

func tarOf(t *testing.T, files []f) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, x := range files {
		typ := x.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: x.name, Typeflag: typ, Mode: 0o755, Linkname: x.link, ModTime: time.Unix(1700000000, 0)}
		if typ == tar.TypeReg {
			h.Size = int64(len(x.body))
			h.Mode = 0o644
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(x.body))
		}
	}
	tw.Close()
	return b.Bytes()
}

// busybox-based base layer so containers have a shell.
func baseLayer(t *testing.T) []byte {
	rootfs := "../../rootfs"
	if _, err := os.Stat(rootfs + "/bin/busybox"); err != nil {
		t.Skip("run bench/fetch-rootfs.sh first")
	}
	out, err := exec.Command("tar", "-C", rootfs, "-cf", "-", ".").Output()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func newRoot(t *testing.T) *image.Store {
	root := t.TempDir()
	t.Setenv("MINIBOX_ROOT", root)
	return &image.Store{Root: root}
}

// build an image from layer tars (bottom first).
func build(t *testing.T, s *image.Store, name string, layers ...[]byte) {
	img := &image.Image{Config: image.Config{Cmd: []string{"/bin/sh"}}}
	parent := ""
	for _, l := range layers {
		ly, err := s.UnpackLayer(parent, bytes.NewReader(l), image.DefaultExtractOptions())
		if err != nil {
			t.Fatal(err)
		}
		img.Layers = append(img.Layers, image.ImageLayer{DiffID: ly.DiffID, ChainID: ly.ChainID})
		parent = ly.ChainID
	}
	if err := s.SaveImage(img, name); err != nil {
		t.Fatal(err)
	}
}

func runImg(t *testing.T, args ...string) (string, error) {
	t.Helper()
	return mb(t, append([]string{"run-raw"}, args...)...)
}

func noLeaks(t *testing.T) {
	t.Helper()
	leaked(t)
	if m, _ := os.ReadFile("/proc/self/mountinfo"); strings.Contains(string(m), "overlay") && strings.Contains(string(m), "minibox") {
		t.Error("overlay mount leaked on host")
	}
}

func TestOverlayWhiteoutAndOpaque(t *testing.T) {
	s := newRoot(t)
	l1 := baseLayer(t)
	l2 := tarOf(t, []f{
		{name: "a", typ: tar.TypeDir}, {name: "a/f1", body: "1"}, {name: "a/f2", body: "2"},
		{name: "d", typ: tar.TypeDir}, {name: "d/x", body: "x"}, {name: "d/y", body: "y"},
		{name: "keep", body: "k"}, {name: "sub", typ: tar.TypeDir}, {name: "sub/gone", body: "g"},
	})
	l3 := tarOf(t, []f{
		{name: "a/.wh.f1"},                                 // delete a/f1
		{name: "d/.wh..wh..opq"}, {name: "d/z", body: "z"}, // replace d wholesale
		{name: ".wh.keep"}, // delete top-level file
		{name: ".wh.sub"},  // delete a whole directory
		{name: "new", body: "n"},
	})
	build(t, s, "app", l1, l2, l3)
	out, err := runImg(t, "--image", "app", "/bin/sh", "-c", "echo A:$(ls /a); echo D:$(ls /d); ls /keep /sub 2>&1 | wc -l; echo N:$(cat /new)")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, w := range []string{"A:f2\n", "D:z\n", "N:n"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
	if !strings.Contains(out, "\n2\n") { // two "No such file" lines
		t.Errorf("deleted paths still visible:\n%s", out)
	}
	// The shared layers still hold the original content.
	low, _ := s.LowerDirs(mustImg(t, s, "app"))
	if _, err := os.Lstat(filepath.Join(low[1].Dir, "keep")); err != nil {
		t.Errorf("layer 2 modified by upper deletions: %v", err)
	}
	noLeaks(t)
}

func TestContainerWritesAreIsolated(t *testing.T) {
	s := newRoot(t)
	build(t, s, "app", baseLayer(t))
	// c1 writes, modifies and deletes; keep its upper dir.
	out, err := runImg(t, "--image", "app", "--keep", "/bin/sh", "-c", "echo c1 > /only-c1; echo hacked >> /etc/os-release; rm /etc/hostname; mkdir /newdir")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// c2 must see pristine image.
	out, err = runImg(t, "--image", "app", "/bin/sh", "-c", "ls /only-c1 /newdir 2>&1 | wc -l; grep -c hacked /etc/os-release; ls /etc/hostname")
	if err != nil {
		t.Logf("c2 err (ls of missing/present): %v", err)
	}
	if !strings.HasPrefix(out, "2\n0\n") {
		t.Errorf("c1's writes visible in c2:\n%s", out)
	}
	// And the shared layer dir is untouched.
	lowers, _ := s.LowerDirs(mustImg(t, s, "app"))
	for _, p := range []string{"only-c1", "newdir"} {
		if _, err := os.Lstat(filepath.Join(lowers[0].Dir, p)); err == nil {
			t.Errorf("%s leaked into image layer", p)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(lowers[0].Dir, "etc/os-release")); strings.Contains(string(b), "hacked") {
		t.Error("copy-up modified the lower layer")
	}
	noLeaks(t)
}

func mustImg(t *testing.T, s *image.Store, n string) *image.Image {
	img, err := s.GetImage(n)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func dirBytes(p string) int64 {
	var n int64
	filepath.Walk(p, func(_ string, fi os.FileInfo, err error) error {
		if err == nil {
			n += fi.Size()
		}
		return nil
	})
	return n
}

func TestSecondContainerDiskUsageNearZero(t *testing.T) {
	s := newRoot(t)
	big := tarOf(t, []f{{name: "big.bin", body: strings.Repeat("z", 20<<20)}})
	build(t, s, "app", baseLayer(t), big)
	for i := 0; i < 2; i++ {
		if out, err := runImg(t, "--image", "app", "--keep", "/bin/true"); err != nil {
			t.Fatalf("%v %s", err, out)
		}
	}
	ents, _ := os.ReadDir(filepath.Join(s.Root, "containers"))
	if len(ents) != 2 {
		t.Fatalf("want 2 containers, got %d", len(ents))
	}
	layers := dirBytes(filepath.Join(s.Root, "layers"))
	for _, e := range ents {
		c := dirBytes(filepath.Join(s.Root, "containers", e.Name()))
		t.Logf("container %s: %d bytes, layers: %d bytes", e.Name()[:12], c, layers)
		if c > 64<<10 {
			t.Errorf("container uses %d bytes; expected ~0", c)
		}
	}
	// du(1) agrees.
	out, _ := exec.Command("du", "-sk", filepath.Join(s.Root, "containers")).Output()
	t.Logf("du containers: %s", strings.TrimSpace(string(out)))
}

func TestManyLayersUseShortLinks(t *testing.T) {
	s := newRoot(t)
	layers := [][]byte{baseLayer(t)}
	const n = 126 // 127 layers total: Docker's own maximum
	for i := 0; i < n; i++ {
		layers = append(layers, tarOf(t, []f{{name: "l", typ: tar.TypeDir}, {name: fmt.Sprintf("l/f%03d", i), body: "x"}}))
	}
	build(t, s, "deep", layers...)
	// Prove the plain option string would NOT have fit.
	low, _ := s.LowerDirs(mustImg(t, s, "deep"))
	plain := 0
	for _, l := range low {
		plain += len(l.Dir) + 1
	}
	if plain < 4096 {
		t.Fatalf("test invalid: plain option string only %d bytes", plain)
	}
	out, err := runImg(t, "--image", "deep", "/bin/sh", "-c", "ls /l | wc -l; cat /l/f000 /l/f125; ls /bin/sh")
	if err != nil || !strings.HasPrefix(out, fmt.Sprintf("%d\nxx/bin/sh", n)) {
		t.Fatalf("err=%v out=%q (plain opts %d bytes)", err, out, plain)
	}
	noLeaks(t)
}

// Beyond what fits in one classic mount string the new mount API path is used;
// layer ORDER must be preserved (top layer wins).
func TestVeryManyLayersOrderPreserved(t *testing.T) {
	s := newRoot(t)
	layers := [][]byte{baseLayer(t)}
	for i := 0; i < 300; i++ {
		layers = append(layers, tarOf(t, []f{{name: "v", body: fmt.Sprint(i)}, {name: fmt.Sprintf("f%d", i), body: "x"}}))
	}
	build(t, s, "very", layers...)
	out, err := runImg(t, "--image", "very", "/bin/sh", "-c", "cat /v; ls / | grep -c '^f[0-9]'")
	if err != nil || out != "299300\n" && out != "299\n300\n" {
		t.Fatalf("err=%v out=%q", err, out)
	}
	noLeaks(t)
}

func TestBeyondKernelLayerLimitFailsClearly(t *testing.T) {
	s := newRoot(t)
	layers := [][]byte{baseLayer(t)}
	for i := 0; i < 520; i++ {
		layers = append(layers, tarOf(t, []f{{name: fmt.Sprintf("f%d", i), body: "x"}}))
	}
	build(t, s, "toodeep", layers...)
	out, err := runImg(t, "--image", "toodeep", "/bin/true")
	if err == nil || !strings.Contains(out, "too many layers") {
		t.Fatalf("expected clear failure, got err=%v out=%q", err, out)
	}
	noLeaks(t)
}

func TestLoadCLIAndRun(t *testing.T) {
	s := newRoot(t)
	tmp := filepath.Join(t.TempDir(), "rootfs.tar")
	os.WriteFile(tmp, baseLayer(t), 0o644)
	if out, err := mb(t, "load", "-i", tmp, "alpine:3"); err != nil || !strings.Contains(out, "Loaded local/alpine:3") {
		t.Fatalf("%v %s", err, out)
	}
	out, err := runImg(t, "--image", "alpine:3", "/bin/sh", "-c", "echo $PATH; hostname; ps | wc -l")
	if err != nil || !strings.Contains(out, "/usr/bin") {
		t.Fatalf("%v %s", err, out)
	}
	if _, err := s.GetImage("alpine:3"); err != nil {
		t.Fatal(err)
	}
	// bad names are rejected and create nothing
	for _, bad := range []string{"../evil", "A/B", "x:../y"} {
		if _, err := mb(t, "load", "-i", tmp, bad); err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
	if _, err := os.Stat(filepath.Join(s.Root, "..", "evil")); err == nil {
		t.Error("escaped MINIBOX_ROOT")
	}
	// unknown image: helpful error
	if out, err := runImg(t, "--image", "nope", "/bin/true"); err == nil || !strings.Contains(out, "minibox load") {
		t.Errorf("unhelpful error: %v %s", err, out)
	}
	noLeaks(t)
}

func TestConcurrentContainersSameImage(t *testing.T) {
	s := newRoot(t)
	build(t, s, "app", baseLayer(t))
	var wg sync.WaitGroup
	fails := make(chan string, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out, err := runImg(t, "--image", "app", "/bin/sh", "-c", fmt.Sprintf("echo %d > /w; cat /w", i))
			if err != nil || strings.TrimSpace(out) != fmt.Sprint(i) {
				fails <- fmt.Sprintf("%d: %v %q", i, err, out)
			}
		}(i)
	}
	wg.Wait()
	close(fails)
	for m := range fails {
		t.Error(m)
	}
	if ents, _ := os.ReadDir(filepath.Join(s.Root, "containers")); len(ents) != 0 {
		t.Errorf("container dirs leaked: %d", len(ents))
	}
	noLeaks(t)
}

func TestKilledSupervisorThenPrune(t *testing.T) {
	s := newRoot(t)
	build(t, s, "app", baseLayer(t))
	cmd := exec.Command("../../bin/minibox", "run-raw", "--image", "app", "--memory", "64m", "/bin/sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(700 * time.Millisecond)
	if ents, _ := os.ReadDir(filepath.Join(s.Root, "containers")); len(ents) != 1 {
		t.Fatalf("expected live container dir")
	}
	if out, _ := mb(t, "system", "prune"); !strings.Contains(out, "removed 0") {
		t.Errorf("prune touched a live container: %s", out)
	}
	cmd.Process.Kill()
	cmd.Wait()
	time.Sleep(300 * time.Millisecond)
	if out, err := mb(t, "system", "prune"); err != nil || strings.Contains(out, "removed 0") {
		t.Errorf("prune did nothing: %v %s", err, out)
	}
	if ents, _ := os.ReadDir(filepath.Join(s.Root, "containers")); len(ents) != 0 {
		t.Errorf("container dir survived prune")
	}
	noLeaks(t)
}
