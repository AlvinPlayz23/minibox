//go:build linux

package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func sum(s string) string { h := sha256.Sum256([]byte(s)); return "sha256:" + hex.EncodeToString(h[:]) }

func TestChainID(t *testing.T) {
	d1, d2, d3 := sum("a"), sum("b"), sum("c")
	if ChainID("", d1) != d1 {
		t.Error("base chain must equal diffID")
	}
	c2 := ChainID(d1, d2)
	if c2 != sum(d1+" "+d2) {
		t.Error("chain(2) wrong")
	}
	if ChainID(c2, d3) != sum(c2+" "+d3) {
		t.Error("chain(3) wrong")
	}
	if ChainID(d2, d1) == c2 {
		t.Error("chain must be order dependent")
	}
}

func TestParseDigest(t *testing.T) {
	good := sum("x")
	if _, err := ParseDigest(good); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"", "sha256:", "sha256:zz", "sha512:" + strings.Repeat("a", 64), strings.TrimPrefix(good, "sha256:"),
		"sha256:" + strings.Repeat("A", 64), "sha256:../../" + strings.Repeat("a", 52), good + "0"} {
		if _, err := ParseDigest(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestPutBlobVerifies(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	data := "hello blob"
	d, n, err := s.PutBlob(strings.NewReader(data), sum(data))
	if err != nil || n != int64(len(data)) || d != sum(data) || !s.HasBlob(d) {
		t.Fatalf("put: %v %d %s", err, n, d)
	}
	if err := s.VerifyBlob(d); err != nil {
		t.Fatal(err)
	}
	// wrong digest -> rejected, nothing stored, no temp left
	if _, _, err := s.PutBlob(strings.NewReader("tampered"), sum(data+"x")); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected mismatch, got %v", err)
	}
	ents, _ := os.ReadDir(s.blobsDir())
	if len(ents) != 1 {
		t.Fatalf("leftover files in blob dir: %v", ents)
	}
	// corrupt a stored blob (flip a byte) -> VerifyBlob catches it
	p, _ := s.BlobPath(d)
	b, _ := os.ReadFile(p)
	b[0] ^= 1
	os.WriteFile(p, b, 0o644)
	if err := s.VerifyBlob(d); err == nil {
		t.Fatal("corruption not detected")
	}
}

func TestImageNameValidation(t *testing.T) {
	s := &Store{Root: "/r"}
	for _, bad := range []string{"", "../x", "a/../b", "/abs", "A/upper", "a b", "a:", "a:../x", "a//b", "a/./b", "-x", "x:tag/with/slash"} {
		if _, _, err := s.imagePath(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	p, canon, err := s.imagePath("team/app:1.0")
	if err != nil || p != "/r/images/docker.io/team/app/1.0.json" || canon != "docker.io/team/app:1.0" {
		t.Errorf("%s %s %v", p, canon, err)
	}
	if _, canon, _ := s.imagePath("alpine"); canon != "docker.io/library/alpine:latest" {
		t.Error(canon)
	}
}

func rootfsTar(t *testing.T, ents []ent, gz bool) []byte {
	raw := mkTar(t, ents)
	if !gz {
		return raw
	}
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write(raw)
	w.Close()
	return b.Bytes()
}

func TestLoadTarPlainAndGzipSameImage(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	ents := []ent{{name: "bin", typ: tar.TypeDir}, {name: "bin/hello", body: "hi", mode: 0o755}}
	plain, gz := rootfsTar(t, ents, false), rootfsTar(t, ents, true)
	i1, err := s.LoadTar(bytes.NewReader(plain), "app", Config{})
	if err != nil {
		t.Fatal(err)
	}
	i2, err := s.LoadTar(bytes.NewReader(gz), "app2:v1", Config{})
	if err != nil {
		t.Fatal(err)
	}
	// Same uncompressed content => same diffID/chainID, shared layer; different blobs.
	if i1.Layers[0].ChainID != i2.Layers[0].ChainID {
		t.Error("layers should be deduplicated")
	}
	if i1.Layers[0].Blob == i2.Layers[0].Blob {
		t.Error("blobs (compressed bytes) should differ")
	}
	if i1.Layers[0].Blob != sum(string(plain)) || i2.Layers[0].Blob != sum(string(gz)) {
		t.Error("blob digest must be sha256 of the input bytes")
	}
	if err := s.VerifyBlob(i2.Layers[0].Blob); err != nil {
		t.Error(err)
	}
	ents2, _ := os.ReadDir(s.layersDir())
	n := 0
	for _, e := range ents2 {
		if e.IsDir() && e.Name() != "l" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("want 1 layer dir, got %d (%v)", n, ents2)
	}
	got, err := s.GetImage("app2:v1")
	if err != nil || got.Config.Cmd[0] != "/bin/sh" {
		t.Errorf("%v %+v", err, got)
	}
	if b, _ := os.ReadFile(filepath.Join(s.Root, "layers", strings.TrimPrefix(i1.Layers[0].ChainID, "sha256:"), "diff/bin/hello")); string(b) != "hi" {
		t.Error("content")
	}
}

func TestLoadTarFailuresLeaveNothingBehind(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	good := rootfsTar(t, []ent{{name: "f", body: strings.Repeat("x", 100000)}}, true)
	cases := map[string][]byte{
		"truncated gzip": good[:len(good)/2],
		"flipped byte":   append(append([]byte{}, good[:len(good)/2]...), append([]byte{good[len(good)/2] ^ 0xff}, good[len(good)/2+1:]...)...),
		"garbage":        []byte("this is not a tar archive at all, not even close........................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................."),
		"escape":         rootfsTar(t, []ent{{name: "../../evil", body: "x"}}, true),
		"zstd":           {0x28, 0xb5, 0x2f, 0xfd, 0, 0, 0, 0},
	}
	for name, data := range cases {
		if _, err := s.LoadTar(bytes.NewReader(data), "bad", Config{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var left []string
	filepath.Walk(s.Root, func(p string, fi os.FileInfo, err error) error {
		if !fi.IsDir() {
			left = append(left, p)
		}
		return nil
	})
	if len(left) != 0 {
		t.Errorf("failed loads left files: %v", left)
	}
	if _, err := s.GetImage("bad"); err == nil {
		t.Error("image record created for failed load")
	}
}

func TestUnpackLayerConcurrentSame(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	data := mkTar(t, []ent{{name: "a", body: "1"}, {name: "d", typ: tar.TypeDir}})
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	ids := make(chan string, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := s.UnpackLayer("", bytes.NewReader(data), DefaultExtractOptions())
			if err != nil {
				errs <- err
				return
			}
			ids <- l.ChainID
		}()
	}
	wg.Wait()
	close(errs)
	close(ids)
	for e := range errs {
		t.Error(e)
	}
	seen := map[string]bool{}
	for id := range ids {
		seen[id] = true
	}
	if len(seen) != 1 {
		t.Errorf("chain ids differ: %v", seen)
	}
	ents, _ := os.ReadDir(s.layersDir())
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("temp dir left: %s", e.Name())
		}
	}
}
