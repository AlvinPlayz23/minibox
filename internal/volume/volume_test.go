//go:build linux

package volume

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVolumeLifecycle(t *testing.T) {
	root := t.TempDir()
	p, err := Ensure(root, "data")
	if err != nil || p != DataDir(root, "data") {
		t.Fatalf("%q %v", p, err)
	}
	if _, err := os.Stat(filepath.Join(p, ".")); err != nil {
		t.Fatal(err)
	}
	// Idempotent.
	if _, err := Ensure(root, "data"); err != nil {
		t.Fatal(err)
	}
	if !Exists(root, "data") || Exists(root, "missing") {
		t.Error("exists check")
	}
	if len(List(root)) != 1 || List(root)[0].Name != "data" {
		t.Errorf("%v", List(root))
	}
	for _, bad := range []string{"", ".x", "-x", "a/b", "a b"} {
		if _, err := Ensure(root, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := Remove(root, "missing"); err == nil {
		t.Error("removed missing volume")
	}
	if err := Remove(root, "data"); err != nil {
		t.Fatal(err)
	}
	if len(List(root)) != 0 {
		t.Error("volume not removed")
	}
}

func TestIsNamedVolumeSource(t *testing.T) {
	for src, want := range map[string]bool{
		"data": true, "my-vol.1": true, "/host": false,
		"./rel": false, "a/b": false, "": false,
	} {
		if got := IsNamedVolumeSource(src); got != want {
			t.Errorf("%q => %v", src, got)
		}
	}
}
