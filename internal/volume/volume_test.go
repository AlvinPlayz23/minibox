//go:build linux

package volume

import (
	"os"
	"path/filepath"
	"testing"
)

func mustList(t *testing.T, root string) []Info {
	t.Helper()
	infos, err := List(root)
	if err != nil {
		t.Fatal(err)
	}
	return infos
}

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
	if infos := mustList(t, root); len(infos) != 1 || infos[0].Name != "data" {
		t.Errorf("%v", infos)
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
	if infos := mustList(t, root); len(infos) != 0 {
		t.Error("volume not removed")
	}
}

func TestListMissingDirIsEmpty(t *testing.T) {
	infos, err := List(filepath.Join(t.TempDir(), "no-such-root"))
	if err != nil || len(infos) != 0 {
		t.Errorf("%v %v", infos, err)
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

func TestLockSerializes(t *testing.T) {
	root := t.TempDir()
	unlock, err := Lock(root)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	// Creation still works while the lock is held by us.
	if _, err := Ensure(root, "v"); err != nil {
		t.Fatal(err)
	}
	if infos := mustList(t, root); len(infos) != 1 {
		t.Errorf("%v", infos)
	}
}
