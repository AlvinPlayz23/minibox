//go:build integration

package integration

import (
	"path/filepath"
	"syscall"
)

const syscallSIGTERM = syscall.SIGTERM

func mustAbs(t interface{ Fatal(...any) }, p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
