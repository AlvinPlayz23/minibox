//go:build linux

package cgroup

import "testing"

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"64m": 64 << 20, "1G": 1 << 30, "512k": 512 << 10, "100": 100} {
		got, err := ParseSize(in)
		if err != nil || got != want {
			t.Errorf("%s: got %d,%v want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "m", "-1m", "abc", "0"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}
