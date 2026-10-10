//go:build linux

// Package security implements capability dropping, no_new_privs and a pure-Go seccomp BPF
// generator (no libseccomp, no cgo).
package security

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// capNames is indexed by capability number.
var capNames = []string{"CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "KILL", "SETGID", "SETUID",
	"SETPCAP", "LINUX_IMMUTABLE", "NET_BIND_SERVICE", "NET_BROADCAST", "NET_ADMIN", "NET_RAW", "IPC_LOCK", "IPC_OWNER",
	"SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT", "SYS_PTRACE", "SYS_PACCT", "SYS_ADMIN", "SYS_BOOT", "SYS_NICE",
	"SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG", "MKNOD", "LEASE", "AUDIT_WRITE", "AUDIT_CONTROL", "SETFCAP",
	"MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG", "WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ", "PERFMON", "BPF", "CHECKPOINT_RESTORE"}

// DefaultCaps is Docker's default capability set.
var DefaultCaps = []string{"CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "MKNOD", "NET_RAW", "SETGID", "SETUID",
	"SETFCAP", "SETPCAP", "NET_BIND_SERVICE", "SYS_CHROOT", "KILL", "AUDIT_WRITE"}

func normCap(s string) (string, error) {
	n := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "CAP_")
	if n == "ALL" {
		return n, nil
	}
	for _, c := range capNames {
		if c == n {
			return n, nil
		}
	}
	return "", fmt.Errorf("unknown capability %q; see capabilities(7), e.g. NET_ADMIN, SYS_PTRACE, or ALL", s)
}

// ResolveCaps applies --cap-drop then --cap-add (Docker's order: drop first) to the default set.
func ResolveCaps(add, drop []string) ([]string, error) {
	set := map[string]bool{}
	for _, c := range DefaultCaps {
		set[c] = true
	}
	all := func(v bool) {
		for _, c := range capNames {
			set[c] = v
		}
	}
	for _, d := range drop {
		n, err := normCap(d)
		if err != nil {
			return nil, err
		}
		if n == "ALL" {
			all(false)
		} else {
			delete(set, n)
		}
	}
	for _, a := range add {
		n, err := normCap(a)
		if err != nil {
			return nil, err
		}
		if n == "ALL" {
			all(true)
		} else {
			set[n] = true
		}
	}
	out := []string{} // non-nil even when empty: nil means "leave capabilities untouched"
	for c, ok := range set {
		if ok {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out, nil
}

func capNum(name string) int {
	for i, c := range capNames {
		if c == name {
			return i
		}
	}
	return -1
}

// capLastCap reads the host kernel's last capability ID from
// /proc/sys/kernel/cap_last_cap (38+ on modern kernels).
func capLastCap() (int, error) {
	b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n < 0 || n > 63 {
		return 0, fmt.Errorf("bad cap_last_cap %q", b)
	}
	return n, nil
}

// ApplyCaps restricts the calling thread (and so everything it execs or forks) to keep:
// bounding set, permitted, effective and inheritable are all reduced to it; ambient is cleared.
// Call it on a thread locked with runtime.LockOSThread, right before exec/fork.
// Capabilities the host kernel does not know (e.g. --cap-add ALL on Linux 5.7)
// are clamped to cap_last_cap instead of failing capset.
func ApplyCaps(keep []string) error {
	var mask uint64
	for _, c := range keep {
		if n := capNum(c); n >= 0 {
			mask |= 1 << uint(n)
		}
	}
	if last, err := capLastCap(); err == nil && last < 63 {
		mask &= (uint64(1) << (uint(last) + 1)) - 1
	}
	for c := 0; c < 64; c++ {
		if mask&(1<<uint(c)) != 0 {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil {
			if err == unix.EINVAL { // beyond the kernel's last capability
				break
			}
			return fmt.Errorf("drop capability %d from bounding set: %w", c, err)
		}
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{
		{Effective: uint32(mask), Permitted: uint32(mask), Inheritable: uint32(mask)},
		{Effective: uint32(mask >> 32), Permitted: uint32(mask >> 32), Inheritable: uint32(mask >> 32)},
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	_ = unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
	return nil
}

// NoNewPrivs sets PR_SET_NO_NEW_PRIVS: execve can never grant more privilege (setuid, file caps).
func NoNewPrivs() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	return nil
}
