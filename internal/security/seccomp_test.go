//go:build linux && (amd64 || arm64)

package security

import (
	"syscall"
	"testing"
)

// run interprets the cBPF program against a syscall (arch, nr, arg0 low word).
func run(t *testing.T, prog []insn, arch, nr, arg0 uint32) uint32 {
	t.Helper()
	var a uint32
	for pc := 0; pc < len(prog); pc++ {
		i := prog[pc]
		switch i.Code {
		case bpfLdAbsW:
			switch i.K {
			case offArch:
				a = arch
			case offNr:
				a = nr
			case offArg0Lo:
				a = arg0
			default:
				t.Fatalf("bad load offset %d", i.K)
			}
		case bpfJEQ, bpfJGE, bpfJSET:
			var cond bool
			switch i.Code {
			case bpfJEQ:
				cond = a == i.K
			case bpfJGE:
				cond = a >= i.K
			case bpfJSET:
				cond = a&i.K != 0
			}
			if cond {
				pc += int(i.Jt)
			} else {
				pc += int(i.Jf)
			}
		case bpfRet:
			return i.K
		default:
			t.Fatalf("unknown opcode %#x", i.Code)
		}
	}
	t.Fatal("fell off the program")
	return 0
}

func TestFilterVerdicts(t *testing.T) {
	def, err := BuildFilter(DefaultCaps)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d instructions", len(def))
	for name, want := range map[string]uint32{
		"read": retAllow, "write": retAllow, "execve": retAllow, "openat": retAllow, "futex": retAllow, "socket": retAllow,
		"mount": errnoRet(syscall.EPERM), "umount2": errnoRet(syscall.EPERM), "unshare": errnoRet(syscall.EPERM),
		"setns": errnoRet(syscall.EPERM), "ptrace": errnoRet(syscall.EPERM), "bpf": errnoRet(syscall.EPERM),
		"init_module": errnoRet(syscall.EPERM), "reboot": errnoRet(syscall.EPERM), "keyctl": errnoRet(syscall.EPERM),
		"clone3": errnoRet(syscall.ENOSYS), "io_uring_setup": errnoRet(syscall.EPERM),
	} {
		nr, ok := sysnums[name]
		if !ok {
			continue // not on this architecture
		}
		if got := run(t, def, auditArch, nr, 0); got != want {
			t.Errorf("%s: got %#x want %#x", name, got, want)
		}
	}
	// Every known syscall must get a verdict consistent with the blocked table.
	for name, nr := range sysnums {
		want := uint32(retAllow)
		if _, bl := blocked[name]; bl {
			want = errnoRet(syscall.EPERM)
		}
		if name == "clone3" {
			want = errnoRet(syscall.ENOSYS)
		}
		if name == "clone" {
			continue
		}
		if got := run(t, def, auditArch, nr, 0); got != want {
			t.Errorf("%s(%d): got %#x want %#x", name, nr, got, want)
		}
	}
	// Unknown syscall numbers and wrong architectures are refused.
	if got := run(t, def, auditArch, 9999, 0); got != errnoRet(syscall.EPERM) {
		t.Errorf("unknown nr: %#x", got)
	}
	if got := run(t, def, 0x40000003, sysnums["read"], 0); got != retKill {
		t.Errorf("foreign arch: %#x", got)
	}
	// clone: plain thread/fork flags pass, namespace flags don't.
	if nr, ok := sysnums["clone"]; ok {
		if got := run(t, def, auditArch, nr, 0x00010f00); got != retAllow { // CLONE_VM|FS|FILES|SIGHAND|THREAD...
			t.Errorf("plain clone: %#x", got)
		}
		for _, f := range []uint32{cloneNSFlags, 0x10000000 /* NEWUSER */, 0x20000000 /* NEWPID */, 0x40000000 /* NEWNET */, 0x00020000 /* NEWNS */} {
			if got := run(t, def, auditArch, nr, f); got != errnoRet(syscall.EPERM) {
				t.Errorf("clone %#x: %#x", f, got)
			}
		}
	}
	// personality: only the default domains and persona-get pass.
	if nr, ok := sysnums["personality"]; ok {
		for arg, want := range map[uint32]uint32{
			0: retAllow, 8: retAllow, 0xffffffff: retAllow,
			0x00040000 /* ADDR_NO_RANDOMIZE */ : errnoRet(syscall.EPERM),
			0x00080000 /* READ_IMPLIES_EXEC */ : errnoRet(syscall.EPERM),
			0x010000 /* ADDR_COMPAT_LAYOUT */ :  errnoRet(syscall.EPERM),
		} {
			if got := run(t, def, auditArch, nr, arg); got != want {
				t.Errorf("personality(%#x): got %#x want %#x", arg, got, want)
			}
		}
	}
	// syslog needs CAP_SYSLOG, which is not in the default set.
	if nr, ok := sysnums["syslog"]; ok {
		if got := run(t, def, auditArch, nr, 0); got != errnoRet(syscall.EPERM) {
			t.Errorf("syslog default: %#x", got)
		}
		sys, _ := BuildFilter(append([]string{"SYSLOG"}, DefaultCaps...))
		if got := run(t, sys, auditArch, nr, 0); got != retAllow {
			t.Errorf("syslog with SYSLOG: %#x", got)
		}
	}
	// With SYS_ADMIN the mount family is allowed again.
	adm, _ := BuildFilter(append([]string{"SYS_ADMIN"}, DefaultCaps...))
	if got := run(t, adm, auditArch, sysnums["mount"], 0); got != retAllow {
		t.Errorf("mount with SYS_ADMIN: %#x", got)
	}
	if got := run(t, adm, auditArch, sysnums["ptrace"], 0); got != errnoRet(syscall.EPERM) {
		t.Errorf("ptrace without SYS_PTRACE: %#x", got)
	}
}

func TestResolveCaps(t *testing.T) {
	c, err := ResolveCaps([]string{"net_admin", "CAP_SYS_PTRACE"}, []string{"MKNOD", "cap_chown"})
	if err != nil {
		t.Fatal(err)
	}
	has := map[string]bool{}
	for _, x := range c {
		has[x] = true
	}
	if !has["NET_ADMIN"] || !has["SYS_PTRACE"] || has["MKNOD"] || has["CHOWN"] || !has["KILL"] {
		t.Errorf("%v", c)
	}
	if c, _ := ResolveCaps([]string{"NET_BIND_SERVICE"}, []string{"ALL"}); len(c) != 1 {
		t.Errorf("drop ALL then add: %v", c)
	}
	if _, err := ResolveCaps([]string{"BOGUS"}, nil); err == nil {
		t.Error("bogus capability accepted")
	}
}
