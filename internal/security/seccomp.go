//go:build linux && (amd64 || arm64)

package security

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// BPF opcodes and seccomp constants (linux/bpf_common.h, linux/seccomp.h).
const (
	bpfLdAbsW = 0x20 // BPF_LD|BPF_W|BPF_ABS
	bpfJGE    = 0x35 // BPF_JMP|BPF_JGE|BPF_K
	bpfJEQ    = 0x15
	bpfJSET   = 0x45
	bpfRet    = 0x06

	retAllow  = 0x7fff0000
	retKill   = 0x80000000 // SECCOMP_RET_KILL_PROCESS
	retErrno  = 0x00050000
	offNr     = 0
	offArch   = 4
	offArg0Lo = 16
	x32Bit    = 0x40000000
)

func errnoRet(e syscall.Errno) uint32 { return retErrno | uint32(e) }

// cloneNSFlags are the CLONE_NEW* flags that need CAP_SYS_ADMIN in Docker's profile.
const cloneNSFlags = unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC |
	unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET

// blocked syscalls and the capability that unblocks them ("" = never).
var blocked = map[string]string{
	"acct": "SYS_PACCT", "add_key": "", "bpf": "SYS_ADMIN", "clock_adjtime": "SYS_TIME", "clock_settime": "SYS_TIME",
	"create_module": "SYS_MODULE", "delete_module": "SYS_MODULE", "finit_module": "SYS_MODULE", "init_module": "SYS_MODULE",
	"get_kernel_syms": "SYS_MODULE", "query_module": "SYS_MODULE", "get_mempolicy": "SYS_NICE", "set_mempolicy": "SYS_NICE",
	"mbind": "SYS_NICE", "move_pages": "SYS_NICE", "migrate_pages": "SYS_NICE", "ioperm": "SYS_RAWIO", "iopl": "SYS_RAWIO",
	"vm86": "SYS_RAWIO", "vm86old": "SYS_RAWIO", "kcmp": "SYS_PTRACE", "kexec_file_load": "SYS_BOOT", "kexec_load": "SYS_BOOT",
	"reboot": "SYS_BOOT", "keyctl": "", "request_key": "", "lookup_dcookie": "SYS_ADMIN", "mount": "SYS_ADMIN",
	"umount": "SYS_ADMIN", "umount2": "SYS_ADMIN", "pivot_root": "SYS_ADMIN", "unshare": "SYS_ADMIN", "setns": "SYS_ADMIN",
	"fsopen": "SYS_ADMIN", "fsconfig": "SYS_ADMIN", "fsmount": "SYS_ADMIN", "fspick": "SYS_ADMIN", "move_mount": "SYS_ADMIN",
	"open_tree": "SYS_ADMIN", "mount_setattr": "SYS_ADMIN", "quotactl": "SYS_ADMIN", "quotactl_fd": "SYS_ADMIN",
	"swapon": "SYS_ADMIN", "swapoff": "SYS_ADMIN", "sysfs": "SYS_ADMIN", "sysctl": "SYS_ADMIN", "_sysctl": "SYS_ADMIN",
	"name_to_handle_at": "DAC_READ_SEARCH", "open_by_handle_at": "DAC_READ_SEARCH", "nfsservctl": "",
	"perf_event_open": "SYS_ADMIN", "process_vm_readv": "SYS_PTRACE", "process_vm_writev": "SYS_PTRACE", "ptrace": "SYS_PTRACE",
	"pidfd_getfd": "SYS_PTRACE", "settimeofday": "SYS_TIME", "stime": "SYS_TIME", "uselib": "", "userfaultfd": "SYS_PTRACE",
	"ustat": "", "io_uring_setup": "", "io_uring_enter": "", "io_uring_register": "", "kexec": "SYS_BOOT",
	"syslog": "SYSLOG",
}

type verdict uint8

const (
	vAllow verdict = iota
	vDeny
	vENOSYS
	vClone
	vPersonality
)

type seg struct {
	start uint32
	v     verdict
}

type insn = unix.SockFilter

func stmt(code uint16, k uint32) insn { return insn{Code: code, K: k} }

// BuildFilter returns the BPF program for the default profile given the container's capabilities.
// Allowed = every syscall known for this architecture minus the blocked list (re-allowed when the
// container holds the matching capability); anything else gets EPERM; clone3 gets ENOSYS so libc
// falls back to clone(2), whose namespace flags are checked.
func BuildFilter(caps []string) ([]insn, error) {
	have := map[string]bool{}
	for _, c := range caps {
		have[c] = true
	}
	verd := map[uint32]verdict{}
	for name, nr := range sysnums {
		v := vAllow
		if need, ok := blocked[name]; ok && (need == "" || !have[need]) {
			v = vDeny
		}
		switch name {
		case "clone3":
			v = vENOSYS
		case "clone":
			if !have["SYS_ADMIN"] {
				v = vClone
			}
		case "personality":
			v = vPersonality
		}
		verd[nr] = v
	}
	// Run-length encode verdicts over [0, ∞); numbers with no syscall (gaps, future syscalls) are denied.
	var maxNr uint32
	for nr := range verd {
		if nr > maxNr {
			maxNr = nr
		}
	}
	var m []seg
	for nr := uint32(0); nr <= maxNr+1; nr++ {
		v, ok := verd[nr]
		if !ok {
			v = vDeny
		}
		if len(m) == 0 || m[len(m)-1].v != v {
			m = append(m, seg{nr, v})
		}
	}
	prog := []insn{
		stmt(bpfLdAbsW, offArch),
		{Code: bpfJEQ, Jt: 1, K: auditArch},
		stmt(bpfRet, retKill),
		stmt(bpfLdAbsW, offNr),
	}
	if auditArch == 0xc000003e { // x86-64: reject the x32 ABI
		prog = append(prog, insn{Code: bpfJSET, Jf: 1, K: x32Bit}, stmt(bpfRet, errnoRet(syscall.ENOSYS)))
	}
	tree, err := emit(m)
	if err != nil {
		return nil, err
	}
	return append(prog, tree...), nil
}

func leaf(v verdict) []insn {
	switch v {
	case vAllow:
		return []insn{stmt(bpfRet, retAllow)}
	case vENOSYS:
		return []insn{stmt(bpfRet, errnoRet(syscall.ENOSYS))}
	case vClone:
		return []insn{stmt(bpfLdAbsW, offArg0Lo), {Code: bpfJSET, Jt: 1, K: cloneNSFlags},
			stmt(bpfRet, retAllow), stmt(bpfRet, errnoRet(syscall.EPERM))}
	case vPersonality:
		// personality() takes an unsigned int, so the low word is the whole
		// argument. Allow only getting the persona and the default exec
		// domains; anything else (ADDR_NO_RANDOMIZE, READ_IMPLIES_EXEC, ...)
		// weakens ASLR/executable-memory protections for later execs.
		return []insn{
			stmt(bpfLdAbsW, offArg0Lo),
			{Code: bpfJEQ, Jt: 3, K: 0},          // PER_LINUX
			{Code: bpfJEQ, Jt: 2, K: 8},          // PER_LINUX32
			{Code: bpfJEQ, Jt: 1, K: 0xffffffff}, // get current persona
			stmt(bpfRet, errnoRet(syscall.EPERM)),
			stmt(bpfRet, retAllow),
		}
	}
	return []insn{stmt(bpfRet, errnoRet(syscall.EPERM))}
}

// emit builds a binary search tree over the segments (accumulator holds the syscall number).
func emit(s []seg) ([]insn, error) {
	if len(s) == 1 {
		return leaf(s[0].v), nil
	}
	mid := len(s) / 2
	left, err := emit(s[:mid])
	if err != nil {
		return nil, err
	}
	right, err := emit(s[mid:])
	if err != nil {
		return nil, err
	}
	if len(left) > 255 {
		return nil, fmt.Errorf("seccomp: jump too long (%d)", len(left))
	}
	// If nr >= start-of-right-half jump over the left subtree, else fall through into it.
	// The clone leaf clobbers A, which is fine: every path ends in a return.
	out := []insn{{Code: bpfJGE, Jt: uint8(len(left)), K: s[mid].start}}
	out = append(out, left...)
	return append(out, right...), nil
}

// ApplySeccomp installs the filter on all threads (TSYNC). Requires no_new_privs.
func ApplySeccomp(caps []string) error {
	prog, err := BuildFilter(caps)
	if err != nil {
		return err
	}
	fp := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	const setModeFilter, flagTSYNC = 1, 1
	r, _, e := unix.Syscall(unix.SYS_SECCOMP, setModeFilter, flagTSYNC, uintptr(unsafe.Pointer(&fp)))
	if e != 0 {
		return fmt.Errorf("install seccomp filter: %w (kernel without seccomp? use --seccomp unconfined)", e)
	}
	// With TSYNC the return is a thread ID, not an errno: nonzero means the
	// filter failed to synchronize to that thread. Fail closed.
	if r != 0 {
		return fmt.Errorf("install seccomp filter: TSYNC failed on thread %d; use --seccomp unconfined", r)
	}
	return nil
}
