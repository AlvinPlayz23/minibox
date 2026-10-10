//go:build linux

package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"

	"minibox/internal/cgroup"
	"minibox/internal/image"
	"minibox/internal/state"
	"minibox/internal/storage"
)

// MergeEnv merges image env with defaults for PATH/HOME/TERM.
func MergeEnv(img []string) []string { return mergeEnv(img) }

// Spawn starts the init stage in new namespaces inside cg, with the given stdio. The child
// blocks reading its spec until the returned send function is called; the supervisor uses that
// window to finish setup that must happen from outside (networking). hostNet shares the host's
// network namespace. The caller waits on the returned command and owns the cgroup.
//
// When not root the container gets a user namespace mapping container root to the invoking
// user (single-ID map; no subuid ranges yet) and cg is nil (no cgroups without delegation).
func Spawn(cg *cgroup.Cgroup, hostNet bool, stdin, stdout, stderr *os.File) (*exec.Cmd, func(InitSpec), error) {
	fd := -1
	if cg != nil {
		var err error
		if fd, err = cg.OpenFD(); err != nil {
			return nil, nil, err
		}
		defer unix.Close(fd)
	}
	specR, specW, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	defer specR.Close()
	c := exec.Command("/proc/self/exe", "init")
	c.ExtraFiles = []*os.File{specR}
	c.Stdin, c.Stdout, c.Stderr = stdin, stdout, stderr
	flags := uintptr(syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS | syscall.CLONE_NEWIPC)
	if !hostNet {
		flags |= syscall.CLONE_NEWNET
	}
	c.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  flags,
		Pdeathsig:   syscall.SIGKILL,
		UseCgroupFD: cg != nil,
		CgroupFD:    fd,
	}
	if os.Geteuid() != 0 {
		c.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUSER
		c.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}}
		c.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}}
		c.SysProcAttr.GidMappingsEnableSetgroups = false
	}
	if err := c.Start(); err != nil {
		specW.Close()
		return nil, nil, fmt.Errorf("start container (need root or CAP_SYS_ADMIN): %w", err)
	}
	send := func(spec InitSpec) {
		sb, _ := json.Marshal(spec)
		// Written concurrently: the spec can exceed the 64 KiB pipe buffer (many layers).
		go func() { specW.Write(sb); specW.Close() }()
	}
	return c, send, nil
}

// BuildSpec resolves an image into an init spec with an overlay rooted in cdirs.
func BuildSpec(st *image.Store, img *image.Image, cdirs *storage.ContainerDirs) (InitSpec, error) {
	var spec InitSpec
	lowers, err := st.LowerDirs(img)
	if err != nil {
		return spec, err
	}
	ov := &storage.Overlay{Upper: cdirs.Upper, Work: cdirs.Work, Target: cdirs.Merged, UserXattr: os.Geteuid() != 0}
	for _, l := range lowers {
		ov.Lowers = append(ov.Lowers, storage.Lower{Dir: l.Dir, Short: l.Short})
	}
	spec.Overlay, spec.Rootfs = ov, cdirs.Merged
	return spec, nil
}

var _ = state.Root
