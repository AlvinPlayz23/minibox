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

// Spawn starts the init stage in new namespaces inside cg, with the given stdio.
// The caller waits on the returned command and owns the cgroup.
func Spawn(spec InitSpec, cg *cgroup.Cgroup, stdin, stdout, stderr *os.File) (*exec.Cmd, error) {
	fd, err := cg.OpenFD()
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	specR, specW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer specR.Close()
	sb, _ := json.Marshal(spec)
	c := exec.Command("/proc/self/exe", "init")
	c.ExtraFiles = []*os.File{specR}
	c.Stdin, c.Stdout, c.Stderr = stdin, stdout, stderr
	c.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWIPC | syscall.CLONE_NEWNET,
		Pdeathsig:   syscall.SIGKILL,
		UseCgroupFD: true,
		CgroupFD:    fd,
	}
	if err := c.Start(); err != nil {
		specW.Close()
		return nil, fmt.Errorf("start container (need root or CAP_SYS_ADMIN): %w", err)
	}
	go func() { specW.Write(sb); specW.Close() }()
	return c, nil
}

// BuildSpec resolves an image into an init spec with an overlay rooted in cdirs.
func BuildSpec(st *image.Store, img *image.Image, cdirs *storage.ContainerDirs) (InitSpec, error) {
	var spec InitSpec
	lowers, err := st.LowerDirs(img)
	if err != nil {
		return spec, err
	}
	ov := &storage.Overlay{Upper: cdirs.Upper, Work: cdirs.Work, Target: cdirs.Merged}
	for _, l := range lowers {
		ov.Lowers = append(ov.Lowers, storage.Lower{Dir: l.Dir, Short: l.Short})
	}
	spec.Overlay, spec.Rootfs = ov, cdirs.Merged
	return spec, nil
}

var _ = state.Root
