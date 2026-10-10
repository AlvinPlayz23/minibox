//go:build linux

package container

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"minibox/internal/cgroup"
)

func (c *Container) waitStopped(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		_ = c.Refresh()
		if !c.Running() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Stop sends SIGTERM, waits timeout, then SIGKILLs the whole cgroup. timeout 0 kills at once.
func Stop(c *Container, timeout time.Duration) error {
	_ = c.Refresh()
	if c.Reconcile() || c.State.Status != "running" {
		return nil
	}
	if timeout > 0 && c.State.Pid > 0 {
		_ = syscall.Kill(c.State.Pid, syscall.SIGTERM)
		if c.waitStopped(timeout) {
			return nil
		}
	}
	if err := os.WriteFile(cgroup.Base()+"/"+c.Config.ID+"/cgroup.kill", []byte("1"), 0o644); err != nil && c.State.Pid > 0 { // rootless: no cgroup; killing PID 1 kills the PID namespace
		_ = syscall.Kill(c.State.Pid, syscall.SIGKILL)
	}
	if !c.waitStopped(10 * time.Second) {
		return fmt.Errorf("container %s did not stop after SIGKILL; check `minibox ps -a`", short(c.Config.ID))
	}
	return nil
}
