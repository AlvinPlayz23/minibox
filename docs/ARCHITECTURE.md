# Architecture (M1)
`minibox run-raw ROOTFS CMD...` re-execs `/proc/self/exe init ROOTFS CMD...` with CLONE_NEW{PID,NS,UTS,IPC,NET} and Pdeathsig.
Init (PID 1): make / private, set hostname, chroot, mount /proc, exec. Parent forwards SIGINT/SIGTERM and propagates the exit code.

## M2 rootfs setup (internal/runtime/rootfs.go)
Bind rootfs onto itself → mount proc, ro sysfs, tmpfs /dev (mknod null/zero/full/random/urandom/tty, bind from host if mknod fails), devpts (newinstance), /dev/shm, fd/stdin/stdout/stderr/ptmx symlinks → mask paths (/dev/null bind or empty ro tmpfs; absent paths skipped) and ro-remount /proc/{bus,fs,irq,sys,sysrq-trigger} → pivot_root into `.oldroot`, lazily unmount and remove it.

## M3 cgroups (internal/cgroup, internal/state)
`$MINIBOX_CGROUP_MOUNT/minibox/<id>` (default /sys/fs/cgroup). Controllers are enabled via parent subtree_control only when a limit needs them; `memory.swap.max=0` accompanies `--memory`. Child starts inside via `UseCgroupFD`. After exit `memory.events` oom_kill is reported; the cgroup is removed (cgroup.kill first).
Liveness: the supervisor holds `flock($MINIBOX_ROOT/run/<id>.lock)`; the kernel drops it on kill -9, so `minibox system prune` removes cgroups whose lock is free. cgroup v1/hybrid is rejected with a message.
