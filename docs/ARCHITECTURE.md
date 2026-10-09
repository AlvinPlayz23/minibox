# Architecture (M1)
`minibox run-raw ROOTFS CMD...` re-execs `/proc/self/exe init ROOTFS CMD...` with CLONE_NEW{PID,NS,UTS,IPC,NET} and Pdeathsig.
Init (PID 1): make / private, set hostname, chroot, mount /proc, exec. Parent forwards SIGINT/SIGTERM and propagates the exit code.

## M2 rootfs setup (internal/runtime/rootfs.go)
Bind rootfs onto itself → mount proc, ro sysfs, tmpfs /dev (mknod null/zero/full/random/urandom/tty, bind from host if mknod fails), devpts (newinstance), /dev/shm, fd/stdin/stdout/stderr/ptmx symlinks → mask paths (/dev/null bind or empty ro tmpfs; absent paths skipped) and ro-remount /proc/{bus,fs,irq,sys,sysrq-trigger} → pivot_root into `.oldroot`, lazily unmount and remove it.
