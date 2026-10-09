# Architecture (M1)
`minibox run-raw ROOTFS CMD...` re-execs `/proc/self/exe init ROOTFS CMD...` with CLONE_NEW{PID,NS,UTS,IPC,NET} and Pdeathsig.
Init (PID 1): make / private, set hostname, chroot, mount /proc, exec. Parent forwards SIGINT/SIGTERM and propagates the exit code.
