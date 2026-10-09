# Architecture (M1)
`minibox run-raw ROOTFS CMD...` re-execs `/proc/self/exe init ROOTFS CMD...` with CLONE_NEW{PID,NS,UTS,IPC,NET} and Pdeathsig.
Init (PID 1): make / private, set hostname, chroot, mount /proc, exec. Parent forwards SIGINT/SIGTERM and propagates the exit code.

## M2 rootfs setup (internal/runtime/rootfs.go)
Bind rootfs onto itself → mount proc, ro sysfs, tmpfs /dev (mknod null/zero/full/random/urandom/tty, bind from host if mknod fails), devpts (newinstance), /dev/shm, fd/stdin/stdout/stderr/ptmx symlinks → mask paths (/dev/null bind or empty ro tmpfs; absent paths skipped) and ro-remount /proc/{bus,fs,irq,sys,sysrq-trigger} → pivot_root into `.oldroot`, lazily unmount and remove it.

## M3 cgroups (internal/cgroup, internal/state)
`$MINIBOX_CGROUP_MOUNT/minibox/<id>` (default /sys/fs/cgroup). Controllers are enabled via parent subtree_control only when a limit needs them; `memory.swap.max=0` accompanies `--memory`. Child starts inside via `UseCgroupFD`. After exit `memory.events` oom_kill is reported; the cgroup is removed (cgroup.kill first).
Liveness: the supervisor holds `flock($MINIBOX_ROOT/run/<id>.lock)`; the kernel drops it on kill -9, so `minibox system prune` removes cgroups whose lock is free. cgroup v1/hybrid is rejected with a message.

## M4 storage
- **Blobs**: `blobs/sha256/<hex>`, written to a temp file while hashing, verified, then renamed (nothing visible on mismatch).
- **Layers**: `layers/<chainhex>/{diff,meta.json}`, chain ID per OCI spec. Unpacked into `layers/.tmp-*` and renamed atomically; identical concurrent unpacks collapse into one. `layers/l/<12 hex>` are short symlinks to `diff` dirs.
- **Whiteouts** are stored overlay-native: `.wh.x` → char device 0:0 named `x`; `.wh..wh..opq` → `trusted.overlay.opaque=y` (configurable for rootless `user.overlay.opaque`).
- **Safe extraction** (`internal/image/extract.go`): all operations are `*at()` calls relative to a directory fd, walking each component with `O_NOFOLLOW`; a symlink in any parent component is an error, `..` in names/link targets is rejected, hardlinks are `linkat(…, 0)` (never follow), dir attrs/mtimes are applied deepest-first at the end, `trusted.*` xattrs and char 0:0 devices from the tar are refused (they could forge whiteouts/redirects). Absolute symlink *targets* are stored verbatim (normal in images) but never followed.
- **Images**: `images/local/<name>/<tag>.json` (M6 replaces `local` with the registry). `minibox load [-i FILE] NAME[:TAG]` imports a rootfs tarball (plain or gzip) as one layer, streaming.
- **Overlay mount** happens in the init stage, inside the container's mount namespace (nothing to leak on the host, nothing to unmount on crash). Option string ≤4000 bytes → absolute lowerdirs; else `/proc/self/fd/<links dir fd>/<short>`; else (Linux ≥6.8) `fsopen`/`fsconfig lowerdir+`. The init spec travels as JSON on fd 3, written from a goroutine (it can exceed the 64 KiB pipe buffer — this was a real hang found by the 300-layer test).
- **pivot_root(".", ".")** replaces the M2 `.oldroot` dir: no writes into a rootfs shared by concurrent containers (the old design raced under 30 parallel runs).
- `system prune` also removes `containers/<id>` of dead supervisors (no `state.json`) and, for cgroups with no lock file under the current root, only if empty.
