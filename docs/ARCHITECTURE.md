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

## M5 lifecycle (internal/container, internal/cli, internal/pty)
`run` resolves the image (pulling on demand under a shared store lock), writes
`containers/<id>/{config.json,state.json}` and supervises: foreground inherits
stdout/stderr (stdin only with `-i`, else `/dev/null`; `-t` allocates a pty
with raw mode + SIGWINCH resizing), detached re-execs `minibox shim`
(setsid, output to a rotating 10 MB x 3 log). Init spec travels on fd 3; the child blocks
reading it until the parent finishes outside-setup (networking). `--init` (default) keeps a
minimal PID 1 that reaps orphans and forwards signals; `stop` sends SIGTERM then SIGKILLs the
cgroup. `exec` joins ipc/uts/net/pid namespaces via `/proc/PID/ns/*` (mount ns can't be joined
from multithreaded Go, so it chroots via `/proc/PID/root`) after pre-warming OS threads —
clone(CLONE_THREAD) fails with EINVAL once inside a new pid namespace.

## M6 pull (internal/image/{reference,registry,pull}.go)
Custom stdlib registry v2 client (bearer auth incl. Docker Hub token flow, basic creds from
`MINIBOX_REGISTRY_USER/PASS` or `~/.docker/config.json`). Manifest index → platform match
(linux/GOARCH), per-digest verification of manifest/config/layers, 3-way parallel download
with retries, streaming unpack verified by diffID before publish. Image records at
`images/<registry>/<repo>/<tag>.json` plus `Digest`/`Size`; `images`, `rmi` (refuses in-use),
GC (unreferenced layers, optional blobs; skipped while a pull/run holds the store lock).

## M7 networking (internal/network)
Modes none/host/bridge/pasta. Bridge `minibox0` (default 172.30.0.0/16, `MINIBOX_SUBNET`),
per-container veth moved into the child netns from outside before the spec is released,
file-locked IPAM, own `ip minibox` nftables table (NAT masquerade, hostports DNAT map,
local-output chain for `curl localhost:PORT`), `/etc/resolv.conf`+`/etc/hosts` bind-mounted
into the rootfs pre-pivot. Everything recorded in `net.json` for crash-safe cleanup;
leases/ports of dead containers are reclaimed by `system prune`.

## M8 security (internal/security, docs/SECURITY.md)
Capability drop to Docker's default 14 (`--cap-add/--cap-drop`, ALL supported; empty set is
non-nil so "drop all" sticks), `no_new_privs` always, pure-Go seccomp-BPF default profile
(allow = arch syscalls minus block list, lifted per capability; clone3 → ENOSYS; clone ns
flags checked; x32 rejected), `--read-only`, `-u`/image User, masked/ro paths. Rootless:
single-ID user namespace, `userxattr` overlay + xattr whiteouts, pasta/host networking, no
cgroup limits, no exec. Rootless could not be exercised (sandbox forbids CLONE_NEWUSER).

## M9 extras (internal/{volume,build,compose}, systemd/health in internal/cli)
`-v SRC:DST[:ro]` (bind or named volume under `volumes/<name>/_data`) and
`--tmpfs DST[:size=64m][,ro]`; destinations resolved with securejoin-style ResolveInRoot
(absolute symlinks and `..` can never escape the rootfs); `volume ls|create|rm|inspect|prune`
with in-use protection. `build` supports FROM/RUN/COPY/ENV/WORKDIR/CMD/ENTRYPOINT/EXPOSE/USER/ARG
(layer cache in `build-cache.json`; RUN captured from the container upper dir with
overlay→OCI whiteout conversion). `up/down` run a Compose subset (no external YAML dep).
`systemd` emits a unit re-running the container foreground (restart mapped to always/no);
`healthcheck` execs `--health-cmd`. Out of scope (documented): Docker API socket, multi-stage
builds, `ADD` in any form (rejected outright; use `COPY`), lazy pulling.

## M10 performance
Hot path (`strace -c -f`, ~1790 syscalls/run) is dominated by Go runtime init ×3 processes
(CLI, init re-exec, init fork) plus 22 required mounts, 33 prctl (caps/NNP) and 1 seccomp
install — nothing left that is removable without dropping features. CLI startup (`version`)
<5 ms. No tuning knobs were needed to meet every target, so none were added.
