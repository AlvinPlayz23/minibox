# Security model

minibox is a learning/engineering project. **It has no security track record and must not be treated as
equivalent to Docker, Podman or runc.** Do not run hostile code in it on a machine you care about.

## Threat model

Goal: contain a *mostly cooperative* workload (a service you wrote or trust somewhat) so that bugs or
compromise of the workload do not trivially reach the host. Non-goal: withstand a determined attacker with
a kernel exploit, or untrusted multi-tenant workloads.

## What is enforced (rootful `minibox run`)

| Layer | Mechanism |
|---|---|
| Isolation | PID, mount, UTS, IPC and (except `--network host`) network namespaces; `pivot_root`, old root unmounted |
| Capabilities | Bounding/permitted/effective/inheritable reduced to Docker's default 14; `--cap-add/--cap-drop` (incl. `ALL`); ambient cleared |
| `no_new_privs` | Always set: `execve` can never gain privilege (setuid binaries, file capabilities) |
| seccomp | Pure-Go generated BPF filter. Allow = every syscall of the architecture minus a block list close to Docker's default; blocked ones return `EPERM`; `clone3` returns `ENOSYS` (libc falls back to `clone`, whose namespace flags are checked); the x32 ABI and foreign architectures are refused. Block list is lifted per capability (e.g. `--cap-add SYS_ADMIN` allows `mount`). `--seccomp unconfined` disables it |
| Filesystem | `/proc/{kcore,keys,timer_list,sched_debug,...}` masked, `/proc/{bus,fs,irq,sys,sysrq-trigger}` read-only, `/sys` read-only, `--read-only` remounts `/` read-only |
| Resources | cgroup v2: memory (+swap 0), cpu, pids |
| Users | `-u`/image `User` applied after the rootfs is in place; non-root users have no effective capabilities |
| Network | Bridge `minibox0` + veth per container, own `ip minibox` nftables table (never touches other tables); IPAM leases are persisted and released on exit/prune |
| Tar extraction | fd-relative `*at()` walk with `O_NOFOLLOW`; `..`, absolute escapes and symlink parents rejected; forged `trusted.*` xattrs and 0:0 devices refused; fuzzed |
| Registry | Manifest, config and every layer blob are verified by sha256; layers additionally by diffID *before* they are published |

The seccomp filter's behaviour is unit-tested with an in-process BPF interpreter
(`internal/security/seccomp_test.go`) and verified end to end in `test/integration/m8_test.go`.

## Rootless mode

When not root, minibox starts the container in a **user namespace with a single-ID mapping** (container
root = invoking user), uses overlayfs with `userxattr`, "xattr whiteouts" for unprivileged layer extraction,
and `pasta` (or host networking) instead of the bridge. **This code path could not be exercised on the
development VM** (its sandbox forbids creating user namespaces even for root), so it is implemented but
**untested**. Known limits: no subuid/subgid ranges (`newuidmap` is not used), no resource limits (no cgroup
delegation), no `exec`.

## Known gaps

- **No user-namespace remapping by default as root**: container root is host root, limited only by the
  capability/seccomp/namespace measures above. A kernel or runtime bug can mean host root. Use rootless mode
  or a VM for anything less than trusted.
- No AppArmor/SELinux profile, no `personality(2)` argument filtering, no socket-family filtering.
- `ptrace` and `io_uring` are blocked by default (stricter than older Docker defaults; opt in with
  `--cap-add SYS_PTRACE` / `--seccomp unconfined`).
- `/proc/self/mountinfo` inside the container exposes host paths of the image store (information leak).
- Published ports (`-p`) are DNAT'ed on all host addresses; there is no host-IP binding and no userland
  proxy, so a host-local listener on the same port does not conflict and is shadowed.
- Containers on the bridge can reach each other and the host's bridge address without restriction.
- Detached-container logs and `config.json` are readable by anyone who can read `MINIBOX_ROOT`
  (default `/var/lib/minibox`, mode 0755). Environment variables (secrets!) are stored in `config.json`.
- Supervisor death kills the container (`Pdeathsig`) but cleanup of cgroup/network happens only on
  `minibox system prune` (or the next `ps`/`rm`/`stop`).
- Registry credentials are read from `MINIBOX_REGISTRY_USER/PASS` or `~/.docker/config.json` (basic `auth`
  only; credential helpers are not supported). TLS is verified; only `localhost` and hosts listed in
  `MINIBOX_INSECURE_REGISTRIES` may use plain HTTP.
