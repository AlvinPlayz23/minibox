PLAN.md

# minibox: a fast, daemonless, Docker-like container runtime in Go

---

## 0. Working agreements (read first)

1. **Safety.** This project calls `mount`, `unshare`, `pivot_root`, writes to `/sys/fs/cgroup`, and creates network devices. Develop inside a **VM or disposable Linux box**, never on a machine with data you care about. All state must live under a configurable root (`MINIBOX_ROOT`, default `/var/lib/minibox`; rootless default `~/.local/share/minibox`). **Never touch host paths outside that root and the container's own cgroup/netns.** Tests must always set `MINIBOX_ROOT` to a temp dir.
2. **One milestone at a time.** Finish it, make its acceptance criteria pass, commit (`git commit -m "M3: cgroup v2 limits"`), then move on. Do not start the next milestone early.
3. **Measure, don't guess.** The benchmark harness (M1) is built before features. After each milestone run it and record results in `docs/BENCHMARKS.md`. If a change makes `run` slower, say so and justify or revert it.
4. **Keep dependencies minimal.** Prefer the standard library and `golang.org/x/sys/unix`. Every new dependency needs a one-line justification in `docs/DECISIONS.md`.
5. **Keep it static and small.** Build with `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w"`. Track binary size per milestone.
6. **Linux only.** Use build tags (`//go:build linux`). It's fine for the project not to compile elsewhere, but keep pure logic (parsing, store, registry client) testable without root.
7. **Ask before big forks.** If a decision isn't covered here (for example choosing a networking library), write the options and your pick in `docs/DECISIONS.md` and continue with the simplest option.
8. **Update docs as you go**: `README.md` (usage), `docs/ARCHITECTURE.md`, `docs/DECISIONS.md`, `docs/BENCHMARKS.md`.

---

## 1. Goals and non-goals

### Goals (priority order)
1. **Speed.** Warm `run --rm alpine true` should take **under ~50 ms** end to end on a typical machine. Measure against Docker, Podman and `crun` on the same machine.
2. **Docker-like UX.** Same core commands and flags where sensible: `run`, `ps`, `images`, `pull`, `exec`, `logs`, `stop`, `rm`, `rmi`, `inspect`, later `build`.
3. **Low RAM.** No always-running daemon. Target about 0 MB idle and under ~5 MB per detached container (shim).
4. **OCI compatibility.** Pull and run standard images from Docker Hub and other OCI registries. No custom image format.
5. **Rootless-capable.** Works as a normal user via user namespaces (milestone M8), not only as root.

### Non-goals for v1
- macOS or Windows support (needs a VM layer).
- Kubernetes/CRI integration.
- Swarm or orchestration.
- Full Docker API compatibility (optional, last).
- Image building beyond a small Dockerfile subset (optional, M9).

---

## 2. Architecture

### 2.1 Process model (daemonless)

```
minibox run alpine sh
   |
   |- CLI resolves image from the local store (pulls if missing)
   |- Creates container dir, overlayfs mount, cgroup (v2)
   |- Re-execs itself: /proc/self/exe init   (new namespaces via SysProcAttr)
   |      parent <-> child synchronise over a pipe
   `- init stage (inside the namespaces):
         pivot_root -> mount /proc /dev /sys -> set hostname
         -> drop capabilities -> no_new_privs -> seccomp -> execve(user command)
```

- **Foreground `run`:** the CLI process itself supervises the container (no extra shim, which is the fastest path).
- **Detached `run -d`:** the CLI re-execs `minibox shim` with `setsid`; the shim holds stdio or the log file, waits for the container, writes the exit code to `state.json`, tears down the cgroup/network, then exits. The CLI returns immediately.
- **No daemon by default.** Optional later: a socket-activated helper (systemd starts it on demand, exits when idle) only if benchmarks justify it.

### 2.2 Why the re-exec pattern
Go is multithreaded, so you cannot `fork()` and then safely change namespaces in the same process. Launch `/proc/self/exe` with `os/exec` and `SysProcAttr`:

- `Cloneflags`: `CLONE_NEWPID | NEWNS | NEWUTS | NEWIPC | NEWNET` (+ `NEWUSER` for rootless)
- `UseCgroupFD` + `CgroupFD` (Go 1.20+): starts the child directly in its cgroup via `CLONE_INTO_CGROUP`, saving a step.
- `UidMappings` / `GidMappings` for user namespaces.
- `Pdeathsig` so the container dies if the supervisor dies unexpectedly.

The child runs the hidden `init` subcommand and **blocks on a pipe** until the parent finishes setup that must happen from outside (uid/gid maps, veth into the netns), then proceeds.

### 2.3 Directory layout (runtime state)

```
$MINIBOX_ROOT/
|-- blobs/sha256/<hex>              # compressed layer blobs (deletable after unpack)
|-- layers/<chainid>/diff/          # unpacked layers (overlay lowerdirs)
|-- images/<registry>/<repo>/<tag>.json   # manifest + config refs
`-- containers/<id>/
    |-- config.json                 # resolved runtime config (OCI runtime-spec-like)
    |-- state.json                  # status, pid, exit code, timestamps
    |-- upper/  work/  merged/      # overlayfs dirs
    `-- log                         # stdout/stderr (rotated)
```

Use file locks (`flock`) for state mutation so concurrent CLI invocations are safe. Container IDs are 64 hex chars; the CLI accepts any unique prefix (12 chars shown).

### 2.4 Source layout

```
minibox/
|-- cmd/minibox/main.go          # subcommand dispatch (stdlib flag, no Cobra)
|-- internal/
|   |-- cli/                     # command implementations
|   |-- container/               # lifecycle, state, shim, supervisor
|   |-- runtime/                 # re-exec, init stage, namespaces, pivot_root, mounts
|   |-- cgroup/                  # cgroup v2 helpers
|   |-- image/                   # reference parsing, registry client, blob store, unpack
|   |-- storage/                 # overlayfs mount management
|   |-- network/                 # host/none/bridge/pasta, netlink, nftables
|   `-- security/                # capabilities, seccomp, masked paths
|-- bench/                       # benchmark scripts (hyperfine)
|-- test/integration/            # root-requiring tests, build tag `integration`
|-- docs/                        # ARCHITECTURE.md, DECISIONS.md, BENCHMARKS.md
|-- Makefile
`-- go.mod
```

### 2.5 Dependencies (allowed list)
- `golang.org/x/sys/unix`: syscalls (required)
- `github.com/opencontainers/runtime-spec/specs-go`: config types (optional)
- `github.com/vishvananda/netlink`: veth, bridge, addresses, routes (M7)
- `github.com/google/go-containerregistry`: registry client; **use it first in M6**, consider replacing with a ~300-line custom client later if size/startup matters
- A pure-Go seccomp BPF generator (`golang.org/x/net/bpf` + own filter builder); **avoid CGO / libseccomp**

---

## 3. CLI surface (target)

```
minibox run [flags] IMAGE [CMD...]
    -d, --detach     --rm      --name NAME
    -it              (tty + stdin)
    -e KEY=VAL       -v SRC:DST[:ro]      -w DIR      -u USER
    -p HOST:CONT     --network host|none|bridge|pasta
    --memory 64m     --cpus 0.5      --pids-limit 100
    --hostname NAME  --read-only     --cap-add/--cap-drop
minibox ps [-a] [--json]
minibox images [--json]
minibox pull IMAGE
minibox exec [-it] CONTAINER CMD...
minibox logs [-f] CONTAINER
minibox stop [-t SECS] CONTAINER...        # SIGTERM then SIGKILL
minibox rm [-f] CONTAINER...
minibox rmi IMAGE...
minibox inspect CONTAINER|IMAGE
minibox system prune
minibox version
```

Rules: every listing command supports `--json`. Error messages say what failed **and what to do next**. Dead containers are auto-removed with `--rm`; `system prune` cleans the rest. Exit code of `run` equals the container's exit code.

---

## 4. Milestones

Each milestone lists **what to build** and **acceptance criteria** (must all pass before moving on).

### M1: Isolated process + benchmark harness
**Build**
- `go mod init`, Makefile (`build`, `test`, `test-integration`, `bench`, `lint`).
- `minibox run-raw ROOTFS CMD...` (temporary dev command): re-exec into new PID/mount/UTS/IPC/net namespaces, set hostname, `chroot` into an extracted Alpine minirootfs, exec the command.
- `bench/run.sh` using `hyperfine` to time `minibox`, `docker run --rm`, `podman run --rm`, `crun`/`runc` on the same trivial command; write results to `docs/BENCHMARKS.md`.

**Accept**
- `minibox run-raw ./rootfs /bin/sh -c 'hostname; ps; echo $$'` shows its own hostname and **PID 1** with only its own processes visible.
- Host `ps` is unaffected; no leaked mounts afterwards (`mount | grep minibox` is empty).
- Benchmark script runs and records a baseline.

### M2: Proper root filesystem
**Build**
- Replace `chroot` with `pivot_root`: make `/` private (`MS_REC|MS_PRIVATE`), bind-mount rootfs onto itself, `pivot_root`, `chdir /`, lazily unmount and remove the old root.
- Mount `/proc`, tmpfs `/dev` with `null zero full random urandom tty` (bind from host when rootless; `mknod` when root), `/dev/pts`, `/dev/shm`, read-only `/sys`.
- Masked and read-only paths (`/proc/kcore`, `/proc/sys`, etc.).

**Accept**
- Inside: `/proc` shows only container PIDs; `/dev/null` and `/dev/urandom` work; `/sys` is read-only; the old root is unreachable (`ls /.oldroot` fails).

### M3: cgroups v2 limits
**Build**
- `internal/cgroup`: create `<cgroup-root>/minibox/<id>`, enable controllers via parent `subtree_control`, write `memory.max`, `cpu.max`, `pids.max`, `memory.swap.max`. Start the child **directly in the cgroup** using `UseCgroupFD`. On exit, read `memory.events` (OOM info) and remove the cgroup.
- Detect cgroup v1/hybrid and fail with a clear message.

**Accept**
- A process allocating beyond `--memory 50m` is OOM-killed and the exit reason is reported.
- A fork bomb is stopped by `--pids-limit`.
- Cgroup directories are removed after normal exit **and** after `kill -9` of the supervisor (cleanup via `minibox system prune` at minimum).

### M4: Layered storage
**Build**
- Content-addressed blob store; unpack layers once into `layers/<chainid>/diff` (handle OCI whiteouts `.wh.*` and opaque dirs `.wh..wh..opq`, preserve ownership, modes, xattrs, hardlinks, symlinks; **reject path traversal** such as `../` or absolute symlink escapes during extraction).
- Per-container overlayfs mount (`lowerdir` = layers, `upperdir`, `workdir`).
- Handle the overlayfs mount-option length limit with many layers (use short relative paths or `/proc/self/fd` tricks).
- For now, import a tarball as a single-layer image via `minibox load`.

**Accept**
- Two containers from one image share lowerdirs; a file written in one is invisible to the other and to the image.
- Disk usage for the second container is near zero (verify with `du`).
- Fuzz or table tests prove malicious tar entries cannot write outside the layer dir.

### M5: Lifecycle and CLI
**Build**
- `run`, `ps`, `stop`, `rm`, `logs`, `exec` (via `setns` into the container's namespaces from a re-exec'd helper), `inspect`.
- `state.json` with locking; foreground supervisor and detached shim (see 2.1).
- Signal forwarding (`SIGINT`, `SIGTERM`, `SIGWINCH`), PTY support for `-it`, exit-code propagation, log capture with rotation.
- Reap zombies; if PID 1 inside the container is a shell, ensure signals behave (optionally `--init` with a tiny built-in init).

**Accept**
- `run -d`, `ps`, `logs -f`, `exec -it sh`, `stop`, `rm` all work; `Ctrl-C` stops a foreground container cleanly; exit codes propagate.
- Killing the shim leaves no orphaned cgroups or mounts after `system prune`.
- 100 sequential `run --rm` calls leave nothing behind.

### M6: Image pull (OCI registries)
**Build**
- Reference parsing (`alpine`, `docker.io/library/alpine:3.20`, digests).
- Registry v2 client: bearer-token auth (anonymous pull first), manifest list to platform selection (`linux/amd64`, `linux/arm64`), config and layer fetch, **verify sha256 digests**.
- Parallel layer download **and** streaming unpack (never buffer a whole layer in RAM); support gzip and zstd layers.
- Apply image config: `Entrypoint`, `Cmd`, `Env`, `WorkingDir`, `User`, `ExposedPorts`.
- `images`, `pull`, `rmi`, and garbage collection of unreferenced blobs/layers.

**Accept**
- `minibox run alpine echo hi`, `minibox run busybox ...`, `minibox run debian:stable-slim cat /etc/os-release` work from a clean store.
- Peak RSS during pulling a ~100 MB image stays low (record the number).
- Corrupted blob (flip a byte) is detected and rejected.

### M7: Networking
**Build**
- Modes: `none`, `host` (share host netns), `bridge` (default when root), `pasta` (rootless, if the binary exists).
- Bridge mode: create `minibox0` bridge, veth pair per container, assign IPs from a small IPAM (persisted, file-locked), default route, NAT via nftables (use a Go library or `nft` behind an interface; replace later if profiling shows it's slow), write `/etc/resolv.conf` and `/etc/hosts` into the container.
- Port publishing `-p HOST:CONT` via nftables DNAT (rootful) or `pasta` (rootless).
- Cleanup of veth, rules and IP leases on stop/rm.

**Accept**
- Container reaches the internet and resolves DNS; two containers reach each other by IP; `-p 8080:80` with an nginx image serves on the host.
- Network setup time is measured and logged separately in the benchmark (it's usually the biggest chunk).
- Optional speed-up (only if measured as a bottleneck): pre-created pool of network namespaces.

### M8: Security hardening and rootless
**Build**
- User namespaces: map container root to the invoking user (`/etc/subuid`/`subgid` with `newuidmap`/`newgidmap`, or single-ID mapping when unavailable).
- Drop capabilities to a Docker-like default set; `--cap-add/--cap-drop`; set `no_new_privs`.
- Default seccomp profile (allow-list close to Docker's default), generated as BPF in pure Go.
- Read-only rootfs option, masked and read-only paths, `--user`.
- Rootless overlayfs (kernel 5.11+, `userxattr`) with fallback message if unsupported.

**Accept**
- Everything in M1-M7 works as a non-root user (except bridge mode, which falls back to `pasta`/`host` with a clear message).
- Inside the container: `capsh --print` shows the reduced set; calling a blocked syscall (e.g. `mount`) fails; `cat /proc/kcore` is denied.
- Write a short `docs/SECURITY.md` explaining the threat model and known gaps. **Do not claim parity with Docker's security record.**

### M9: Optional extras (only after M1-M8 are solid)
- Volumes: bind mounts and named volumes, `tmpfs`.
- `minibox build` for a Dockerfile subset (`FROM`, `RUN`, `COPY`, `ENV`, `WORKDIR`, `CMD`, `ENTRYPOINT`) with layer caching; or document using Buildah/BuildKit instead.
- A Compose-like YAML (`minibox up/down`).
- Healthchecks, restart policies via a systemd unit generator (no daemon needed).
- Docker-compatible API on a socket (socket-activated) so IDEs and Portainer work.
- Lazy pulling (eStargz/SOCI-style) to start containers before the full image downloads.

### M10: Performance pass
- Profile with `pprof` and `strace -T -f`/`perf trace`; list every syscall in the hot path and remove the unnecessary ones.
- Tune the Go runtime in the shim and CLI (`GOGC`, `GOMEMLIMIT`, avoid goroutine/alloc churn at startup).
- Lazy-initialize everything that isn't needed for `run` (flag sets, registry client, JSON schemas).
- Re-check binary size, startup time, and RSS. Update `docs/BENCHMARKS.md` with a final comparison table.

---

## 5. Performance targets (verify, don't assume)

| Metric | Target |
|---|---|
| Warm `run --rm alpine true` (no network or host network) | < 50 ms |
| Warm `run --rm` with bridge networking | < 150 ms (record the real number) |
| Idle RAM (no containers) | 0 (no daemon) |
| RSS of detached-container shim | < 5 MB |
| Binary size | < 15 MB |
| Peak RSS pulling a 100 MB image | record, keep low via streaming |

Benchmark method: `hyperfine --warmup 5 --runs 50 'minibox run --rm alpine true' 'podman run --rm alpine true' 'docker run --rm alpine true'`, plus a raw `crun` run as the floor. Run each on the same kernel, same filesystem, cold and warm.

---

## 6. Testing strategy

- **Unit tests** (no root): reference parsing, digest verification, tar extraction safety, whiteout handling, IPAM, config merge, state locking.
- **Integration tests** (`//go:build integration`, need root or user namespaces): namespace isolation, cgroup limits, overlay behavior, pull-run cycle, networking. Each test uses a temp `MINIBOX_ROOT` and cleans up even on failure (`t.Cleanup`).
- **Leak check:** after the suite, assert there are no leftover mounts (`/proc/self/mountinfo`), cgroups, veth devices or nftables rules owned by minibox.
- **Fuzzing:** `go test -fuzz` on the tar extractor and image reference parser.
- **CI:** build + unit tests on every push; integration tests on a Linux runner with privileges (or a nested VM).

---

## 7. Go-specific gotchas

- Use `runtime.LockOSThread()` before any per-thread syscall sequence (`setns`, `unshare`, per-thread capability or uid changes).
- `setns` into mount/user namespaces fails in a multithreaded process; do it in the re-exec'd child before the Go runtime spreads, or use the re-exec pattern consistently.
- Keep CGO disabled so the binary stays static; avoid libraries that require it.
- Stream tar extraction (`archive/tar` + `io.Copy`); never `io.ReadAll` a layer.
- Close file descriptors you don't want inherited (`O_CLOEXEC`, `ExtraFiles` only for the sync pipe).
- Handle `EINTR`/`EAGAIN` on raw syscalls; prefer `unix.*` wrappers.

---

## 8. Kernel and environment requirements

- Linux **5.7+** (`CLONE_INTO_CGROUP`), **5.11+** for rootless overlayfs, **cgroup v2** unified hierarchy.
- Needed for bridge mode: `CAP_NET_ADMIN`, nftables or iptables.
- For rootless: `newuidmap`/`newgidmap` (package `uidmap`) and populated `/etc/subuid`, `/etc/subgid`.
- Development extras: Go 1.22+, `hyperfine`, `strace`, `perf` (optional), and for comparisons: Docker, Podman, `crun`.

---

## 9. Disk and resource budget

| Item | Approx. size |
|---|---|
| Go toolchain + caches (dev) | ~0.5-1.3 GB |
| Test images (alpine ~8 MB, busybox ~4 MB, debian-slim ~80 MB unpacked) | ~100-200 MB |
| Docker + Podman installed for benchmarking | ~0.5-1 GB |
| The minibox binary | ~8-15 MB |
| Image store | ~2-3x compressed image size (less if compressed blobs are deleted after unpack) |
| Per container | ~0 at start, grows with writes; log rotation required |

---

## 10. Definition of done for v1 (end of M8)

- All M1-M8 acceptance criteria pass; unit and integration suites are green and leak-free.
- `README.md` documents install, usage and limitations. `docs/BENCHMARKS.md` shows real numbers vs Docker/Podman/crun.
- Runs the images the user cares about (alpine, debian, an nginx or similar web image, a database image) as root **and** rootless.
- Known gaps are listed honestly in `docs/SECURITY.md`.

---

## 11. Open questions (record answers in `docs/DECISIONS.md`)

1. Primary use case: long-running services with published ports (bridge and port-publish matter most) or short-lived dev commands (host/none networking is enough)? **Default if unanswered: bridge for root, `pasta`/host for rootless.**
2. Delete compressed blobs after unpacking (saves disk, but re-pull needed to rebuild layers)? **Default: keep until `system prune`.**
3. Replace `go-containerregistry` with a custom client after M6 if binary size or startup time suffers?
4. Add a socket-activated helper for warm state, or stay fully daemonless? **Decide only after M10 numbers.**

---

## 12. References to study (by name; look them up as needed)

- Specs: OCI Image Spec, OCI Runtime Spec, OCI Distribution Spec.
- Man pages: `namespaces(7)`, `cgroups(7)`, `pivot_root(2)`, `clone3(2)`, `mount_namespaces(7)`, `user_namespaces(7)`, `capabilities(7)`, `seccomp(2)`, and the kernel's overlayfs documentation.
- Code to read: **runc** (reference), **crun** (fast C runtime), **youki** (Rust runtime), **Podman/conmon** (daemonless model), **containerd** (image store design).
- Talk: Liz Rice, "Containers from Scratch" (minimal Go runtime in about 100 lines).

---

## 13. Suggested first prompt to Claude Code

> Read PLAN.md fully. Initialize the Go module and repository layout from section 2.4, then implement **Milestone M1** only: the `run-raw` dev command and the benchmark harness. Follow the working agreements in section 0. When M1's acceptance criteria pass, summarize what you built and the benchmark numbers, then stop and wait for me before starting M2.
