# minibox progress checklist

Legend: `[x]` done and verified; `[ ]` not done. "Verified" means exercised by a test or a manual run on the dev VM
(Linux 6.18, cgroup v2, root, Go 1.27). Nothing is checked on the strength of "it compiles".

Status: **M1–M4 done. M5–M10 not started.**

## Working agreements (PLAN §0)
- [x] State under `MINIBOX_ROOT`; tests use temp roots
- [x] One milestone at a time, one commit each
- [x] Benchmark harness built first; results in `docs/BENCHMARKS.md` after each milestone
- [x] Minimal dependencies (only `golang.org/x/sys/unix`)
- [x] Static build (`CGO_ENABLED=0 -trimpath -ldflags="-s -w"`), size tracked (3.7 MB at M4)
- [x] `//go:build linux` on all runtime code; pure logic testable without root
- [x] `docs/DECISIONS.md`, `ARCHITECTURE.md`, `BENCHMARKS.md`, `README.md` kept up to date
- [ ] CI (build + unit tests on push; privileged integration runner) — not set up

## M1: isolated process + benchmark harness
- [x] `go mod init`, Makefile (`build`, `test`, `test-integration`, `bench`, `lint`)
- [x] `minibox run-raw ROOTFS CMD...`: re-exec into new PID/mount/UTS/IPC/net namespaces, hostname, exec
- [x] `bench/run.sh` (hyperfine) + `bench/fetch-rootfs.sh`, results in `docs/BENCHMARKS.md`
- [x] Accept: own hostname, PID 1, only own processes visible
- [x] Accept: host `ps` unaffected; no leaked mounts
- [x] Accept: benchmark runs and records a baseline
- Notes: only **runc** is benchmarked. Docker's `alpine` image wasn't pulled, and podman and crun aren't installed here, so there is **no Docker/Podman/crun comparison yet**. It's required for the v1 definition of done (§10).

## M2: proper root filesystem
- [x] `pivot_root` (private `/`, bind rootfs, lazy-unmount old root); implemented as `pivot_root(".", ".")` so no `.oldroot` dir is written into the (possibly shared) rootfs
- [x] `/proc`, tmpfs `/dev` with null/zero/full/random/urandom/tty (`mknod`, host bind fallback), `/dev/pts`, `/dev/shm`, read-only `/sys`
- [x] Masked and read-only paths
- [x] Accept: `/proc` shows only container PIDs; `/dev/null` and `/dev/urandom` work; `/sys` read-only; old root unreachable
- Notes: `/proc/kcore` doesn't exist on this kernel, so masking an existing file was **not exercised** (the code path handles missing paths). The rootless bind-mount fallback for `/dev` nodes is **untested** (needs M8). No `/dev/console`.

## M3: cgroups v2 limits
- [x] `internal/cgroup`: create `minibox/<id>`, enable controllers, `memory.max`, `memory.swap.max`, `cpu.max`, `pids.max`
- [x] Child starts in its cgroup via `UseCgroupFD` (CLONE_INTO_CGROUP)
- [x] Read `memory.events`, report OOM, remove cgroup on exit
- [x] Detect cgroup v1/hybrid and fail clearly (statfs magic check)
- [x] Accept: OOM kill beyond `--memory 50m` is reported (exit 137)
- [x] Accept: fork bomb stopped by `--pids-limit`
- [x] Accept: cgroups removed after normal exit **and** after `kill -9` of the supervisor (via `minibox system prune`, the stated minimum)
- [x] `--cpus` verified: `--cpus 0.25` slows a CPU loop about 4x
- Notes: the **v1/hybrid rejection path is untested** (VM is v2). Cleanup after `kill -9` is not automatic; `system prune` must be run. Liveness is an `flock` per container, which the kernel releases on death.

## M4: layered storage
- [x] Content-addressed blob store (write to temp, verify, rename)
- [x] Layers unpacked once to `layers/<chainid>/diff`, atomic rename, concurrent-safe, OCI chain IDs
- [x] Whiteouts (`.wh.*` to char 0:0) and opaque dirs (`.wh..wh..opq` to `trusted.overlay.opaque`)
- [x] Preserve ownership, modes (setuid/sticky), mtimes, hardlinks, symlinks, fifos, devices, allowed xattrs
- [x] Reject path traversal and symlink-escape extraction (fd-relative `*at` walk with `O_NOFOLLOW`)
- [x] Per-container overlayfs (`lowerdir`/`upperdir`/`workdir`), mounted inside the container's mount namespace
- [x] Option-length limit: short symlinks via `/proc/self/fd`, then `fsconfig lowerdir+` on Linux 6.8+
- [x] `minibox load` imports a plain/gzip tarball as a single-layer image (streaming)
- [x] Accept: two containers share lowerdirs; writes are invisible to the other container and the image
- [x] Accept: second container disk use is near zero (~20 KB, `du` agrees)
- [x] Accept: table tests and a fuzz target show malicious tars can't write outside the layer dir (fuzz: 131k execs, 40 s; test suite checked against a deliberately broken extractor)
- Also verified: 127 layers work, and 300 layers work with order preserved. 520 layers fail with a clear error.
- Also verified: 30 parallel and 100 sequential runs leave no cgroups, mounts, locks or dirs behind.
- Also verified: loading a 300 MB gzip layer takes 1.6 s, peak RSS 17 MB, blob digest equals input sha256.
- Notes / limitations:
  - Rootless layers aren't supported yet: creating whiteouts needs `CAP_MKNOD` (M8). `user.overlay.*` is parameterised but untested.
  - Symlinks in a parent path are a hard error (strict, not "resolve within root"); revisit if a real image trips on it.
  - Only `security.capability` and `user.*` xattrs are kept. Sparse tar entries aren't supported. zstd is rejected until M6.
  - Images live under `images/local/...`; real registry paths arrive in M6.
  - `run-raw` is a temporary dev command. Flags `--memory/--cpus/--pids-limit/--image/--keep` only exist there.

## M5: lifecycle and CLI
- [ ] `run`, `ps`, `stop`, `rm`, `logs`, `exec` (setns), `inspect`
- [ ] `state.json` with locking; foreground supervisor and detached shim
- [ ] Signal forwarding (SIGINT/SIGTERM/SIGWINCH), PTY (`-it`), exit-code propagation, log rotation
- [ ] Zombie reaping / `--init`
- [ ] Accept: `run -d`, `ps`, `logs -f`, `exec -it sh`, `stop`, `rm`; Ctrl-C stops a foreground container
- [ ] Accept: killing the shim leaves nothing after prune; 100 sequential `run --rm` leave nothing (note: 100 sequential `run-raw` already pass as an early check)
- Known problem to fix here: PID 1 ignores SIGTERM/SIGINT unless it installs handlers. The supervisor forwards the signals, but a plain `sleep` doesn't die. Needs `--init` and `stop` escalation to SIGKILL.

## M6: image pull (OCI registries)
- [ ] Reference parsing, registry v2 client with auth, platform selection, digest verification
- [ ] Parallel download plus streaming unpack, gzip and zstd
- [ ] Apply image config; `images`, `pull`, `rmi`, GC
- [ ] Accept: alpine, busybox and debian-slim run from a clean store; peak RSS recorded; corrupted blob rejected
- Groundwork present: blob digest verification, chain IDs, lazy-compiled name validation.

## M7: networking
- [ ] none/host/bridge/pasta, IPAM, NAT, port publishing, DNS files, cleanup
- [ ] Accept: internet and DNS, container-to-container, `-p 8080:80`; network setup time benchmarked
- Note: containers currently get a fresh empty network namespace (only loopback, which isn't brought up).

## M8: security hardening and rootless
- [ ] User namespaces, capability drop, `no_new_privs`, seccomp (pure Go BPF), read-only rootfs, `--user`, rootless overlayfs
- [ ] `docs/SECURITY.md`
- Known gap now: containers run with **full root capabilities and no seccomp**. They are not safe for untrusted code.
- Known gap now: `/proc/self/mountinfo` inside the container shows host paths (information leak, not an escape).

## M9: optional extras
- [ ] Volumes/tmpfs, `build`, compose-like `up/down`, healthchecks/systemd, Docker API socket, lazy pulling

## M10: performance pass
- [ ] pprof/strace hot-path audit, runtime tuning, lazy init, final comparison table
- Current numbers (noisy shared VM): `run-raw ... /bin/true` mean about 50–60 ms (±10–16), fastest runs 28–36 ms; runc about 270–280 ms.
- Targets: warm run under 50 ms is **not reliably met** (only the fastest runs). The <150 ms bridge target is untested. Idle RAM is 0 (no daemon). Binary 3.7 MB, under the 15 MB target. Shim RSS under 5 MB is not applicable yet.

## Testing status (PLAN §6)
- [x] Unit tests (no root): digest parsing, chain IDs, blob verification and corruption, name validation, extraction safety, whiteouts, xattr filtering, size parsing
- [x] Integration tests (`-tags integration`, root): isolation, OOM, pids limit, cpu throttle, overlay behaviour, many layers, signals, exit codes, parallel/sequential runs, prune
- [x] Leak checks (cgroups, overlay mounts, lock files) inside the integration tests
- [x] Fuzzing of the tar extractor
- [ ] Fuzzing of the image reference parser (M6)
- [ ] Unit tests for IPAM, config merge, state locking (later milestones)
- [ ] Leak check for veth devices / nftables rules (M7)

## Repo / process notes
- My local commits had initially included `.agent-sessions/`, `.cursor/`, `AGENTS.md` and `index.html`. They were removed from the pushed history and added to `.gitignore`.
- Bugs found by the cross-milestone testing and fixed: spec pipe deadlock with many layers, `.oldroot` race between parallel containers, prune touching another root's cgroups, regexp compile cost at startup.
