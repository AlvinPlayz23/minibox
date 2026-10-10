# minibox progress checklist

Legend: `[x]` done and verified; `[ ]` not done. "Verified" means exercised by a test or a manual run on the dev VM
(Linux 6.18, cgroup v2, root, Go 1.27). Nothing is checked on the strength of "it compiles".

Status: **M1–M10 done (verified below). M9 Docker-API socket / multi-stage / ADD magic / lazy pulling explicitly out of scope; rootless path implemented but untestable in this sandbox.**

## Working agreements (PLAN §0)
- [x] State under `MINIBOX_ROOT`; tests use temp roots
- [x] One milestone at a time, one commit each
- [x] Benchmark harness built first; results in `docs/BENCHMARKS.md` after each milestone
- [x] Minimal dependencies (`golang.org/x/sys/unix`, plus `klauspost/compress` for zstd and `vishvananda/netlink` for veth/bridge — both justified in `docs/DECISIONS.md`)
- [x] Static build (`CGO_ENABLED=0 -trimpath -ldflags="-s -w"`), size tracked (8.5 MB at M10, target <15 MB)
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
- [x] `run`, `ps`, `stop`, `rm`, `logs`, `exec` (pid-netns join via `/proc/PID/root` chroot + thread pre-warm), `inspect`
- [x] `state.json` with locking; foreground supervisor and detached shim
- [x] Signal forwarding (SIGINT/SIGTERM/SIGHUP/SIGWINCH), PTY (`-it`, raw mode, resize), exit-code propagation, log rotation (10 MB x 3)
- [x] Zombie reaping / `--init` (default on; +8 ms vs `--init=false`)
- [x] Accept: `run -d`, `ps`, `logs -f`, `exec -it sh`, `stop`, `rm`; Ctrl-C stops a foreground container (rc 130)
- [x] Accept: killing the shim shows Dead, prune reaps cgroup+network, `rm` works; 100 sequential `run --rm` leave nothing
- Notes: PID 1 signal problem solved by `--init` reaper; `stop -t` escalates to cgroup SIGKILL (verified ~1 s for `--init=false sleep`).

## M6: image pull (OCI registries)
- [x] Reference parsing (docker.io normalization, digest refs), custom stdlib registry v2 client with bearer+basic auth, platform selection, digest verification
- [x] Parallel download (3x) plus streaming unpack, gzip and zstd
- [x] Apply image config; `images`, `pull`, `rmi` (refuses in-use), GC (skips while store RLocked)
- [x] Accept: alpine, busybox and debian-slim run from a clean store; peak RSS 16 MB for 152 MB postgres:16; corrupted blob rejected (digest mismatch), diffID verified pre-publish
- Notes: `run` auto-pulls missing images. Registry faked in unit tests (bearer flow, index selection, corruption).

## M7: networking
- [x] none/host/bridge/pasta, file-locked IPAM, nftables NAT + port publishing, DNS/hosts files, crash-safe cleanup via net.json
- [x] Accept: internet and DNS, container-to-container by IP, `-p 8099:80` serves on localhost and host IP (busybox httpd; official alpine has no httpd)
- [x] Network setup time measured: ~30–46 ms (`MINIBOX_TRACE=1`), bridge mean run ~88 ms (<150 ms target)
- Notes: pasta as root fails in this sandbox (netns open denied even with --runas); rootless pasta untested. Own `ip minibox` table never touches other tables.

## M8: security hardening and rootless
- [x] Single-ID user namespace, capability drop (Docker default 14; `--cap-add/--cap-drop`, ALL), `no_new_privs`, pure-Go seccomp BPF, read-only rootfs, `--user`, rootless overlayfs (userxattr + xattr whiteouts)
- [x] `docs/SECURITY.md` (threat model + honest gaps; no parity claims)
- [x] Accept (rootful): CapEff/Bnd `a80425fb`, NNP=1, mount/unshare blocked (EPERM), `--cap-add SYS_ADMIN` re-enables mount, `--cap-drop ALL` zeroes caps, `/proc/kcore` denied; exec'd processes hardened too
- Notes: rootless path **implemented but untestable** — sandbox forbids CLONE_NEWUSER even for root. `exec` rootless returns a clear error.

## M9: optional extras
- [x] Volumes/tmpfs (`-v SRC:DST[:ro]`, named volumes, `--tmpfs`, `volume ls|create|rm|inspect|prune` with in-use protection; securejoin ResolveInRoot)
- [x] `build` for Dockerfile subset (FROM RUN COPY ENV WORKDIR CMD ENTRYPOINT EXPOSE USER ARG) with layer caching; errors clearly on ADD/`COPY --from`/multi-stage/unknown instructions
- [x] Compose-like `up/down` (dependency-free YAML subset: image/command/ports/environment/volumes/network/restart/working_dir/user/hostname)
- [x] Healthchecks (`--health-cmd` + `healthcheck`), restart policies (`--restart` + `systemd` unit generator)
- [ ] Docker API socket, multi-stage builds, ADD magic, lazy pulling — explicitly out of scope (README + ARCHITECTURE say so)

## M10: performance pass
- [x] strace hot-path audit (~1790 syscalls/run, runtime-dominated; 22 mounts, 33 prctl, 1 seccomp — nothing removable), CLI startup <5 ms, no tuning knobs needed
- [x] Lazy init already in place (lazy regexp); binary size re-checked (8.5 MB)
- [x] Final comparison table in `docs/BENCHMARKS.md` + `bench/compare.sh` automation (minibox vs docker vs podman vs runc, hyperfine or fallback loop)
- Final numbers: no-net ~26–31 ms mean (~15 ms min, target <50 ms); bridge ~88 ms (<150 ms); shim 3.8 MB (<5 MB); minibox ~22x faster than docker, ~1.7x faster than runc on this VM

## Testing status (PLAN §6)
- [x] Unit tests (no root): digest parsing, chain IDs, blob verification and corruption, name validation, extraction safety, whiteouts (+xattr whiteouts), xattr filtering, size parsing, reference parsing, volume/mount spec parsing, Dockerfile + compose parsers, seccomp BPF interpreter verdicts, IPAM (+concurrent uniqueness)
- [x] Integration tests (`-tags integration`, root): isolation, OOM, pids limit, cpu throttle, overlay behaviour, many layers, signals, exit codes, parallel/sequential runs, prune, full M5 lifecycle, M6 pull-run, M7 networking + port publishing + leak checks, M8 caps/seccomp/read-only/user, M9 volumes/build/up-down/systemd/healthcheck
- [x] Leak checks (cgroups, overlay mounts, lock files, veth, nftables rules, IPAM leases) inside the integration tests
- [x] Fuzzing of the tar extractor and the image reference parser (30 s, 237k execs, fixed tag+digest round-trip bug)
- [x] Benchmark automation `bench/compare.sh` (minibox vs docker vs podman vs runc; podman covered when installed)

## Repo / process notes
- My local commits had initially included `.agent-sessions/`, `.cursor/`, `AGENTS.md` and `index.html`. They were removed from the pushed history and added to `.gitignore`.
- Bugs found by the cross-milestone testing and fixed: spec pipe deadlock with many layers, `.oldroot` race between parallel containers, prune touching another root's cgroups, regexp compile cost at startup.
