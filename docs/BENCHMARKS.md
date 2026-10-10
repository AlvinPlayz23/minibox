# Benchmarks

Method: `bench/run.sh` (hyperfine, 5 warmup, 30 runs). Env: Railway VM, kernel 6.18, root, Go 1.27, Alpine 3.20 minirootfs.
Binary: `CGO_ENABLED=0 -trimpath -ldflags="-s -w"`.

## M1 baseline (trivial `/bin/true`)

| Command | Mean wall [ms] | Notes |
|---|---:|---|
| `minibox run-raw rootfs /bin/true` | 67.8 ± 24.8 (min 38.3) | chroot, 5 namespaces, /proc mount |
| `runc run` (default spec, rootfs copy) | 281.3 ± 34.4 | |
| docker / podman | n/a | alpine image not pulled / podman not installed on this VM |

Binary size: 1.96 MB. High variance is from a shared VM. Target <50 ms is met at best-case (min 38 ms); revisit in M10.

## M2 (pivot_root + /dev, /sys, masks)

| Command | Mean wall [ms] |
|---|---:|
| `minibox run-raw rootfs /bin/true` | 50.4 ± 22.3 (min 28.3) |

Binary 1.98 MB. Not slower than M1 (VM noise dominates).

## M3 (cgroup v2, CLONE_INTO_CGROUP)

| Command | Mean wall [ms] |
|---|---:|
| `minibox run-raw rootfs /bin/true` (cgroup created+removed) | 57.2 ± 16.5 (min 32.2) |

Binary 2.27 MB. ~+7 ms mean vs M2 is within VM noise but plausibly the cgroup mkdir/rmdir + flock; revisit in M10.

## M4 (overlayfs image run, pivot_root(".", "."))

| Command | Mean wall [ms] |
|---|---:|
| `minibox run-raw rootfs /bin/true` (dir rootfs) | 60.1 ± 16.3 (min 36.4) |
| `minibox run-raw --image img /bin/true` (overlayfs, 1 layer) | 54.6 ± 10.3 (min 42.3) |
| `runc run` | 281.2 ± 37.0 |

Paired A/B of the M3 binary vs M4 on the same dir-rootfs command (100 runs, interleaved): 50.9 ms vs 50.4 ms — no regression
(an earlier +3 ms came from regexps compiled at package init; now lazy). Overlay mount adds no measurable cost (it happens in the
container's own mount namespace). Binary 3.70 MB (was 2.27 MB: encoding/json, archive/tar, compress/gzip, regexp). Idle RSS of supervisor 4.3 MiB.

Streaming check: `minibox load` of a 300 MB layer (gzip, incompressible): 1.6 s, **peak RSS 17 MB**, stored blob digest equals sha256 of the input.

## M5 (lifecycle CLI, --init)
`run --rm alpine true`: ~20 ms mean (init on) vs ~12 ms (`--init=false`); init kept default
for correct signal/zombie behavior. 100 sequential `run --rm` leave nothing behind.

## M6 (registry pull)
`pull alpine`: ~1.1 s, 1 layer, 3 MB. `pull postgres:16`: 14 layers, 152 MB compressed,
10.96 s, **peak RSS 16 MB** (streaming verified). Corrupted blobs rejected by digest;
diffID verified before layer publish. Binary 7.7 MB (http/tls/zstd).

## M7 (bridge networking)
`MINIBOX_TRACE=1` network setup: ~30–46 ms of the run. Internet/DNS, container-to-container
and `-p` (localhost + host IP) verified with busybox httpd; leases/ports/veth reclaimed on
stop/rm/prune (including after `kill -9` of the shim).

## M8 (caps/seccomp/NNP/read-only)
No measurable regression vs M7 on `run --rm` (filter is 120 BPF instructions, one seccomp(2)).
Binary 8.3 MB.

## M9 (volumes/build/compose)
No hot-path change (mounts only when `-v`/`--tmpfs` given). Binary 8.5 MB.

## M10 final (hyperfine via `bench/compare.sh alpine true`, 6.18 kernel, this VM)

`compare.sh` measures process startup only: `--network none` for every runtime
(minibox, `docker --network none`, `podman --network none` when installed),
runc with the requested CMD written into the bundle. Typical result
(RUNS=10, noisy shared VM — re-run on your machine):

| runtime | mean [ms] | min [ms] | relative |
|---|---|---:|---:|
| minibox (`run --rm --network none alpine true`) | ~26–36 | ~15–24 | 1.00 |
| runc (minimal bundle, same `true`) | ~43–75 | ~28–49 | ~1.7–2.1x |
| docker (`docker run --rm --network none alpine true`) | ~370–570 | ~310–460 | ~10–22x |

Targets check: warm no-net ~26–36 ms mean (<50 ms ✓); warm bridge ~88 ms mean (<150 ms ✓);
idle RAM 0 ✓; shim VmHWM 3.8 MB (<5 MB ✓); binary 8.5 MB (<15 MB ✓);
pull postgres:16 peak RSS 16 MB (streaming ✓). Podman is covered by `compare.sh`
automatically when installed (absent here). Hot-path audit (`strace -c -f`): ~1790 syscalls/run,
dominated by Go runtime init in the 3 processes (CLI, init re-exec, init fork); container work
is 22 mounts, 6 mknods, 1 pivot_root, 33 prctl, 1 seccomp install — nothing removable without
dropping features, so no tuning knobs were added. Review follow-ups: the forward chain
policy is now drop (with bridge allows), and `MINIBOX_SUBNET` changes are reconciled
into the persistent table.
