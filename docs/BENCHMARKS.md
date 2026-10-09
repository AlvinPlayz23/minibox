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
