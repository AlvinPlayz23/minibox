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
