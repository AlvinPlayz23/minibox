# Decisions
- M1: only dependency is golang.org/x/sys/unix (required syscalls).
- M1: `run-raw` uses a fixed hostname "minibox" and a minimal env; replaced by real config in later milestones.
- Open questions (PLAN §11) use their stated defaults for now.
- M3: liveness via flock rather than PID files (survives kill -9, no PID reuse races).
- M3: `--memory` also sets swap.max=0 so OOM is deterministic.
- M4: whiteouts converted to overlay-native form at unpack time (as Docker's overlay2 does), so layers are directly usable as lowerdirs.
- M4: overlay is mounted by init inside the container mount namespace instead of by the supervisor: no host-visible mounts to leak.
- M4: strict extraction — a symlink in a parent path component is an error rather than resolved "within root" (securejoin style). Layers produced by `docker save`/registries never need it; revisit if a real image breaks.
- M4: absolute names in tars are re-rooted (GNU tar behaviour); `..` anywhere is rejected.
- M4: layer-count limit: ~126 layers via classic mount (short fd links), up to the kernel's 500 via fsconfig on Linux ≥6.8.
- M4: compressed blobs are kept after unpack (PLAN §11.2 default).
- M4: no new dependencies.
## Known gaps found while testing M1–M4
- PID 1 in the container ignores SIGTERM/SIGINT unless it installs handlers (kernel rule). Supervisor forwards signals; `stop` escalation and `--init` are M5.
- `/proc/self/mountinfo` inside the container shows host paths (rootfs / overlay options). Information leak, not an escape; may be masked later.
- Container still runs with full root capabilities and no seccomp until M8.
