# Decisions
- M1: only dependency is golang.org/x/sys/unix (required syscalls).
- M1: `run-raw` uses a fixed hostname "minibox" and a minimal env; replaced by real config in later milestones.
- Open questions (PLAN §11) use their stated defaults for now.
- M3: liveness via flock rather than PID files (survives kill -9, no PID reuse races).
- M3: `--memory` also sets swap.max=0 so OOM is deterministic.
