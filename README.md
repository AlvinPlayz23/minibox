# minibox

A fast, daemonless, Docker-like container runtime in Go. Status: **M1–M10 complete**
(isolation, rootfs, cgroup limits, layered storage, lifecycle CLI, registry pull,
networking, security hardening, volumes/build/compose, performance pass).

## Requirements

- Linux 5.7+ (6.8+ recommended for many-layer images), cgroup v2 unified hierarchy
- Root for bridge networking, mounts and cgroups (rootless mode works with
  `pasta`/host networking; user namespaces must be permitted by the kernel)
- Go 1.22+ to build; `nft` + `ip` for bridge networking; `pasta` (package `passt`)
  for rootless networking
- Optional for benchmarks: `hyperfine`, Docker, Podman, `runc`/`crun`

## Installation

```
git clone https://github.com/AlvinPlayz23/minibox && cd minibox
make build                 # static binary at bin/minibox (CGO_ENABLED=0, ~8.5 MB)
sudo make test-integration # optional: full suite, needs root
```

`minibox` is a single static binary — copy `bin/minibox` anywhere on your `PATH`.
No daemon, no installation beyond that. All state lives under `MINIBOX_ROOT`
(default `/var/lib/minibox`, or `~/.local/share/minibox` when not root):

```
$MINIBOX_ROOT/
|-- blobs/sha256/<hex>            # compressed layer blobs
|-- layers/<chainid>/diff/        # unpacked layers (overlay lowerdirs)
|-- images/<registry>/<repo>/<tag>.json
|-- volumes/<name>/_data          # named volumes
|-- network/ipam.json             # bridge IP leases
|-- build-cache.json              # build step cache
`-- containers/<id>/              # config.json, state.json, upper/work/merged, log, net.json
```

## Quick start

```
sudo bin/minibox run --rm alpine echo hi        # pulls docker.io/library/alpine on demand
sudo bin/minibox pull debian:stable-slim
sudo bin/minibox run -d --name web -p 8080:80 nginx
sudo bin/minibox ps; sudo bin/minibox logs web; sudo bin/minibox exec web sh
sudo bin/minibox stop web && sudo bin/minibox rm web
```

## Usage

```
minibox run [flags] IMAGE [CMD...]
    -d, --detach     --rm      --name NAME
    -it              (tty + stdin)
    -e KEY=VAL       -v SRC:DST[:ro]  --tmpfs DST[:size=64m][,ro]
    -w DIR  -u USER  -p HOST:CONT[/udp]  --network bridge|host|none|pasta
    --memory 64m  --cpus 0.5  --pids-limit N  --hostname NAME
    --read-only  --cap-add/--cap-drop CAP  --seccomp default|unconfined
    --restart no|always|on-failure[:N]|unless-stopped  --health-cmd "CMD..."
minibox ps [-a] [--json]            minibox images [--json]
minibox pull [-q] [--stats] IMAGE   minibox rmi IMAGE...
minibox exec [-it] [-e K=V] [-w DIR] [-u USER] CONTAINER CMD...
minibox logs [-f] CONTAINER         minibox stop [-t SECS] CONTAINER...
minibox rm [-f] CONTAINER...        minibox inspect CONTAINER|IMAGE
minibox build -t NAME [-f Dockerfile] [--build-arg K=V] PATH
minibox up [-f FILE] [-p PROJECT]   minibox down [-f FILE] [-p PROJECT]
minibox volume ls|create|rm|inspect|prune
minibox systemd [-o DIR] CONTAINER  minibox healthcheck CONTAINER
minibox load [-i FILE] NAME[:TAG]   minibox system prune
minibox version
```

Every listing command supports `--json`. Exit code of `run`/`exec` equals the
container's/command's exit code. `run` auto-pulls missing images.

### Examples

```
# Volumes: bind, read-only, named (persists), tmpfs
bin/minibox run --rm -v /host/dir:/data alpine sh -c 'echo hi > /data/f'
bin/minibox run --rm -v mydata:/data:ro --tmpfs /run:size=64m alpine sh

# Dockerfile subset: FROM RUN COPY ENV WORKDIR CMD ENTRYPOINT EXPOSE USER ARG
bin/minibox build -t myapp:1.0 ./myapp
bin/minibox run --rm myapp:1.0

# Compose subset (services: image, command, ports, environment, volumes,
# network, restart, working_dir, user, hostname)
bin/minibox up -f minibox.yml && bin/minibox down -f minibox.yml

# systemd unit for a container (restart policy included, no daemon needed)
bin/minibox systemd -o /etc/systemd/system myservice
```

## Specifications and performance targets

| Metric | Target | Measured (M10, kernel 6.18) |
|---|---|---|
| Warm `run --rm alpine true` (`--network none`) | < 50 ms | ~26–31 ms mean, ~15 ms min |
| Warm `run --rm` with bridge networking | < 150 ms | ~88 ms mean |
| Idle RAM (no containers) | 0 (no daemon) | 0 |
| RSS of detached-container shim | < 5 MB | 3.8 MB (VmHWM) |
| Binary size | < 15 MB | 8.5 MB static |
| Peak RSS pulling ~100+ MB image | record, keep low | ~16 MB for 152 MB postgres:16 |
| `docker run --rm alpine true` same box | comparison | ~567 ms mean (minibox ~22x faster) |
| `runc run` same box | floor | ~43 ms mean (minibox ~1.7x faster) |

See `docs/BENCHMARKS.md` (method + per-milestone numbers) and run
`bench/compare.sh [IMAGE] [CMD]` to reproduce the comparison on your machine
(hyperfine optional; works with docker and/or podman, whichever exist).

## Security

Rootful containers get Docker's default 14 capabilities, `no_new_privs`, and a
pure-Go seccomp-BPF default profile (blocked syscalls → `EPERM`; `--cap-add`
re-allows per capability). Untested-code warning: this project has no security
track record — see `docs/SECURITY.md` for the threat model and known gaps
(no AppArmor/SELinux, container root is host root when rootful, rootless mode
is implemented but could not be exercised on the dev VM).

## Limitations (honest)

- No Docker API socket, no multi-stage builds (`COPY --from` rejected), no
  `ADD` URL/tar magic, no lazy pulling, no Compose `depends_on`/networks/build.
- Published ports bind all host addresses; no host-IP binding.
- Registry auth: anonymous + basic (`MINIBOX_REGISTRY_USER/PASS` or
  `~/.docker/config.json`); no credential helpers. Plain HTTP only for
  localhost / `MINIBOX_INSECURE_REGISTRIES`.
- Rootless: single-ID user mapping, no cgroup limits, no `exec`, pasta-based
  networking; **untested** (dev sandbox forbids user namespaces).
- `system prune` also GCs unreferenced layers/blobs; volumes are never touched
  by it (use `minibox volume prune`).

## Tests

`make test` (unit, no root), `make test-integration` (needs root; uses temp
`MINIBOX_ROOT`, leak-checks cgroups/mounts/veth/nftables/IPAM),
`go test ./internal/image -run x -fuzz FuzzExtract -fuzztime 60s`,
`go test ./internal/image -run x -fuzz FuzzParseReference -fuzztime 30s`.
