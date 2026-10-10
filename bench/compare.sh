#!/bin/sh
# Compare container startup across minibox, docker, podman and runc on one image.
# Usage: bench/compare.sh [IMAGE] [CMD...]
#   IMAGE defaults to alpine; CMD defaults to true. Argument boundaries are
#   preserved (each argv element is shell-quoted once).
#   All runtimes use isolated/none networking so only process startup is
#   measured (minibox --network none, docker/podman --network none).
#   Uses hyperfine when available, else a python3 timing loop.
#   Missing runtimes are skipped with a note (podman is optional).
set -e
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/share/mise/shims:$PATH"

IMAGE=${1:-alpine}; shift 2>/dev/null || true
if [ "$#" -eq 0 ]; then set -- true; fi
# Shell-quote each argv element once; every consumer below parses quotes
# (hyperfine -N word-splits quote-aware, sh -c parses normally).
CMD_STR=""
for a in "$@"; do
  CMD_STR="$CMD_STR '$(printf "%s" "$a" | sed "s/'/'\\''/g")'"
done
CMD_STR=${CMD_STR# }

BIN=$PWD/bin/minibox
[ -x "$BIN" ] || { echo "building minibox..."; make build >/dev/null; }
export MINIBOX_ROOT=${MINIBOX_ROOT:-$(mktemp -d)}
echo "MINIBOX_ROOT=$MINIBOX_ROOT" >&2

# Make sure the image exists locally for minibox (pulls on demand).
if ! "$BIN" images 2>/dev/null | grep -q .; then :; fi
"$BIN" pull -q "$IMAGE" >&2 2>/dev/null || {
  echo "note: could not pull $IMAGE for minibox; trying existing store" >&2
}

MB="env MINIBOX_ROOT=$MINIBOX_ROOT $BIN run --rm --network none $IMAGE $CMD_STR"
HAVE_DOCKER=; HAVE_PODMAN=; HAVE_RUNC=
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE" >&2 2>/dev/null || true
docker image inspect "$IMAGE" >/dev/null 2>&1 && HAVE_DOCKER=1 || echo "note: docker image $IMAGE unavailable, skipping docker" >&2
if command -v podman >/dev/null 2>&1; then
  podman image exists "$IMAGE" 2>/dev/null || podman pull "$IMAGE" >&2 2>/dev/null || true
  podman image exists "$IMAGE" 2>/dev/null && HAVE_PODMAN=1 || echo "note: podman image $IMAGE unavailable, skipping podman" >&2
else
  echo "note: podman not installed, skipping" >&2
fi
command -v runc >/dev/null 2>&1 && HAVE_RUNC=1 || echo "note: runc not installed, skipping" >&2

# runc needs an OCI bundle; use ./rootfs when present and set the bundle's
# process args to the requested CMD so it measures the same workload.
RUNC_BUNDLE=""
if [ -n "$HAVE_RUNC" ]; then
  if [ -d "$PWD/rootfs/bin" ]; then
    RUNC_BUNDLE=$(mktemp -d)
    cp -a "$PWD/rootfs" "$RUNC_BUNDLE/rootfs"
    (cd "$RUNC_BUNDLE" && runc spec >/dev/null 2>&1 && sed -i 's/"terminal": true/"terminal": false/' config.json) || RUNC_BUNDLE=""
    if [ -n "$RUNC_BUNDLE" ]; then
      python3 - "$RUNC_BUNDLE" "$@" <<'EOF'
import json,sys
b=sys.argv[1]; args=sys.argv[2:]
with open(b+'/config.json') as f: cfg=json.load(f)
cfg['process']['args']=args
with open(b+'/config.json','w') as f: json.dump(cfg,f,indent=2)
EOF
      echo "runc bundle: $RUNC_BUNDLE (rootfs/ copy, args: $*)" >&2
    fi
  else
    echo "note: ./rootfs missing (run bench/fetch-rootfs.sh), skipping runc" >&2
    HAVE_RUNC=
  fi
fi

RUNS=${RUNS:-15}
if command -v hyperfine >/dev/null 2>&1; then
  set -- --warmup 3 --runs "$RUNS" -N --export-markdown /tmp/compare.md
  set -- "$@" -n minibox "$MB"
  [ -n "$HAVE_DOCKER" ] && set -- "$@" -n docker "docker run --rm --network none $IMAGE $CMD_STR"
  [ -n "$HAVE_PODMAN" ] && set -- "$@" -n podman "podman run --rm --network none $IMAGE $CMD_STR"
  [ -n "$HAVE_RUNC" ] && set -- "$@" -n runc "sh -c 'cd $RUNC_BUNDLE && runc run mb-compare-$$'"
  hyperfine "$@"
  echo; cat /tmp/compare.md
else
  echo "note: hyperfine not found, using built-in timing loop (${RUNS} runs each)" >&2
  python3 - "$RUNS" "$MB" "$HAVE_DOCKER" "$HAVE_PODMAN" "$IMAGE" "$CMD_STR" <<'EOF'
import subprocess, sys
runs = int(sys.argv[1]); mb = sys.argv[2]
have_docker = sys.argv[3]; have_podman = sys.argv[4]
image = sys.argv[5]; cmd = sys.argv[6]
def bench(name, argv, **kw):
    ts = []
    for _ in range(runs):
        t0 = __import__('time').perf_counter()
        subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)
        ts.append((__import__('time').perf_counter() - t0) * 1000)
    ts.sort()
    print(f"| `{name}` | {sum(ts)/len(ts):.1f} | {ts[0]:.1f} |")
print(f"\n| runtime | mean [ms] ({runs} runs) | min [ms] |")
print("|---|---|---|")
bench("minibox", ["sh", "-c", mb])
if have_docker:
    bench("docker", ["sh", "-c", f"docker run --rm --network none {image} {cmd}"])
if have_podman:
    bench("podman", ["sh", "-c", f"podman run --rm --network none {image} {cmd}"])
EOF
fi
