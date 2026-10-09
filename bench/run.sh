#!/bin/sh
# Benchmark minibox run-raw against docker/podman/crun/runc, whichever exist.
# Usage: bench/run.sh   (needs root; hyperfine in PATH)
set -e
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/share/mise/shims:$PATH"
ROOTFS=${ROOTFS:-$PWD/rootfs}
[ -d "$ROOTFS/bin" ] || bench/fetch-rootfs.sh "$ROOTFS"
CMDS="$PWD/bin/minibox run-raw $ROOTFS /bin/true"
if command -v runc >/dev/null; then
  B=$(mktemp -d); cp -a "$ROOTFS" "$B/rootfs"
  (cd "$B" && runc spec && sed -i 's/"terminal": true/"terminal": false/; s/"sh"/"\/bin\/true"/' config.json)
  RUNC="cd $B && runc run mb-bench-\$\$"
fi
set -- -N --warmup 5 --runs ${RUNS:-50} --export-markdown /tmp/bench.md
set -- "$@" -n minibox "$CMDS"
if command -v crun >/dev/null; then :; fi
[ -n "$RUNC" ] && set -- "$@" -n runc "sh -c '$RUNC'"
if docker info >/dev/null 2>&1 && docker image inspect alpine >/dev/null 2>&1; then set -- "$@" -n docker "docker run --rm alpine true"; fi
if command -v podman >/dev/null; then set -- "$@" -n podman "podman run --rm alpine true"; fi
hyperfine "$@"
echo; cat /tmp/bench.md
