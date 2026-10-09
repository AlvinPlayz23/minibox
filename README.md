# minibox
Daemonless, Docker-like container runtime in Go (see PLAN.md). Status: **M4** (isolation, pivot_root, cgroup limits, layered overlay storage).
```
make build
bench/fetch-rootfs.sh rootfs
sudo bin/minibox run-raw ./rootfs /bin/sh -c 'hostname; ps; echo $$'
make bench
```
Linux only, needs root for now. Set `MINIBOX_ROOT` for state (used from M4).

## Images (M4)
```
tar -C rootfs -cf - . | sudo bin/minibox load myimg      # or: load -i rootfs.tar.gz myimg:1.0
sudo bin/minibox run-raw --image myimg --memory 64m /bin/sh -c 'echo hi'
sudo bin/minibox system prune                              # remove leftovers of killed runs
```
`MINIBOX_ROOT` (default /var/lib/minibox) holds blobs, layers, images and containers.

## Tests
`make test` (unit + fuzz seeds, no root), `make test-integration` (needs root and `bench/fetch-rootfs.sh`),
`go test ./internal/image -run x -fuzz FuzzExtract -fuzztime 60s`.
