# minibox
Daemonless, Docker-like container runtime in Go (see PLAN.md). Status: **M1**.
```
make build
bench/fetch-rootfs.sh rootfs
sudo bin/minibox run-raw ./rootfs /bin/sh -c 'hostname; ps; echo $$'
make bench
```
Linux only, needs root for now. Set `MINIBOX_ROOT` for state (used from M4).
