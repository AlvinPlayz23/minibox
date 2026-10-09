#!/bin/sh
# Download and extract an Alpine minirootfs into ./rootfs (or $1).
set -e
DEST=${1:-rootfs}
case $(uname -m) in x86_64) A=x86_64;; aarch64) A=aarch64;; *) echo unsupported arch; exit 1;; esac
V=3.20.3
mkdir -p "$DEST"
curl -fsSL "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/$A/alpine-minirootfs-$V-$A.tar.gz" | tar -xz -C "$DEST"
echo "rootfs ready in $DEST"
