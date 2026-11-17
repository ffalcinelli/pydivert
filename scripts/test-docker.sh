#!/bin/bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
# Run PyDivert's Linux test suite inside a privileged Docker container.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE_NAME="${PYDIVERT_TEST_IMAGE:-pydivert-test}"
UID_GID="$(id -u):$(id -g)"

docker build -t "$IMAGE_NAME" -f "$REPO_DIR/Dockerfile.test" "$REPO_DIR"

EXTRA_ARGS=()
if [ -n "${PYDIVERT_EBPFDIVERT_LIB:-}" ]; then
    EXTRA_ARGS+=(-v "${PYDIVERT_EBPFDIVERT_LIB}:/tmp/local_libebpfdivert.so:ro")
    EXTRA_ARGS+=(-e "PYDIVERT_EBPFDIVERT_LIB=/tmp/local_libebpfdivert.so")
fi

exec docker run --rm --privileged --pid=host \
    -v "$REPO_DIR:/src:ro" \
    -v "$REPO_DIR:/out" \
    -e "HOST_UID_GID=$UID_GID" \
    "${EXTRA_ARGS[@]}" \
    "$IMAGE_NAME" \
    bash -ceu '
        mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
        mountpoint -q /sys/fs/cgroup || mount -t cgroup2 none /sys/fs/cgroup
        mkdir -p /tmp/work
        tar -C /src --exclude=.venv --exclude=.git --exclude=.pytest_cache -cf - . | tar -C /tmp/work -xf -
        cd /tmp/work
        PYDIVERT_DIR=/tmp/work bash scripts/run-tests-linux.sh "$@"
        if [ -f /tmp/work/.coverage.linux ]; then
            cp /tmp/work/.coverage.linux /out/.coverage.linux
            chown "$HOST_UID_GID" /out/.coverage.linux
        fi
    ' -- "$@"
