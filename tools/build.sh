#!/bin/bash
set -euo pipefail

IMAGE="ivano/asuswrt-merlin-toolchains-custom:latest"
MODEL="dsl-ac68u"
RELEASE_DIR="src-rt-6.x.4708"
# CircleCI's docker executor checks this repo out at ~/project (/home/docker/project); the
# committed release/src-rt-6.x.4708/toolchains symlink is a *relative* path
# (../../../am-toolchains/brcm-arm-sdk) that only resolves to the image's baked-in toolchain SDK
# at that exact mount point, so re-exec into the container at this same path.
CONTAINER_PROJECT_DIR="/home/docker/project"
CONTAINER_NAME="asuswrt-dsl-ac68u-build"

# Single entry point for both human and agent use, on the host side only (this whole block is
# skipped once we're actually inside the container). The container itself always runs detached
# (docker run -d) and this script just attaches to its logs in the foreground -- so the build is
# never tied to this shell/terminal's lifetime: killing/disconnecting this command (or the
# terminal it runs in) never stops the build, and simply re-running "./tools/build.sh" reattaches
# to the same in-progress build instead of starting a duplicate one. No separate nohup/tail/docker
# command is ever required -- this one script call does it all.
if [ ! -f /.dockerenv ]; then
    REPO_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
    OUTPUT_DIR="${REPO_DIR}/tools/build"
    mkdir -p "${OUTPUT_DIR}"
    docker pull "$IMAGE"

    if [ "${1:-}" = "--shell" ]; then
        exec docker run -it --rm \
            -v "${REPO_DIR}:${CONTAINER_PROJECT_DIR}" \
            -w "${CONTAINER_PROJECT_DIR}" \
            -u "$(id -u):$(id -g)" \
            "$IMAGE" bash
    fi

    if [ "$(docker inspect -f '{{.State.Running}}' "${CONTAINER_NAME}" 2>/dev/null)" != "true" ]; then
        docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
        docker run -d --name "${CONTAINER_NAME}" \
            -v "${REPO_DIR}:${CONTAINER_PROJECT_DIR}" \
            -w "${CONTAINER_PROJECT_DIR}" \
            -u "$(id -u):$(id -g)" \
            "$IMAGE" "${CONTAINER_PROJECT_DIR}/tools/build.sh" >/dev/null
    fi

    echo "Following build log (Ctrl-C or a dropped connection here does NOT stop the build --"
    echo "just re-run ./tools/build.sh to reattach; build.sh also streams it live to"
    echo "${OUTPUT_DIR}/build.log) ..."
    docker logs -f "${CONTAINER_NAME}" || true
    EXIT_CODE=$(docker wait "${CONTAINER_NAME}")

    # The container writes directly into the bind-mounted repo (both the log, see LOG_FILE below,
    # and release/${RELEASE_DIR}/image/), so these are already on the host in real time -- just
    # copy the firmware image(s) into the output dir too for convenience, no docker cp needed.
    cp -f "${REPO_DIR}/release/${RELEASE_DIR}"/image/*.trx "${OUTPUT_DIR}/" 2>/dev/null || true
    cp -f "${REPO_DIR}/release/${RELEASE_DIR}"/image/*.trx.sha256 "${OUTPUT_DIR}/" 2>/dev/null || true

    docker rm "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    echo "Output in ${OUTPUT_DIR}"
    exit "${EXIT_CODE}"
fi

# --- everything below runs inside the container ---

MAKEFLAGS="-j 1"
PROJECT_DIR="${CONTAINER_PROJECT_DIR}"
BUILD_ROOT="${PROJECT_DIR}/release/${RELEASE_DIR}"
# Written under the bind-mounted repo (not /tmp) so it streams live to tools/build/build.log on
# the host as the build runs, instead of only appearing via docker cp after the container exits.
LOG_FILE="${PROJECT_DIR}/tools/build/build.log"

# This tree's Makefiles don't fully clean up after themselves (leftover .config, .o/.cmd files,
# whole untracked dirs like openssl/ or et/linux/, etc.), so repeated local builds accumulate
# drift `make clean` never removes. Reset to a CI-equivalent pristine tree automatically on every
# run -- never touches tracked files (git clean can't remove those, modified or not) or gitignored
# ones (no -x), only untracked-and-not-ignored build cruft under release/, so no manual cleanup is
# needed.
echo "Removing untracked build artifacts under release/ ..."
git -C "${PROJECT_DIR}" clean -fd -- release/

# release/src-rt-6.x.4708/toolchains is a *committed* relative symlink; do NOT recreate/rewrite it
# here -- it's tracked in git and a machine-specific rewrite just dirties the tree; read it
# instead, with a same-image fallback if it doesn't resolve (e.g. run outside this container).
TOOLCHAIN_NAME="hndtools-arm-linux-2.6.36-uclibc-4.5.3"
TOOLCHAIN_SDK_DIR=$(readlink -f "${BUILD_ROOT}/toolchains" 2>/dev/null || true)
if [ -n "${TOOLCHAIN_SDK_DIR}" ] && [ -d "${TOOLCHAIN_SDK_DIR}/${TOOLCHAIN_NAME}" ]; then
    TOOLCHAIN_BIN_DIR="${TOOLCHAIN_SDK_DIR}/${TOOLCHAIN_NAME}"
elif [ -d /opt/brcm-arm ]; then
    # ivano/asuswrt-merlin-toolchains-custom bakes in this convenience symlink directly to the
    # hndtools-* dir, for use when the repo isn't mounted at $HOME/project.
    TOOLCHAIN_BIN_DIR=/opt/brcm-arm
else
    echo "Error: ARM toolchain SDK not found (repo isn't mounted at ${CONTAINER_PROJECT_DIR} and" >&2
    echo "no /opt/brcm-arm fallback exists in this image)." >&2
    exit 1
fi

export MAKEFLAGS MERLINUPDATE=y
# Append (not prepend) the toolchain bin dir: its own perl-based autom4te/aclocal shadow the
# system ones and break autoreconf (missing Autom4te::C4che) if placed first on PATH.
export PATH="${PATH}:${TOOLCHAIN_BIN_DIR}/bin"
export LD_LIBRARY_PATH="${TOOLCHAIN_BIN_DIR}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
cd "${BUILD_ROOT}"
# Force stdin closed for the actual build: "make dsl-ac68u" walks kernel/router Kconfig-style
# prompts via config/conf, and any symbol not yet answered in the checked-in .config shows as
# "(NEW)" and blocks on a real keypress if its stdin is a TTY. The detached `docker run -d` above
# already has no TTY, but keep this explicit in case build.sh is ever invoked another way. Use
# `./tools/build.sh --shell` if you need to answer prompts interactively (e.g. make menuconfig).
make clean </dev/null
make "${MODEL}" </dev/null 2>&1 | tee "${LOG_FILE}"

shopt -s nullglob
images=("${BUILD_ROOT}/image"/*.trx)
if [ "${#images[@]}" -eq 0 ]; then
    echo "Error: No firmware image was produced" >&2
    exit 1
fi

for image in "${images[@]}"; do
    (cd "$(dirname "${image}")" && sha256sum "$(basename "${image}")" > "$(basename "${image}").sha256")
done

printf '%s\n' "${images[@]}"
