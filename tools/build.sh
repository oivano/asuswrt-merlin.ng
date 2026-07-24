#!/bin/bash
MAKEFLAGS="-j 1"
PROJECT_DIR="."
CHANGELOG_FILE="/tmp/CHANGELOG"
MODEL="dsl-ac68u"
SDK_PLATFORM="sdk"
RELEASE_DIR="src-rt-6.x.4708"

rm -f ${PROJECT_DIR}/release/${RELEASE_DIR}/toolchains
ln -s /opt/am-toolchains/brcm-arm-sdk  ${PROJECT_DIR}/release/${RELEASE_DIR}/toolchains

export MERLINUPDATE=y
cd ${PROJECT_DIR}/release/${RELEASE_DIR}
make clean
make ${MODEL} | tee "/tmp/build.log" # | grep -i "error\|-e"

# Verify build output exists
if [ ! -d "${PROJECT_DIR}/release/${RELEASE_DIR}/image/" ]; then
    echo "Error: Build output directory not found"
    exit 1
fi

ls ${PROJECT_DIR}/release/${RELEASE_DIR}/image/
