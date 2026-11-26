#!/usr/bin/env bash

parse_release_version() {
    local version=$1

    [[ $version =~ ^([0-9]+([.][0-9]+)*)(_([0-9]+))?-ion$ ]] || {
        echo "Invalid release version: $version" >&2
        return 1
    }

    MAJOR_VER=${BASH_REMATCH[1]}
    MINOR_VER=${BASH_REMATCH[4]:-0}
    if [[ -n "${BASH_REMATCH[4]:-}" ]]; then
        ARTIFACT_EXTENDNO="${MINOR_VER}-ion"
    else
        ARTIFACT_EXTENDNO="ion"
    fi
}
