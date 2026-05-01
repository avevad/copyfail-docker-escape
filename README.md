Escape any Docker container with healthcheck enabled and run a command on the host.

Usage:
```
./poc.sh <HOST_COMMAND>
```

Settings:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DCF_WORK` | `/tmp/copyfail-poc-$(id -u)` | Staging directory, Python install root parent, and host-command output location. |
| `DCF_PYROOT` | `$DCF_WORK/pyroot` | Directory where the standalone Python tarball is unpacked. |
| `DCF_PY` | `$DCF_PYROOT/bin/python3` | Python interpreter used by all helper scripts. |
| `DCF_SUIDBIN` | `/usr/bin/passwd` | SUID binary patched for the first container-root pivot. It must execute the patched bytes as root and inherit stdin. |
| `DCF_HEALTHBIN` | `/bin/busybox` | In-container binary patched to `#!/proc/self/exe --help` so the next healthcheck/runc exec leaves a catchable runc fd. |
| `DCF_INTERVAL` | `5` | Expected seconds between healthcheck/runc exec events. The runc catcher waits for 24 intervals, with a 30 second minimum. |
| `DCF_FAKE_LOADER_SLEEP` | `1` | Seconds that the fake ELF interpreter sleeps to keep the runc process catchable. |
| `DCF_FAKE_LOADER_PATH` | unset | If set, install only this fake ELF interpreter path instead of the default glibc loader path list. |
| `DCF_HOST_CMD_TIMEOUT` | `240` | Seconds to wait for the patched host runc payload to write command output back into `DCF_WORK`. |
