#!/usr/bin/env python3
import json
import os
import shutil
import struct
import sys


STATE = "fake-loader-state.json"
DEFAULT_LOADERS = (
    "/lib64/ld-linux-x86-64.so.2",
    "/lib/ld-linux-x86-64.so.2",
    "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
)


def elf_sleep_payload(seconds):
    code = bytearray()
    fixups = []

    def emit(data):
        code.extend(data)

    def lea_rdi(label):
        pos = len(code)
        emit(b"\x48\x8d\x3d\0\0\0\0")
        fixups.append((pos + 3, label, pos + 7))

    emit(b"\x48\xc7\xc0\x23\0\0\0")  # mov rax, SYS_nanosleep
    lea_rdi("timespec")
    emit(b"\x31\xf6")  # xor esi, esi
    emit(b"\x0f\x05")  # syscall
    emit(b"\x6a\x3c\x58")  # push 60; pop rax
    emit(b"\x6a\x7f\x5f")  # push 127; pop rdi
    emit(b"\x0f\x05")  # syscall

    labels = {"timespec": len(code)}
    emit(struct.pack("<QQ", seconds, 0))

    for at, label, next_ip in fixups:
        code[at : at + 4] = struct.pack("<i", labels[label] - next_ip)

    off = 0x78
    size = off + len(code)

    eh = bytearray(0x40)
    eh[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        eh,
        16,
        3,  # ET_DYN, so it can act as an ELF interpreter without a fixed base.
        0x3E,
        1,
        off,
        0x40,
        0,
        0,
        0x40,
        0x38,
        1,
        0,
        0,
        0,
    )

    ph = bytearray(0x38)
    struct.pack_into("<IIQQQQQQ", ph, 0, 1, 5, 0, 0, 0, size, size, 0x1000)
    return bytes(eh + ph + code)


def state_path(work):
    return os.path.join(work, STATE)


def loader_paths():
    override = os.environ.get("DCF_FAKE_LOADER_PATH")
    if override:
        return [override]
    return list(DEFAULT_LOADERS)


def backup_path(work, loader):
    safe = loader.strip("/").replace("/", "_")
    return os.path.join(work, safe + ".backup")


def install(work):
    seconds = int(os.environ.get("DCF_FAKE_LOADER_SLEEP", "1"))
    states = []
    payload = elf_sleep_payload(seconds)

    for loader in loader_paths():
        state = {
            "path": loader,
            "existed": os.path.lexists(loader),
            "backup": backup_path(work, loader),
            "was_symlink": os.path.islink(loader),
            "symlink_target": None,
        }

        os.makedirs(os.path.dirname(loader), exist_ok=True)
        if state["existed"]:
            try:
                os.unlink(state["backup"])
            except FileNotFoundError:
                pass

            if state["was_symlink"]:
                state["symlink_target"] = os.readlink(loader)
            else:
                shutil.copy2(loader, state["backup"])

        tmp = loader + ".fake"
        with open(tmp, "wb") as f:
            f.write(payload)
        os.chmod(tmp, 0o755)
        os.replace(tmp, loader)
        states.append(state)
        print(f"[+] fake loader installed at {loader} sleep={seconds}s", flush=True)

    with open(state_path(work), "w") as f:
        json.dump(states, f)


def restore(work):
    try:
        with open(state_path(work)) as f:
            states = json.load(f)
    except FileNotFoundError:
        return

    if isinstance(states, dict):
        states = [states]

    for state in reversed(states):
        path = state["path"]
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass

        if state["existed"]:
            if state["was_symlink"]:
                os.symlink(state["symlink_target"], path)
            else:
                shutil.copy2(state["backup"], path)

        print(f"[+] fake loader restored at {path}", flush=True)


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("install", "restore"):
        raise SystemExit(f"usage: {sys.argv[0]} install|restore WORKDIR")

    if sys.argv[1] == "install":
        install(sys.argv[2])
    else:
        restore(sys.argv[2])


if __name__ == "__main__":
    main()
