#!/usr/bin/env python3

import atexit
import base64
import lzma
import os
import subprocess
import sys

if not hasattr(os, "memfd_create"):
    import ctypes

    def _memfd_create(name, flags):
        nr = {"x86_64": 319, "aarch64": 385}.get(os.uname().machine, 279)
        syscall = ctypes.CDLL(None).syscall
        return syscall(nr, name.encode(), flags)

    os.memfd_create = _memfd_create


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <flag>", flush=True)
        os._exit(1)
    flag = sys.argv[1].encode()
    NATIVE = os.uname().machine == "loongarch64"
    o = os.memfd_create("o", 0)
    os.write(o, lzma.decompress(base64.a85decode(O)))
    exe = os.memfd_create("exe", 0)
    args = [
        "gcc" if NATIVE else "loongarch64-linux-gnu-gcc",
        "-o",
        "/proc/self/fd/{}".format(exe),
        "/proc/self/fd/{}".format(o),
    ]
    for i in range(0, len(flag), 8):
        args.append(
            "-Wl,--defsym=v{}={}".format(
                i // 8, int.from_bytes(flag[i : i + 8], "little")
            )
        )
    if not NATIVE:
        args.append("-static")
    try:
        subprocess.run(args, pass_fds=(o, exe), stdout=-3, stderr=-1, check=True)
    except FileNotFoundError:
        print("sh: command not found: " + args[0], flush=True)
        os._exit(127)
    except subprocess.CalledProcessError as e:
        if NATIVE and os.uname().version[0] != "4":
            print("THANK YOU MARIO, BUT OUR CHALLENGE BELONGS TO OLD WORLD", flush=True)
        elif b" 11 [" in e.stderr:
            print("your toolchain is too good, grab a worse one", flush=True)
        elif b"wn re" in e.stderr:
            print("your toolchain is hilariously buggy, grab a better one", flush=True)
        else:
            print("incorrect flag :p", flush=True)
        os._exit(1)
    os.close(o)
    try:
        os.execv("/proc/self/fd/{}".format(exe), [":heart:"])
    except OSError:
        print("your computer is too broken just throw it out of window bro", flush=True)
        os._exit(1)


atexit.register(main)
