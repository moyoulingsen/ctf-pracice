#!/usr/bin/env python3
# cosmic-ray 解题模板
# 用法: python3 solve.py [remote|local] [host] [port]
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

# 每轮: (patch 文件偏移, 单字节, 自定义类型)
ROUNDS = [
    # (0x????, 0x??, 'k1')
]


def build_payload(kind, libc_base):
    # TODO: 按类型返回本轮的 exp 字节串
    raise NotImplementedError


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
        print(out.decode(errors='replace')[-300:])


main()
