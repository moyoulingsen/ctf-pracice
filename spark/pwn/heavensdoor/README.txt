heavensdoor — 附件说明
======================

文件列表
--------
heavensdoor        题目二进制(64 位,No PIE / Partial RELRO / NX / 无 Canary)

本地运行
--------
本题不依赖 libc 版本(预期解只需要二进制自身的地址),
在任何 Ubuntu 22.04+(glibc >= 2.34)环境里直接运行即可,无需 patchelf。

    ./heavensdoor

连接
----
    nc <ip> <port>

flag 在远程的 /flag。

提示
----
门前的空间只有 0x20 宽,但读入会写到 0x100 深。
门的地址,IDA 里找。
