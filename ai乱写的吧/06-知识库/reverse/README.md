# Reverse 知识库

## 学习目标

Reverse 方向考察从二进制程序中还原逻辑的能力。入门阶段重点不是手写汇编，而是学会使用 `file`、`strings`、Ghidra、gdb 找到程序的校验逻辑，然后还原出 flag。

## Level 0：程序基础

### 必会概念

- 源码：人写的 C/C++/Python/Go/Rust 等代码。
- 编译：把源码变成可执行文件。
- 汇编：机器指令的文本形式。
- 反汇编：从机器码还原汇编。
- 反编译：从机器码近似还原 C 伪代码。
- 静态分析：不运行程序，直接看文件内容和代码。
- 动态分析：运行程序，用调试器观察行为。

### 常见文件

- Windows：`.exe`、`.dll`
- Linux：ELF 文件，通常没有后缀
- Android：`.apk`
- Java：`.class`、`.jar`
- Python：`.pyc`

## Level 1：拿到程序后的第一步

### 基础三连

```bash
file chall
strings chall | less
checksec chall
```

解释：

- `file`：判断文件类型、架构、是否 stripped。
- `strings`：找明文字符串、提示、flag 片段。
- `checksec`：查看安全保护，Pwn 更常用，Reverse 也能辅助判断。

### 运行看看

```bash
chmod +x ./chall
./chall
```

如果提示输入密码：

```text
please input flag:
wrong
```

说明目标是找到正确输入。

## Level 2：Ghidra 入门流程

### 基本步骤

1. 打开 Ghidra。
2. 新建 Non-Shared Project。
3. Import 导入程序。
4. 双击打开 CodeBrowser。
5. 选择 Analyze。
6. 找 `main` 函数。
7. 看右侧 Decompiler 伪代码。

### 常看窗口

- Listing：汇编视图。
- Decompiler：伪代码视图。
- Symbol Tree：函数、导入表、字符串。
- Defined Strings：字符串列表。

### 找 main 方法

常见方式：

- Symbol Tree 搜 `main`
- Search -> For Strings
- 从字符串交叉引用跳转
- 找 `puts`、`printf`、`scanf` 的调用位置

## Level 3：识别常见校验逻辑

### 直接字符串比较

C 代码类似：

```c
if (strcmp(input, "flag{xxx}") == 0) {
    puts("right");
}
```

特征：

- 伪代码里有 `strcmp`、`strncmp`、`memcmp`。
- 字符串列表里可能直接有 flag。

### 字符逐位比较

```c
if (input[0] == 'f' && input[1] == 'l')
```

解法：

- 直接从伪代码抄出字符。
- 或写脚本拼接。

### 简单变换比较

```c
for (i = 0; i < len; i++) {
    if ((input[i] ^ 0x12) != enc[i]) wrong();
}
```

解法：反向计算。

```python
enc = [0x74, 0x7e, 0x73]
pt = bytes([x ^ 0x12 for x in enc])
print(pt)
```

常见变换：

- 加减：`+ 3`、`- 5`
- 异或：`^ 0x12`
- 位移：`<<`、`>>`
- 交换位置
- Base64
- RC4 / AES / TEA / XXTEA

## Level 4：汇编基础

### x86/x64 常见寄存器

| 寄存器 | 用途 |
|---|---|
| `rax` | 返回值、通用寄存器 |
| `rbx` | 通用寄存器 |
| `rcx` | 参数/计数 |
| `rdx` | 参数/数据 |
| `rsi` | 源地址/参数 |
| `rdi` | 目标地址/第一个参数 |
| `rbp` | 栈基址 |
| `rsp` | 栈顶指针 |
| `rip` | 当前指令地址 |

### Linux x64 函数参数

前六个参数通常放在：

```text
rdi, rsi, rdx, rcx, r8, r9
```

返回值在：

```text
rax
```

### 常见指令

| 指令 | 含义 |
|---|---|
| `mov` | 赋值/移动数据 |
| `lea` | 取地址/地址计算 |
| `add` | 加法 |
| `sub` | 减法 |
| `xor` | 异或 |
| `cmp` | 比较 |
| `test` | 按位测试 |
| `jmp` | 无条件跳转 |
| `je/jz` | 相等/为零跳转 |
| `jne/jnz` | 不相等/不为零跳转 |
| `call` | 调用函数 |
| `ret` | 函数返回 |

## Level 5：gdb 动态调试

### 基础命令

```bash
gdb ./chall
```

gdb 内：

```gdb
start
break main
run
next
step
continue
info registers
x/20gx $rsp
x/s 地址
disassemble main
quit
```

### 常见断点

```gdb
break main
break strcmp
break memcmp
break scanf
break puts
```

### 看函数参数

Linux x64 下，断在 `strcmp` 时：

```gdb
x/s $rdi
x/s $rsi
```

这经常能直接看到程序拿你的输入和什么字符串比较。

## Level 6：patch 思路

Patch 是修改程序逻辑。

常见操作：

- 把 `jne` 改成 `je`
- 把条件跳转改成无条件跳转
- 把校验函数返回值改成成功

入门用途：

- 验证自己找的判断逻辑是否正确。
- 绕过复杂校验继续看后续逻辑。

注意：比赛题最终通常要求 flag，不是只要求程序显示 right。

## Level 7：常见算法识别

### Base64

特征：

- 字符串表有 Base64 字符表：

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
```

### TEA / XXTEA

特征：

- 常量 `0x9e3779b9`
- 大量移位和异或

### RC4

特征：

- 256 字节 S 盒
- 初始化循环 `for i in range(256)`
- 交换数组元素

### AES

特征：

- S-box 常量表
- 16 字节 block
- 128/192/256 bit key

### MD5 / SHA

特征：

- 固定 IV 常量
- 大量位运算
- 输出 hash 再比较

## Level 8：壳与混淆

### 查壳

```bash
file chall
strings chall | head
upx -t chall
```

常见壳：

- UPX
- VMProtect
- Themida

### UPX 脱壳

```bash
upx -d chall -o chall_unpacked
```

### 混淆常见表现

- 函数名全没了。
- 控制流很乱。
- 大量无意义跳转。
- 字符串加密。
- 反调试。

入门阶段遇到重混淆可以先跳过。

## Level 9：不同语言逆向

### Python pyc

工具：

```bash
uncompyle6
pycdc
```

思路：

1. 判断 Python 版本。
2. 反编译 pyc。
3. 读 Python 源码逻辑。

### Java jar/class

工具：

- jadx
- jd-gui
- CFR

思路：

1. 解压 jar。
2. 反编译 class。
3. 找 main 或关键校验函数。

### Android apk

工具：

- jadx-gui
- apktool

思路：

1. jadx 看 Java/Kotlin 逻辑。
2. apktool 看资源和 manifest。
3. 搜索 flag、secret、check、verify。

### Go / Rust

特点：

- 二进制大。
- 函数名可能很多。
- 反编译结果不如 C 清晰。

入门建议：先用字符串和交叉引用定位关键函数。

## Level 10：解题套路

### 标准流程

```text
file -> strings -> 运行 -> Ghidra 找 main -> 找比较逻辑 -> 还原算法 -> Python 解密
```

### 如果找不到 main

1. 看 Defined Strings。
2. 找输出字符串，如 `right`、`wrong`、`flag`。
3. 对字符串看 XREF。
4. 从引用位置向上找函数。

### 如果伪代码很乱

1. 先动态调试。
2. 断在 `strcmp/memcmp`。
3. 看比较双方。
4. 找输入变换前后的内存。

### 如果输入被加密后比较

1. 找密文数组。
2. 找变换循环。
3. 判断是否可逆。
4. 写 Python 逆向计算。

## 做题检查清单

- `file` 看过了吗？
- `strings` 里有没有 flag、right、wrong、key？
- 程序能运行吗？需要参数吗？
- Ghidra 分析完成了吗？
- 找到 main 或关键函数了吗？
- 找到输入函数了吗？
- 找到比较函数了吗？
- 是否有加密数组？
- 是否有常量，比如 `0x9e3779b9`？
- 是否需要动态调试？
- 是否可能加壳？

## 推荐练习

1. picoCTF Reverse：入门友好。
2. BUUCTF Reverse：经典题多。
3. NSSCTF Reverse：比赛风格较新。
4. 攻防世界 Reverse：适合巩固基础。
5. Root-Me Cracking：练基础逆向和调试。

## 硬核进阶路线

### 阶段 1：汇编和体系结构

目标：能脱离伪代码，看懂关键汇编逻辑。

必学内容：

- x86/x64 指令集。
- ARM/AArch64 基础。
- 寄存器、栈帧、调用约定。
- 条件跳转和标志位。
- 函数序言/尾声。
- 编译器优化对代码形态的影响。
- ELF、PE 文件格式基础。

推荐书籍：

- 《汇编语言》王爽：中文汇编入门。
- 《深入理解计算机系统》：程序表示、链接、异常控制流。
- 《Computer Systems: A Programmer's Perspective》英文版。
- 《x86 Assembly Language and C Fundamentals》。
- Intel Software Developer's Manual：权威但很厚，用来查。

阶段验收：

- 能手动分析一个简单 C 函数对应的汇编。
- 能解释 x64 Linux 函数参数如何传递。
- 能看懂循环、if、switch 在汇编里的形态。

### 阶段 2：文件格式和加载过程

目标：理解可执行文件如何被系统加载和运行。

ELF 必学：

- ELF Header。
- Program Header / Section Header。
- `.text`、`.data`、`.rodata`、`.bss`。
- PLT/GOT。
- 动态链接。
- relocation。
- symbol table。

PE 必学：

- DOS Header。
- NT Header。
- Section Table。
- Import Table。
- Export Table。
- Resource。
- TLS Callback。
- IAT Hook。

工具：

- readelf。
- objdump。
- rabin2。
- PE-bear。
- CFF Explorer。
- Detect It Easy。

推荐资料：

- 《程序员的自我修养：链接、装载与库》：ELF/链接装载非常推荐。
- Practical Malware Analysis：PE 和 Windows 逆向经典。
- corkami PE/ELF 图解资料。

阶段验收：

- 能用 `readelf -a` 找入口点、段、动态符号。
- 能解释 PLT/GOT 如何解析外部函数。
- 能用 PE 工具找到导入函数和资源。

### 阶段 3：静态分析能力

目标：熟练使用 Ghidra/IDA，快速定位关键逻辑。

必学技能：

- 函数重命名和变量重命名。
- 交叉引用 XREF。
- 字符串引用追踪。
- 结构体恢复。
- 数组和全局变量识别。
- 函数签名修复。
- 枚举和常量识别。
- 脚本自动化分析。

Ghidra 重点：

- Data Type Manager。
- Function Graph。
- Decompiler 参数和类型修复。
- Ghidra Script。
- Patch Instruction。

IDA 重点：

- Graph View。
- Hex-Rays Decompiler。
- IDAPython。
- FLIRT signatures。

推荐书籍/资料：

- 《The IDA Pro Book》：IDA 经典。
- Ghidra 官方教程。
- Practical Reverse Engineering。
- Reverse Engineering for Beginners。

阶段验收：

- 能把一个 stripped 程序的关键函数命名清楚。
- 能通过字符串引用定位校验逻辑。
- 能把伪代码整理成可运行 Python 解密脚本。

### 阶段 4：动态调试

目标：能在运行时观察和控制程序。

Linux：

- gdb / pwndbg。
- 断点、条件断点、硬件断点。
- watchpoint。
- 查看栈、堆、寄存器。
- 跟踪函数调用。
- patch 内存。

Windows：

- x64dbg。
- WinDbg。
- Process Monitor。
- Process Explorer。
- API Monitor。

Android：

- jadx。
- apktool。
- frida。
- objection。
- adb。

阶段验收：

- 能断在 `strcmp/memcmp` 并读取比较双方。
- 能 patch 条件跳转验证逻辑。
- 能用 Frida hook Java 方法或 native 函数。

### 阶段 5：算法逆向

目标：识别并还原常见算法。

必学算法：

- Base64 变种。
- XOR/加减/位移混合。
- RC4。
- TEA / XTEA / XXTEA。
- AES 常量识别。
- MD5/SHA 常量识别。
- CRC32。
- 自定义 VM。
- 迷宫/路径搜索。
- 约束求解。

工具：

- Python。
- z3-solver。
- angr。
- manticore。
- Triton。

z3 适合：

- 多个字符约束。
- 方程约束。
- 位运算约束。
- 校验逻辑复杂但路径固定。

angr 适合：

- 找到 `success` 地址和 `failure` 地址。
- 自动符号执行输入。

阶段验收：

- 能识别 TEA 常量 `0x9e3779b9`。
- 能用 z3 解一个 30-50 字符约束题。
- 能用 angr 自动跑一个简单 crackme。

### 阶段 6：反调试、壳和混淆

目标：面对加壳和混淆不崩溃。

必学内容：

- UPX 脱壳。
- OEP 查找。
- IAT 修复概念。
- Windows 反调试 API。
- Linux ptrace 反调试。
- 时间检测。
- 异常控制流。
- 控制流平坦化。
- 字符串加密。
- 虚拟机保护 VM。

工具：

- x64dbg。
- Scylla。
- Detect It Easy。
- Frida。
- Qiling。
- unicorn。

推荐资料：

- Practical Malware Analysis。
- Malware Unicorn Workshops。
- OpenSecurityTraining2。
- RPISEC Malware Analysis。

阶段验收：

- 能脱 UPX。
- 能绕过基础 IsDebuggerPresent。
- 能手动找到解密后的字符串。
- 能分析一个简单 VM 指令分发循环。

### 阶段 7：Android 和移动逆向

目标：能做移动端 CTF 逆向和简单 App 分析。

必学内容：

- APK 结构。
- AndroidManifest.xml。
- Java/Kotlin 反编译。
- JNI 和 native so。
- smali 基础。
- Frida hook。
- 签名和重打包。

工具：

- jadx-gui。
- apktool。
- adb。
- frida-tools。
- objection。
- Android Studio emulator。

阶段验收：

- 能用 jadx 找到 Java 校验逻辑。
- 能修改 smali 后重打包。
- 能用 Frida hook 返回值绕过校验。
- 能分析 native so 里的 flag 校验。

### 阶段 8：恶意代码分析方向

这不是 CTF 必须，但能极大提升逆向能力。

学习内容：

- Windows API。
- 进程注入。
- 持久化。
- 网络通信。
- 加密配置提取。
- 沙箱规避。
- YARA 规则。

推荐书籍：

- Practical Malware Analysis。
- The Art of Memory Forensics。
- Malware Analyst's Cookbook。
- Windows Internals。

长期训练任务：

- 每周做 3-5 道 crackme。
- 每周精读 1 个高质量 reverse writeup。
- 每月分析 1 个真实小样本或开源 crackme。
- 建立自己的算法识别笔记：TEA、RC4、AES、Base64、CRC、VM。
