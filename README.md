# CTF Practice

这是一个用于长期学习、训练和复盘 CTF 的个人项目目录。

## 目录结构

```text
ctf-pracice/
├── 00-环境与工具/          # 工具安装、环境配置、常用命令
├── 01-比赛记录/            # 每场比赛的时间线、队伍信息、结果复盘
├── 02-题目训练/            # 按方向保存题目附件、脚本、过程记录
│   ├── web/                # Web 安全题
│   ├── crypto/             # 密码学题
│   ├── reverse/            # 逆向题
│   ├── pwn/                # 二进制漏洞利用题
│   └── misc/               # 杂项、隐写、取证、流量分析
├── 03-脚本库/              # 可复用脚本和模板
│   ├── python/             # Python 解题脚本
│   └── shell/              # Shell 辅助脚本
├── 04-字典与资源/          # 小型字典、参考资料索引
├── 05-writeups/            # 完整题解和赛后复盘
├── 06-知识库/              # 按方向沉淀知识点
│   ├── web/
│   ├── crypto/
│   ├── reverse/
│   ├── pwn/
│   └── misc/
├── 07-靶场与平台/          # 平台账号、靶场记录、练习路线
├── 08-工具输出/            # 工具临时输出，定期清理
├── 99-归档/                # 过期资料、旧题目、历史文件
└── 密码学/                 # 已有密码学学习笔记
```

## 当前工具清单

见：[00-环境与工具/工具清单.md](00-环境与工具/工具清单.md)

## 单题目录模板

每道题建议按下面格式保存：

```text
题目名/
├── README.md       # 题目描述、思路、flag、复盘
├── attachments/    # 原始附件，不要直接改
├── work/           # 分析过程中的中间文件
├── solve.py        # 解题脚本
└── exp.py          # Pwn 利用脚本，如有
```

## 入门训练顺序

1. Misc：熟悉文件分析、隐写、流量包、压缩包。
2. Crypto：熟悉 Python、编码、RSA、AES、数论。
3. Web：熟悉 HTTP、Cookie、SQL 注入、文件上传、命令执行。
4. Reverse：熟悉 Ghidra、字符串、伪代码、简单动态调试。
5. Pwn：熟悉 C、栈、GDB、pwntools、ROP。

## 基础命令

```bash
# 进入 WSL 工作目录
cd ~
mkdir -p ctf
cd ~/ctf

# 常见分析
file target
strings target | less
xxd target | less
binwalk target
exiftool target

# Pwn 常见
checksec ./pwn
gdb ./pwn
ROPgadget --binary ./pwn
python3 exp.py
```
