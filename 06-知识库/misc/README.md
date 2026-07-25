# Misc 知识库

## 学习目标

Misc 是 CTF 中最杂的方向，常见内容包括文件分析、隐写、流量分析、压缩包、编码、取证、音频视频、二维码和 OSINT。入门阶段最重要的是建立“拿到文件先系统检查”的习惯。

## Level 0：拿到文件后的基础流程

### 基础四连

```bash
file target
strings target | less
xxd target | less
exiftool target
```

解释：

- `file`：判断文件真实类型。
- `strings`：找可见字符串。
- `xxd`：看十六进制内容和文件头。
- `exiftool`：看元数据。

### 文件头魔数

常见文件头：

| 类型 | 文件头 |
|---|---|
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| JPG | `FF D8 FF` |
| GIF | `47 49 46 38` |
| ZIP | `50 4B 03 04` |
| RAR | `52 61 72 21` |
| PDF | `25 50 44 46` |
| ELF | `7F 45 4C 46` |
| Windows EXE | `4D 5A` |

如果后缀和文件头不一致，以文件头为准。

## Level 1：编码与文本处理

### 常见编码

- Base64
- Base32
- Base16 / Hex
- URL 编码
- HTML 实体
- Morse
- Bacon 培根密码
- Unicode 转义
- ASCII 数字

### 判断方法

```text
末尾有 = ：可能是 Base64
只含 A-Z2-7：可能是 Base32
只含 0-9a-f：可能是 Hex
有 %xx：可能是 URL 编码
只有 . 和 -：可能是 Morse
只有 a/b：可能是 Bacon
```

### Python 解码模板

```python
import base64
from urllib.parse import unquote

s = 'ZmxhZ3t0ZXN0fQ=='
print(base64.b64decode(s))

s = '%66%6c%61%67'
print(unquote(s))
```

## Level 2：图片隐写

### 基础检查

```bash
file image.png
exiftool image.png
strings image.png | less
binwalk image.png
xxd image.png | less
```

### 常见隐藏方式

- 元数据隐藏 flag。
- 文件尾追加压缩包。
- 修改图片宽高。
- LSB 隐写。
- alpha 通道隐藏。
- 调色板隐藏。
- 图片异或/拼接。

### PNG 宽高修复

PNG 宽高在 IHDR 块中，可能被篡改导致图片显示不完整。可以用 ImHex/HxD 修改，或用脚本爆破 CRC。

### binwalk 提取

```bash
binwalk image.png
binwalk -e image.png
```

### steghide

```bash
steghide info image.jpg
steghide extract -sf image.jpg
```

如果需要密码，尝试题目提示、文件名、弱口令。

### zsteg

PNG/BMP LSB 常用：

```bash
zsteg image.png
```

如果没装，后续遇到相关题再安装。

## Level 3：压缩包与密码

### 常见类型

- zip
- rar
- 7z
- tar.gz

### 基础命令

```bash
7z l file.zip
7z x file.zip
unzip file.zip
```

### 伪加密

ZIP 伪加密常见表现：

- 压缩包显示加密。
- 实际不需要密码或可通过修改标志位解开。

处理方式：

- 用 ZipCenOp.jar。
- 用十六进制编辑器修改加密标志位。

### 爆破密码

先提取 hash：

```bash
zip2john file.zip > hash.txt
rar2john file.rar > hash.txt
john hash.txt
```

如果系统没有 `zip2john/rar2john`，后续按需安装 john jumbo。

### 明文攻击

如果压缩包里有一个已知文件，可以用明文攻击恢复密码或内容。

## Level 4：流量分析

### 工具

- Wireshark
- tshark

### 常见过滤器

```text
http
tcp
udp
dns
icmp
ftp
ftp-data
smtp
ip.addr == 1.2.3.4
tcp.stream eq 0
```

### 常用操作

- Follow TCP Stream
- Export Objects -> HTTP
- 查看 DNS 查询
- 查看 FTP 传输
- 查看 ICMP 数据
- 查找 flag 字符串

### 命令行提取

```bash
strings capture.pcapng | grep -i flag
```

### 常见题型

- HTTP 传输了 flag 文件。
- FTP 账号密码在明文流量中。
- DNS 查询携带数据。
- ICMP payload 隐藏数据。
- USB 键盘流量恢复输入。
- TLS 流量给了 key log 文件。

## Level 5：音频隐写

### 常见方向

- 频谱图藏文字。
- 声道差异。
- 摩斯电码。
- 音频倒放。
- LSB 隐写。

### 工具

- Audacity
- Sonic Visualiser
- Python wave 库

### 检查点

1. 播放听是否有摩斯节奏。
2. 看频谱图是否有文字。
3. 分离左右声道。
4. 倒放。
5. 检查文件尾是否追加数据。

## Level 6：视频隐写

### 常见方向

- 某一帧藏 flag。
- 二维码一闪而过。
- 音频轨藏信息。
- 字幕轨藏信息。
- 帧差异。

### ffmpeg 常用命令

```bash
ffmpeg -i video.mp4 frames/%05d.png
ffmpeg -i video.mp4 audio.wav
ffmpeg -i video.mp4
```

检查：

1. 抽帧。
2. 看音频。
3. 看元数据。
4. 看字幕。

## Level 7：二维码与条形码

### 常见题型

- 二维码破损修复。
- 多张二维码拼接。
- 颜色通道分离。
- 二维码反色。
- 条形码识别。

### 工具

- 在线二维码识别工具
- zbarimg
- Python OpenCV

命令：

```bash
zbarimg qrcode.png
```

如果没装：

```bash
sudo apt install zbar-tools
```

## Level 8：内存取证

### 常见文件

- `.raw`
- `.mem`
- `.vmem`

### 工具

- Volatility 2
- Volatility 3

### 常见任务

- 查看系统信息。
- 查看进程。
- 查看命令历史。
- dump 文件。
- 查找浏览器历史。
- 提取剪贴板/密码/flag。

### Volatility 3 示例

```bash
vol -f memory.raw windows.info
vol -f memory.raw windows.pslist
vol -f memory.raw windows.cmdline
vol -f memory.raw windows.filescan
```

入门阶段遇到内存取证再专门配置 Volatility。

## Level 9：磁盘和文件系统取证

### 常见文件

- `.img`
- `.dd`
- `.vhd`
- `.vmdk`
- `.E01`

### 常见任务

- 挂载镜像。
- 恢复删除文件。
- 查看浏览器记录。
- 查看系统日志。
- 查找隐藏分区。

### 工具

- Autopsy
- FTK Imager
- foremost
- binwalk
- strings

## Level 10：OSINT

OSINT 是开源情报题，常见考察：

- 图片定位。
- 社交账号搜索。
- 域名 WHOIS。
- GitHub 泄露。
- 地图和街景。
- EXIF 地理位置。
- 时间线分析。

注意：只做题目授权范围内的信息检索，不要骚扰真实个人或组织。

## Misc 标准流程

### 文件类

```text
file -> strings -> exiftool -> binwalk -> xxd -> 根据文件类型专项分析
```

### 图片类

```text
exiftool -> strings -> binwalk -> ImHex/HxD -> LSB -> 宽高/CRC -> 通道分析
```

### 流量包

```text
Wireshark 打开 -> Statistics -> Protocol Hierarchy -> Follow Stream -> Export Objects -> strings grep
```

### 压缩包

```text
7z l -> 尝试解压 -> 判断伪加密 -> 爆破密码 -> 明文攻击
```

## 做题检查清单

- `file` 判断真实类型了吗？
- 后缀和文件头一致吗？
- `strings` 有没有 flag 或提示？
- `exiftool` 有没有可疑元数据？
- `binwalk` 有没有隐藏文件？
- 文件尾有没有追加数据？
- 是否是压缩包伪加密？
- 是否需要爆破密码？
- 图片宽高是否异常？
- 是否有 LSB 隐写？
- 流量包是否 Follow Stream？
- 是否能导出 HTTP 对象？
- 是否有 DNS/ICMP/FTP 明文信息？

## 推荐练习

1. picoCTF Forensics：入门友好。
2. BUUCTF Misc：经典题多。
3. NSSCTF Misc：题型较新。
4. Bugku Misc：中文入门题多。
5. Root-Me Forensics：偏实战。

## 硬核进阶路线

### 阶段 1：文件格式和二进制分析

目标：不依赖工具输出，能自己判断文件结构和异常点。

必学内容：

- 常见文件魔数。
- PNG：signature、chunk、IHDR、IDAT、IEND、CRC。
- JPEG：SOI、APP、DQT、DHT、SOS、EOI。
- GIF：header、logical screen、image descriptor、LZW。
- ZIP：local file header、central directory、EOCD。
- PDF：object、xref、stream、trailer。
- ELF/PE 基础结构。
- 文件尾追加和文件嵌套。

推荐资料：

- Wikipedia 各文件格式页面。
- PNG Specification。
- JPEG File Interchange Format。
- PKWARE ZIP AppNote。
- PDF Reference。
- Gary Kessler File Signatures。

阶段验收：

- 能手动判断 PNG 宽高是否被改。
- 能手动找到 ZIP central directory。
- 能用 ImHex/HxD 定位文件尾追加内容。
- 能解释 binwalk 为什么能识别嵌入文件。

### 阶段 2：隐写专项

目标：面对图片、音频、视频隐写能系统排查。

图片隐写：

- LSB。
- RGB/Alpha 通道。
- 调色板隐写。
- 图片宽高修改。
- PNG CRC 爆破。
- 盲水印。
- F5/JSteg/OutGuess。
- 图片异或和像素差分。

音频隐写：

- 频谱图。
- 摩斯音频。
- 声道差异。
- 音频倒放。
- LSB。
- DTMF 电话按键音。

视频隐写：

- 抽帧。
- 帧差。
- 字幕轨。
- 音频轨。
- 二维码闪帧。

工具：

- stegsolve。
- zsteg。
- steghide。
- binwalk。
- exiftool。
- Audacity。
- Sonic Visualiser。
- ffmpeg。
- OpenCV。

推荐训练：

- BUUCTF Misc 图片隐写题。
- picoCTF Forensics。
- Root-Me Steganography。

阶段验收：

- 能自己写 LSB 提取脚本。
- 能用 ffmpeg 批量抽帧。
- 能用 Python/Pillow 做通道分离。
- 能从音频频谱读出隐藏文本。

### 阶段 3：网络流量分析

目标：从 pcap 中恢复通信、文件、凭据和隐藏数据。

必学协议：

- Ethernet / ARP。
- IP / ICMP。
- TCP / UDP。
- DNS。
- HTTP。
- FTP。
- SMTP / POP3 / IMAP。
- TLS 基础。
- SMB。
- USB HID。
- 802.11 Wi-Fi。

Wireshark 技能：

- display filter。
- Follow TCP/UDP Stream。
- Export Objects。
- Protocol Hierarchy。
- Conversations。
- IO Graphs。
- 解密 TLS：key log file。
- USB 键盘流量恢复。

命令行工具：

- tshark。
- tcpdump。
- foremost。
- NetworkMiner。
- scapy。

推荐书籍/资料：

- 《Wireshark 网络分析就这么简单》：中文入门。
- Wireshark User's Guide。
- Practical Packet Analysis。
- TCP/IP Illustrated Volume 1。

阶段验收：

- 能从 HTTP 流量导出文件。
- 能从 FTP 流量恢复账号密码和传输文件。
- 能从 DNS 查询中拼接出隐藏数据。
- 能从 USB HID pcap 恢复键盘输入。

### 阶段 4：内存取证

目标：分析内存镜像，恢复进程、命令、文件和敏感信息。

必学内容：

- 进程和线程。
- 虚拟内存。
- Windows 注册表。
- Windows 进程结构基础。
- Linux 进程内存基础。
- 浏览器内存和历史记录。
- 凭据和剪贴板痕迹。

工具：

- Volatility 3。
- Volatility 2。
- Rekall。
- strings。
- bulk_extractor。
- MemProcFS。

Volatility 方向：

- `windows.info`
- `windows.pslist`
- `windows.pstree`
- `windows.cmdline`
- `windows.filescan`
- `windows.dumpfiles`
- `windows.netscan`
- `windows.registry.*`
- `linux.pslist`

推荐书籍：

- The Art of Memory Forensics：内存取证圣经。
- Malware Analyst's Cookbook：很多取证和恶意代码分析技巧。
- Windows Internals：Windows 底层结构。

阶段验收：

- 能识别内存镜像系统版本。
- 能列出可疑进程和命令行。
- 能 dump 出可疑文件。
- 能从内存中搜索 flag 或浏览器痕迹。

### 阶段 5：磁盘和文件系统取证

目标：从磁盘镜像恢复删除文件、时间线和用户行为。

必学文件系统：

- FAT32。
- NTFS。
- ext4。
- APFS 基础。

必学概念：

- 分区表 MBR/GPT。
- inode。
- MFT。
- journal。
- slack space。
- unallocated space。
- 文件删除和恢复。
- 时间戳：MACB。

工具：

- Autopsy。
- Sleuth Kit。
- FTK Imager。
- X-Ways Forensics。
- foremost。
- testdisk / photorec。

推荐资料：

- File System Forensic Analysis。
- The Sleuth Kit 文档。
- Autopsy 官方文档。

阶段验收：

- 能挂载磁盘镜像。
- 能恢复删除文件。
- 能用时间线分析用户行为。
- 能从浏览器缓存和历史中找线索。

### 阶段 6：密码恢复和取证综合

目标：处理 hash、压缩包、办公文档和真实取证链。

内容：

- ZIP/RAR/7z hash 提取。
- Office 文档密码恢复。
- PDF 密码。
- Windows SAM/NTDS 基础。
- 浏览器密码数据库。
- SSH key 和 known_hosts。
- weak password wordlist。
- hashcat mode。
- john jumbo。

工具：

- john。
- hashcat。
- zip2john / rar2john / office2john。
- hashid。
- hash-identifier。
- rockyou 字典。
- crunch / cewl。

阶段验收：

- 能识别常见 hash 类型。
- 能提取 zip/rar/office hash。
- 能用规则和字典爆破弱密码。
- 能解释 hash 和加密的区别。

### 阶段 7：OSINT 和真实调查能力

目标：根据公开信息定位地点、人物、时间、事件。

必学内容：

- 搜索引擎高级语法。
- 图片反搜。
- EXIF 地理位置。
- 地图/街景定位。
- WHOIS / DNS 历史。
- GitHub 泄露搜索。
- 社交平台交叉验证。
- 时间线建立。

推荐资源：

- Bellingcat OSINT Guides。
- OSINT Framework。
- Google Dorking。
- GitHub Search 语法。

阶段验收：

- 能根据图片定位大致地点。
- 能根据域名查注册和 DNS 信息。
- 能从 GitHub 历史 commit 中找泄露信息。

### 阶段 8：综合 Forensics 比赛打法

拿到附件先分类：

1. 单文件：先 `file/strings/exiftool/binwalk/xxd`。
2. 图片：看元数据、通道、LSB、宽高、CRC、附加文件。
3. 压缩包：看伪加密、密码爆破、明文攻击、嵌套。
4. 流量包：先 Protocol Hierarchy，再 Follow Stream，再 Export Objects。
5. 内存镜像：先识别 profile/info，再进程、网络、文件、命令。
6. 磁盘镜像：先分区、文件系统、删除文件、时间线。
7. 音视频：抽帧、抽音频、看频谱、查元数据。

长期训练任务：

- 每周至少做 5 道 Misc/Forensics。
- 建立自己的文件头和工具命令速查表。
- 每月完整复现 1 道内存取证或磁盘取证题。
- 学会用 Python 处理图片、pcap、二进制文件。
