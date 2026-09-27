# Crypto 知识库

## 学习目标

Crypto 方向主要考察编码、古典密码、现代密码、数学基础和代码分析能力。入门时不要只背算法，要学会把题目里的 `n、e、c、p、q、iv、key、nonce` 和对应算法联系起来。

## Level 0：Python 与数据表示

### 必会类型

- `str`：文本字符串。
- `bytes`：字节串，密码题最常用。
- `int`：大整数，RSA 常用。
- `hex`：十六进制表示。
- `base64`：编码表示。

### 常用转换

```python
from Crypto.Util.number import *
import base64

s = 'flag{test}'
b = s.encode()
print(b)
print(b.decode())

x = bytes_to_long(b)
print(x)
print(long_to_bytes(x))

h = b.hex()
print(h)
print(bytes.fromhex(h))

enc = base64.b64encode(b)
print(enc)
print(base64.b64decode(enc))
```

### 常见编码

- Base16 / Hex
- Base32
- Base64
- URL 编码
- Morse
- ASCII 码
- Unicode
- ROT13

做题思路：

1. 看字符集。
2. 看是否有 `=` 结尾，可能是 Base64。
3. 看是否只有 `0-9a-f`，可能是 Hex。
4. 看是否大量 `%xx`，可能是 URL 编码。
5. 多层编码要逐层解。

## Level 1：古典密码

### 凯撒密码

每个字母平移固定距离。

```python
import string

ct = 'iodj'
for shift in range(26):
    pt = ''
    for ch in ct:
        if ch in string.ascii_lowercase:
            pt += chr((ord(ch) - 97 - shift) % 26 + 97)
        else:
            pt += ch
    print(shift, pt)
```

### 维吉尼亚密码

使用重复密钥对字母平移。

重点：

- 找密钥长度。
- 频率分析。
- 已知明文攻击。

### 栅栏密码

把字符串按栏数重排。

```python
ct = '...'
for n in range(2, 20):
    rows = ['' for _ in range(n)]
    for i, ch in enumerate(ct):
        rows[i % n] += ch
    print(n, ''.join(rows))
```

### 替换密码

单表替换或多表替换。

分析方式：

- 频率分析。
- 已知 flag 格式。
- 猜测 `flag{`、`ctf{`。

## Level 2：异或 XOR

### 基础性质

```text
a ^ a = 0
a ^ 0 = a
a ^ b ^ b = a
```

### 单字节 XOR

```python
ct = bytes.fromhex('...')
for k in range(256):
    pt = bytes([c ^ k for c in ct])
    if b'flag' in pt or b'ctf' in pt:
        print(k, pt)
```

### 重复密钥 XOR

```python
ct = bytes.fromhex('...')
key = b'key'
pt = bytes([c ^ key[i % len(key)] for i, c in enumerate(ct)])
print(pt)
```

### 已知明文求 key

如果知道明文开头是 `flag{`：

```python
ct = bytes.fromhex('...')
known = b'flag{'
key_part = bytes([ct[i] ^ known[i] for i in range(len(known))])
print(key_part)
```

## Level 3：哈希与爆破

### 哈希特点

- 不可逆。
- 相同输入得到相同输出。
- 常见算法：MD5、SHA1、SHA256。

### Python 计算哈希

```python
import hashlib

s = b'123456'
print(hashlib.md5(s).hexdigest())
print(hashlib.sha1(s).hexdigest())
print(hashlib.sha256(s).hexdigest())
```

### 常见题型

- 弱口令 hash 爆破。
- 彩虹表查询。
- hash 长度扩展攻击。
- 哈希碰撞。

### john/hashcat

```bash
john hash.txt
hashcat -m 0 hash.txt wordlist.txt      # MD5
hashcat -m 100 hash.txt wordlist.txt    # SHA1
hashcat -m 1400 hash.txt wordlist.txt   # SHA256
```

## Level 4：数学基础

### 模运算

```python
print(pow(2, 10, 17))  # 2^10 mod 17
```

### 最大公约数

```python
import math
print(math.gcd(12, 18))
```

### 模逆元

```python
# Python 3.8+
print(pow(3, -1, 11))
```

### 常用定理

- 费马小定理
- 欧拉函数
- 中国剩余定理 CRT
- 扩展欧几里得

### gmpy2

```python
import gmpy2

print(gmpy2.gcd(12, 18))
print(gmpy2.invert(3, 11))
print(gmpy2.iroot(27, 3))
```

## Level 5：RSA 入门

### 基本公式

```text
n = p * q
phi = (p - 1) * (q - 1)
e * d ≡ 1 mod phi
c = m^e mod n
m = c^d mod n
```

### 标准解密模板

```python
from Crypto.Util.number import *

p = 0
q = 0
e = 65537
c = 0

n = p * q
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

### 常见 RSA 题型

#### 已知 p、q、e、c

直接求 `d` 解密。

#### n 可分解

用 factordb 或本地分解：

```python
import sympy
print(sympy.factorint(n))
```

#### e 很小

如果 `m^e < n`，直接开 e 次方：

```python
import gmpy2
m, ok = gmpy2.iroot(c, e)
if ok:
    print(long_to_bytes(m))
```

#### 共模攻击

同一个 `n`，不同 `e`，同一个明文。

```python
from Crypto.Util.number import *
import gmpy2

# c1 = m^e1 mod n, c2 = m^e2 mod n, gcd(e1,e2)=1
s1, s2, g = gmpy2.gcdext(e1, e2)
if s1 < 0:
    c1 = inverse(c1, n)
    s1 = -s1
if s2 < 0:
    c2 = inverse(c2, n)
    s2 = -s2
m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
print(long_to_bytes(m))
```

#### p、q 太接近

费马分解：

```python
import gmpy2

x = gmpy2.isqrt(n) + 1
while True:
    y2 = x*x - n
    y, ok = gmpy2.iroot(y2, 2)
    if ok:
        p = x + y
        q = x - y
        break
    x += 1
print(p, q)
```

#### 多个 n 有公共因子

```python
import math

ns = [n1, n2, n3]
for i in range(len(ns)):
    for j in range(i + 1, len(ns)):
        g = math.gcd(ns[i], ns[j])
        if g != 1:
            print(i, j, g)
```

## Level 6：对称加密

### AES 基础

常见模式：

- ECB：相同明文块产生相同密文块。
- CBC：需要 IV。
- CTR：需要 nonce/counter。
- GCM：带认证标签 tag。

### AES CBC 解密模板

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = bytes.fromhex('')
iv = bytes.fromhex('')
ct = bytes.fromhex('')

cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(ct), 16)
print(pt)
```

### AES ECB 解密模板

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = b'0123456789abcdef'
ct = bytes.fromhex('')
cipher = AES.new(key, AES.MODE_ECB)
print(unpad(cipher.decrypt(ct), 16))
```

### 常见考点

- ECB 模式泄露结构。
- CBC bit flipping。
- Padding Oracle。
- CTR nonce 重用。
- 弱随机数生成 key。

## Level 7：随机数与伪随机

常见问题：

- Python `random` 不适合密码学。
- 时间戳作为种子可以爆破。
- MT19937 可以状态恢复。
- 多次使用相同 nonce/key 会出问题。

时间种子爆破：

```python
import random, time

known = 123456
now = int(time.time())
for seed in range(now - 10000, now + 1):
    random.seed(seed)
    if random.randint(0, 999999) == known:
        print(seed)
```

## Level 8：进阶主题

入门后再学：

- ECC 椭圆曲线
- Lattice 格攻击
- Coppersmith
- Paillier
- Schnorr / ECDSA nonce 泄露
- LFSR
- Shamir Secret Sharing

## 做题检查清单

- 是否是编码而不是加密？
- 是否有明显 Base64 / Hex / URL 编码？
- 是否知道 flag 格式，可以做已知明文？
- 是否有 XOR 特征？
- RSA 是否给了 `p/q/n/e/c`？
- RSA 的 `e` 是否很小？
- 多个 RSA 的 `n` 是否有公共因子？
- `p` 和 `q` 是否接近？
- AES 是否给了 key、iv、mode？
- 是否使用了固定 IV 或重复 nonce？
- 是否用了 Python `random`？

## 推荐练习

1. CryptoHack：系统学习密码学。
2. picoCTF Crypto：入门友好。
3. BUUCTF Crypto：经典 RSA 题多。
4. NSSCTF Crypto：新题和比赛题较多。
5. 攻防世界 Crypto：基础题适合巩固。

## 硬核进阶路线

### 阶段 1：数学基础补强

目标：能看懂 RSA、ECC、格攻击相关题解里的数学符号。

必学内容：

- 数论：整除、同余、欧拉函数、费马小定理、欧拉定理。
- 扩展欧几里得：求 gcd 和模逆元。
- 中国剩余定理 CRT。
- 有限域：模素数域、模多项式域。
- 群、环、域的基本概念。
- 多项式运算。
- 线性代数：矩阵、基、线性相关、向量空间。
- 概率论：随机变量、生日悖论、熵。

推荐书籍：

- 《具体数学》：离散数学和数论思维训练。
- 《数论概论》：数论入门。
- 《Introduction to Modern Cryptography》：现代密码学理论入门。
- 《Understanding Cryptography》：工程和数学平衡较好。
- 《A Course in Number Theory and Cryptography》：数论密码学经典。

阶段验收：

- 能手写扩展欧几里得和 CRT。
- 能解释为什么 RSA 需要 `gcd(e, phi)=1`。
- 能用 Python 实现模逆、快速幂、CRT。
- 能看懂 CryptoHack 前半部分题解。

### 阶段 2：RSA 专项

目标：遇到 RSA 题能快速识别是哪类攻击。

必须掌握：

- 基础 RSA 解密。
- 小指数攻击。
- Hastad 广播攻击。
- 共模攻击。
- 低私钥指数 Wiener attack。
- Boneh-Durfee 思路。
- Fermat 分解。
- Pollard p-1 / rho。
- 公共因子批量 gcd。
- dp/dq 泄露。
- p 高位/低位泄露。
- Coppersmith 小根攻击。
- Franklin-Reiter related message attack。
- RSA padding：PKCS#1 v1.5、OAEP。
- Bleichenbacher padding oracle 原理。

工具：

- SageMath：格、Coppersmith、代数计算。
- RsaCtfTool：快速识别简单 RSA 弱点。
- factordb：查常见可分解 n。
- gmpy2 / sympy：基础数论。

推荐资料：

- Twenty Years of Attacks on the RSA Cryptosystem。
- Boneh 的 RSA survey。
- CryptoHack RSA 章节。
- RsaCtfTool 源码和 examples。

阶段验收：

- 能整理一份 RSA 攻击决策树。
- 能独立完成 50 道 RSA 题。
- 能用 Sage 跑基础 Coppersmith 小根。
- 能解释 Wiener 和 Coppersmith 适用条件。

### 阶段 3：对称密码和分组模式

目标：理解 AES 本身、模式安全性和 oracle 攻击。

必须掌握：

- AES 结构：SubBytes、ShiftRows、MixColumns、AddRoundKey。
- ECB：模式泄露、字节逐位泄露 oracle。
- CBC：bit flipping、padding oracle。
- CTR：nonce 重用、流密码等价。
- GCM：认证标签、nonce 重用灾难。
- MAC：CBC-MAC、HMAC、长度扩展攻击。
- Hash：MD5、SHA1、SHA256、Merkle-Damgard。

推荐书籍/资料：

- 《Serious Cryptography》：现代密码工程入门，非常推荐。
- Cryptopals Crypto Challenges：对称密码和协议攻击经典训练。
- The Cryptopals Set 1-4：必须做。
- Hash Length Extension Attack 相关 writeup。

阶段验收：

- 完成 Cryptopals Set 1-4。
- 能手写 CBC bit flipping。
- 能实现 padding oracle 攻击脚本。
- 能解释 CTR nonce 重用为什么会暴露明文关系。

### 阶段 4：随机数、流密码和状态恢复

目标：能处理伪随机数和流密码题。

必须掌握：

- Python random / MT19937。
- MT19937 状态恢复。
- LCG 参数恢复。
- LFSR 和 Berlekamp-Massey。
- RC4 KSA/PRGA。
- nonce/key 重用。
- 时间种子爆破。

推荐资料：

- Cryptopals Set 3。
- CryptoHack Symmetric Ciphers / Stream Ciphers。
- randcrack 源码。
- Berlekamp-Massey algorithm 讲解。

阶段验收：

- 能从 624 个 MT 输出恢复状态。
- 能从 LCG 输出恢复参数。
- 能用 BM 算法恢复 LFSR 反馈多项式。

### 阶段 5：椭圆曲线 ECC

目标：能做中等 ECC CTF 题。

必须掌握：

- 椭圆曲线群定义。
- 点加、倍点、标量乘。
- ECDLP。
- ECDH。
- ECDSA。
- nonce 泄露导致私钥恢复。
- 重复 nonce 攻击。
- invalid curve attack。
- small subgroup attack。
- MOV attack 基本概念。

推荐书籍/资料：

- 《An Introduction to Mathematical Cryptography》：ECC 章节质量高。
- CryptoHack ECC 章节。
- SafeCurves：理解曲线安全性。
- ECDSA nonce reuse writeup。

阶段验收：

- 能用 Sage 实现椭圆曲线点加和标量乘。
- 能完成 ECDSA nonce 重用私钥恢复。
- 能解释小子群攻击的思路。

### 阶段 6：格攻击 Lattice

目标：能看懂 CTF Crypto 进阶题里最常见的 LLL 用法。

必须掌握：

- 格、基、行列式、最短向量问题。
- LLL 算法用途。
- 背包密码和低密度攻击。
- Coppersmith 小根。
- Hidden Number Problem。
- ECDSA 部分 nonce 泄露。
- RSA p 部分 bit 泄露。

工具：

- SageMath。
- fpylll。
- flatter。

推荐资料：

- 《A Decade of Lattice Cryptography》：格密码综述。
- defund/coppersmith 相关实现。
- Connor McCartney 的 CTF Crypto lattice notes。
- CryptoHack Lattices。

阶段验收：

- 能用 Sage 调 `LLL()`。
- 能复现基础背包攻击。
- 能复现 RSA 高位泄露恢复 p。
- 能复现 ECDSA partial nonce attack。

### 阶段 7：现代密码协议

目标：从算法题走向协议漏洞题。

方向：

- Diffie-Hellman 参数攻击。
- SRP 协议弱点。
- TLS 历史漏洞概念。
- Padding oracle 协议化利用。
- 签名伪造。
- 零知识证明基础。
- 同态加密和 Paillier。
- Shamir Secret Sharing。

推荐资料：

- Cryptopals Set 5-8。
- 《Real-World Cryptography》。
- 《Serious Cryptography》。
- TLS 1.2 / 1.3 协议材料。

长期训练任务：

- CryptoHack 全站至少完成 General、Mathematics、RSA、Symmetric、ECC。
- Cryptopals 至少完成 Set 1-6。
- 每周复现 1 道高质量 Crypto writeup。
- 每月整理 1 类攻击模板，比如 RSA、LFSR、ECC、Lattice。
