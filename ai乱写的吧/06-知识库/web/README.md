# Web 知识库

## 学习目标

Web 方向主要考察对 HTTP、浏览器、服务端语言、数据库、文件系统和常见漏洞的理解。入门阶段不要急着背漏洞名，先学会看请求、改参数、读源码、验证输入输出关系。

## Level 0：基础工具和概念

### 必会概念

- URL：协议、域名、端口、路径、查询参数。
- HTTP 方法：GET、POST、PUT、DELETE。
- 请求头：Cookie、User-Agent、Referer、Content-Type、Authorization。
- 响应状态码：200、301、302、403、404、500。
- 表单提交：普通表单、JSON、文件上传。
- Cookie / Session：登录态如何维持。
- 前端与后端：浏览器执行 JS，服务器处理业务逻辑。

### 必会工具

- 浏览器开发者工具：Network、Application、Console。
- Burp Suite：Proxy、HTTP history、Repeater。
- curl：命令行发请求。
- Python requests：写自动化请求脚本。

### 常用命令

```bash
curl -i http://target/
curl -X POST http://target/login -d 'username=admin&password=123456'
curl -H 'Cookie: PHPSESSID=xxx' http://target/profile
```

```python
import requests

url = 'http://target/'
r = requests.get(url)
print(r.status_code)
print(r.text)
```

## Level 1：信息收集

### 目录扫描

目标：找隐藏路径、备份文件、管理后台。

```bash
ffuf -u http://target/FUZZ -w wordlist.txt
ffuf -u http://target/FUZZ.php -w wordlist.txt
gobuster dir -u http://target -w wordlist.txt
```

常见敏感路径：

```text
/admin
/login
/backup
/uploads
/www.zip
/.git/
/robots.txt
/index.php.bak
/config.php.bak
```

### 源码泄露

常见形式：

- `.git` 泄露
- `.svn` 泄露
- 备份文件：`.bak`、`.zip`、`.tar.gz`、`.swp`
- 编辑器临时文件

检查思路：

1. 看页面源码。
2. 看 `robots.txt`。
3. 扫描常见备份文件。
4. 如果拿到源码，优先找配置、路由、过滤逻辑。

## Level 2：编码、参数和弱逻辑

### 常见编码

- URL 编码：`%20`、`%2f`
- Base64
- Hex
- HTML 实体编码
- Unicode 编码

### 弱逻辑

常见题型：

- 前端校验绕过
- Cookie 伪造
- JWT 弱密钥或 none 算法
- 参数越权：`id=1` 改 `id=2`
- 支付金额改小
- 只判断用户名不判断密码
- 只在前端隐藏按钮

判断原则：

> 前端代码不可信，浏览器发出的所有请求都可以被 Burp 修改。

## Level 3：SQL 注入

### 基础判断

常见参数：

```text
?id=1
?username=admin
?search=abc
```

测试：

```text
?id=1'
?id=1 and 1=1
?id=1 and 1=2
?id=1 order by 1
?id=1 union select 1,2,3
```

### 注入类型

- 联合查询注入
- 报错注入
- 布尔盲注
- 时间盲注
- 堆叠注入
- 二次注入

### sqlmap 基础用法

```bash
sqlmap -u 'http://target/item.php?id=1'
sqlmap -u 'http://target/item.php?id=1' --dbs
sqlmap -u 'http://target/item.php?id=1' -D dbname --tables
sqlmap -u 'http://target/item.php?id=1' -D dbname -T users --dump
```

### 手工注入思路

1. 判断是否存在注入。
2. 判断列数。
3. 判断回显位。
4. 查询数据库名。
5. 查询表名。
6. 查询列名。
7. 查询数据。

## Level 4：文件相关漏洞

### 文件上传

绕过方式：

- 改后缀：`.php`、`.phtml`、`.phar`
- MIME 绕过：改 `Content-Type`
- 图片马：文件头加 `GIF89a`
- 双写后缀：`.php.jpg`
- 大小写绕过：`.pHp`
- 解析漏洞：和服务器配置有关

检查点：

1. 上传后文件保存路径在哪里。
2. 是否能访问上传文件。
3. 服务器是否会执行脚本。
4. 是否只校验前端。

### 文件包含

常见参数：

```text
?page=home
?file=index.php
?path=about
```

测试：

```text
?page=../../../../etc/passwd
?page=php://filter/read=convert.base64-encode/resource=index.php
?page=data://text/plain,<?php system('id');?>
```

类型：

- 本地文件包含 LFI
- 远程文件包含 RFI
- PHP 伪协议
- 日志包含
- session 文件包含

### 文件读取 / 下载

常见目标：

```text
/etc/passwd
/proc/self/environ
/var/www/html/index.php
/app/config.php
C:\Windows\win.ini
```

## Level 5：命令执行和代码执行

### 命令注入

常见危险函数：

```php
system
exec
shell_exec
passthru
popen
proc_open
```

常见拼接符：

```text
;
&&
||
|
`
$()
%0a
```

测试：

```text
127.0.0.1;id
127.0.0.1&&whoami
127.0.0.1|ls
```

### 代码执行

常见函数：

```php
eval
assert
preg_replace /e
create_function
unserialize
```

核心思路：

1. 找到可控输入。
2. 判断输入是否进入危险函数。
3. 判断过滤规则。
4. 构造最短 payload。

## Level 6：XSS 和前端安全

### XSS 类型

- 反射型 XSS
- 存储型 XSS
- DOM 型 XSS

基础 payload：

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

CTF 常见目标：

- 让 bot 访问页面。
- 读取 bot 的 Cookie。
- 绕过 CSP。
- 利用 DOMPurify 版本漏洞。

## Level 7：SSRF

### 基础概念

SSRF 是让服务器代替你访问某个地址。

常见参数：

```text
?url=http://example.com
?image=http://example.com/a.png
?api=http://example.com
```

常见目标：

```text
http://127.0.0.1/
http://localhost/
http://0.0.0.0/
http://[::1]/
http://169.254.169.254/
```

绕过思路：

- IP 进制转换
- DNS rebinding
- 跳转绕过
- gopher 协议
- URL 解析差异

## Level 8：反序列化

### PHP 反序列化

关键函数：

```php
serialize
unserialize
__wakeup
__destruct
__toString
__call
```

学习重点：

1. 看类定义。
2. 找魔术方法。
3. 找可控属性。
4. 构造 POP 链。
5. 触发危险函数。

### Java / Python 反序列化

入门阶段先了解：

- Java：ysoserial、CommonsCollections。
- Python：pickle 反序列化。
- Node.js：node-serialize。

## Level 9：模板注入 SSTI

常见模板：

- Python Jinja2
- Twig
- Smarty
- Freemarker
- Velocity

判断：

```text
{{7*7}}
${7*7}
<%= 7*7 %>
```

Jinja2 常见方向：

```text
{{config}}
{{self.__dict__}}
```

核心目标：从模板上下文逐步拿到文件读取或命令执行能力。

## Level 10：综合题思路

综合 Web 题通常不是单点漏洞，而是链式利用。

常见链：

```text
源码泄露 -> 审计源码 -> SQL 注入 -> 登录后台 -> 文件上传 -> getshell
```

```text
SSRF -> 访问内网服务 -> Redis/Gopher -> 写文件 -> RCE
```

```text
任意文件读取 -> 读源码/配置 -> 拿密钥 -> 伪造 Cookie/JWT -> 进入后台
```

## 做题检查清单

- 是否看过页面源码？
- 是否抓过包？
- 是否尝试改 Cookie / Header / 参数？
- 是否扫过目录？
- 是否查看 `robots.txt`？
- 是否测试 SQL 注入？
- 是否存在文件上传？
- 是否存在文件读取参数？
- 是否有源码泄露？
- 是否有登录逻辑漏洞？
- 是否可以通过报错获得路径或框架信息？

## 推荐练习

1. PortSwigger Web Security Academy：HTTP、SQLi、XSS、SSRF、文件上传。
2. CTFHub：Web 技能树。
3. ctf.show：Web 入门和命令执行。
4. NSSCTF：刷新题。
5. BUUCTF：复现经典题。

## 硬核进阶路线

### 阶段 1：Web 基础工程能力

目标：不只会打 payload，而是能看懂一个 Web 应用怎么写出来。

必学内容：

- HTML / CSS / JavaScript 基础。
- HTTP/1.1、HTTP/2、Cookie、Session、CORS、缓存。
- PHP 基础：数组、字符串、文件上传、反序列化、常见危险函数。
- Python Flask/FastAPI 基础。
- Node.js Express 基础。
- Java Spring Boot 基础。
- MySQL 基础：SELECT、INSERT、UPDATE、JOIN、权限、information_schema。
- Redis、MongoDB 基础。

推荐书籍：

- 《HTTP 权威指南》：理解 HTTP 协议。
- 《JavaScript 高级程序设计》：理解前端和 DOM。
- 《PHP 和 MySQL Web 开发》：CTF Web 里 PHP 很常见。
- 《高性能 MySQL》：理解 SQL、索引和数据库行为。

阶段验收：

- 能自己写一个登录、上传、数据库查询的小网站。
- 能用 Burp 完整抓登录、上传、接口请求。
- 能解释 Cookie、Session、JWT 的区别。

### 阶段 2：漏洞原理专项

目标：每类漏洞都能手工验证、解释成因、写最小 demo。

专项列表：

- SQL 注入：联合注入、报错注入、布尔盲注、时间盲注、二次注入、堆叠注入、宽字节注入。
- XSS：反射型、存储型、DOM 型、CSP 绕过、模板场景 XSS。
- CSRF：Token、SameSite、Referer 校验绕过。
- SSRF：内网探测、协议利用、gopher、云元数据、URL parser 差异。
- 文件上传：后缀、MIME、内容检测、解析漏洞、条件竞争、对象存储绕过。
- 文件包含：LFI、RFI、PHP 伪协议、日志包含、session 包含。
- 命令执行：shell 元字符、环境变量、无字母数字绕过、过滤器绕过。
- 模板注入：Jinja2、Twig、Smarty、Freemarker。
- 反序列化：PHP POP 链、Java gadget、Python pickle、Node serialize。
- XXE：外部实体、文件读取、SSRF、盲 XXE。
- 访问控制：IDOR、越权、水平/垂直权限绕过。
- OAuth/OIDC/SAML：redirect_uri、state、token 泄露、签名校验。

推荐资源：

- PortSwigger Web Security Academy：Web 漏洞体系最完整的免费训练。
- OWASP Web Security Testing Guide：Web 测试方法论。
- OWASP Top 10：漏洞分类框架。
- PayloadsAllTheThings：payload 参考，但不要只复制。
- HackTricks：知识面很广，适合查漏补缺。

阶段验收：

- 每类漏洞至少做 10 道题或实验。
- 每类漏洞写一个最小复现 demo。
- 能不用 sqlmap 手工完成基础 SQL 注入。
- 能独立分析一条 SSRF 到 RCE 的链。

### 阶段 3：源码审计

目标：看到源码能定位漏洞，而不是只靠黑盒猜。

PHP 审计重点：

- 超全局变量：`$_GET`、`$_POST`、`$_COOKIE`、`$_FILES`、`$_SERVER`。
- 危险函数：`eval`、`assert`、`system`、`exec`、`shell_exec`、`unserialize`、`include`、`require`。
- 文件函数：`file_get_contents`、`fopen`、`move_uploaded_file`。
- 弱比较：`==`、`0e`、数组绕过。
- 变量覆盖：`extract`、`parse_str`、动态变量。

Java 审计重点：

- Spring MVC 路由和参数绑定。
- Fastjson/Jackson 反序列化。
- SpEL 表达式注入。
- Shiro、Log4j、Struts2 经典漏洞链。
- 文件上传和路径穿越。
- JDBC/MyBatis SQL 注入。

Node.js 审计重点：

- 原型污染。
- 模板注入。
- 反序列化。
- child_process 命令执行。
- npm 依赖漏洞。

Python 审计重点：

- Flask/Jinja2 SSTI。
- pickle 反序列化。
- yaml.load。
- subprocess 命令拼接。
- Django debug、模板和 ORM 使用错误。

推荐书籍与资料：

- 《白帽子讲 Web 安全》：中文 Web 安全经典入门。
- 《Web 安全深度剖析》：适合中文体系化补基础。
- 《代码审计：企业级 Web 代码安全架构》：PHP 审计入门。
- 《Java 安全漫谈》：Java 安全和反序列化入门。
- Orange Tsai 的博客和议题：SSRF、URL parser、Web 漏洞链很强。

阶段验收：

- 能审计一个 1k-5k 行的小型 PHP 项目。
- 能从路由入口追踪用户输入到危险函数。
- 能画出漏洞数据流：source -> sanitize -> sink。
- 能写出可复现的漏洞报告。

### 阶段 4：真实漏洞和框架安全

目标：从 CTF Web 走向真实漏洞研究。

方向：

- Java 反序列化 gadget 链。
- Spring、Struts2、Shiro、Fastjson、Log4j 漏洞复现。
- PHP 框架：ThinkPHP、Laravel、Yii 历史漏洞。
- Node.js 原型污染到 RCE。
- 云安全：SSRF 到云元数据、AK/SK 滥用。
- 容器安全：Docker API、Kubernetes Dashboard、服务账户 token。
- OAuth/OIDC/SAML 认证协议漏洞。

推荐资源：

- Project Zero Blog。
- PortSwigger Research。
- Orange Tsai 演讲。
- 先知社区漏洞分析。
- 安全客漏洞复现文章。
- 各类 CVE 的官方 patch diff。

阶段验收：

- 每月复现 1 个真实 CVE。
- 能读 patch diff 判断漏洞点。
- 能写最小漏洞环境和利用说明。

### 阶段 5：Web 方向比赛打法

比赛优先级：

1. 先看题目是否有源码。
2. 有源码先审入口、路由、配置、依赖版本。
3. 无源码先抓包、扫目录、看 robots、看响应头。
4. 优先打信息泄露、弱逻辑、SQLi、文件读取。
5. 后台题重点看上传、模板、反序列化、命令执行。
6. 链式题要记录每一步拿到的新信息。

长期训练任务：

- 完成 PortSwigger Academy 全部 Apprentice 和 Practitioner 实验。
- CTFHub Web 技能树至少刷完基础模块。
- ctf.show Web 入门、命令执行、文件包含、SQL 注入专题刷完。
- 每周复现 1 篇高质量 Web writeup。
- 每月复现 1 个真实 Web CVE。
