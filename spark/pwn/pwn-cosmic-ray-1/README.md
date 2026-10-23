# cosmic-ray-1

`./pwn`本身无法直接完成利用

服务端会复制 `./pwn`，按你的"宇宙射线"改变**一个字节**，运行补丁后的程序，把该进程的`/proc/<pid>/maps` 发给你，最后把你发送的 **exp**（十六进制字节串）作为输入喂给它。

要求：

1. 给出一个**文件偏移**（十六进制）和一个**单字节**机器码（十六进制）；
2. 再给出一段 **exp**（十六进制）；
3. 让打了该补丁后的程序输出 flag。

(AwdPwnPatcher真的很好用，推荐学习)

## 交互格式

```
[1/1] Enter patch location (hex file offset): <hex>
[1/1] Enter patch machine code (hex byte): <hex byte>
<... 子进程 maps ...>
[1/1] Enter exp (hex): <hex payload>
```

通过后会收到 `Well Done.`和flag。

## 附件

- `pwn`：目标程序，IBT/SHSTK未实际启用
- `libc.so.6`、`ld-linux-x86-64.so.2`：与线上一致
- `solve.py`：解题模板，补全 `ROUNDS` 和 `build_payload` 即可

## 运行

```
python3 solve.py
python3 solve.py remote <host> <port>
```
