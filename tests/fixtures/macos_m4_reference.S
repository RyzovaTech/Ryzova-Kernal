/* SPDX-License-Identifier: GPL-3.0-only */
.text
.globl _main
.p2align 4
_main:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %rax
    movq Lpointer(%rip), %rsi
    movl $1, %ebx
    movl $(Lmessage_end-Lmessage), %edx
    movl $1, %edi
    callq _write
    cmpq $(Lmessage_end-Lmessage), %rax
    movl $47, %eax
    cmovnel %ebx, %eax
    addq $8, %rsp
    popq %rbx
    popq %rbp
    retq

.section __TEXT,__const
Lmessage:
    .ascii "FLEX_MACOS_M4_DYNAMIC\n"
Lmessage_end:

.section __DATA_CONST,__const
.p2align 3
Lpointer:
    .quad Lmessage
