/* SPDX-License-Identifier: GPL-3.0-only */
.text
.globl _main
_main:
#if defined(__aarch64__)
    stp x29, x30, [sp, #-16]!
    stp x19, x20, [sp, #-16]!
    sub sp, sp, #16
    ldr x0, [x1, #8]
    ldr x20, [x2]
    mov w1, #2
    bl _open
    cmn w0, #1
    b.eq Lfail
    mov w19, w0
    add x1, sp, #0
    mov w2, #4
    bl _read
    cmp x0, #4
    b.ne Lfail
    mov w0, #1
    add x1, sp, #0
    mov w2, #4
    bl _write
    cmp x0, #4
    b.ne Lfail
    mov w0, w19
    mov x1, x20
    mov w2, #14
    bl _write
    cmp x0, #14
    b.ne Lfail
    mov w0, w19
    bl _close
    cmp x0, #0
    b.ne Lfail
    mov w0, #61
    b Lreturn
Lfail:
    mov w0, #13
Lreturn:
    add sp, sp, #16
    ldp x19, x20, [sp], #16
    ldp x29, x30, [sp], #16
    ret
#else
    pushq %rbp
    pushq %rbx
    pushq %rax
    movq 8(%rsi), %rdi
    movq (%rdx), %rbp
    movl $2, %esi
    movl $0, %eax
    callq _open
    cmpl $-1, %eax
    je Lfail
    movl %eax, %ebx
    movl %eax, %edi
    movq %rsp, %rsi
    movl $4, %edx
    callq _read
    cmpq $4, %rax
    jne Lfail
    movl $1, %edi
    movq %rsp, %rsi
    movl $4, %edx
    callq _write
    cmpq $4, %rax
    jne Lfail
    movl %ebx, %edi
    movq %rbp, %rsi
    movl $14, %edx
    callq _write
    cmpq $14, %rax
    jne Lfail
    movl %ebx, %edi
    callq _close
    cmpq $0, %rax
    jne Lfail
    movl $61, %eax
    jmp Lreturn
Lfail:
    movl $13, %eax
Lreturn:
    addq $8, %rsp
    popq %rbx
    popq %rbp
    retq
#endif
