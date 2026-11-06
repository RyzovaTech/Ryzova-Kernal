/* SPDX-License-Identifier: AGPL-3.0-only */
/* SysV main arguments. The Darwin-numbered traps use M3's bounded profile. */
.text
.globl start
start:
    mov 8(%rsi), %rdi
    mov (%rdx), %rbp
    mov $2, %esi
    mov $0x2000005, %eax
    syscall
    jc denied
    mov %eax, %ebx

    mov %ebx, %edi
    lea scratch(%rip), %rsi
    mov $4, %edx
    mov $0x2000003, %eax
    syscall
    jc denied
    cmp $4, %rax
    jne denied

    mov $1, %edi
    lea scratch(%rip), %rsi
    mov $0x2000004, %eax
    syscall
    jc denied

    mov %ebx, %edi
    mov %rbp, %rsi
    mov $14, %edx
    mov $0x2000004, %eax
    syscall
    jc denied
    cmp $14, %rax
    jne denied

    mov %ebx, %edi
    mov $0x2000006, %eax
    syscall
    jc denied
    mov $37, %eax
    ret
denied:
    mov $13, %eax
    ret

.org 0xe00
scratch:
