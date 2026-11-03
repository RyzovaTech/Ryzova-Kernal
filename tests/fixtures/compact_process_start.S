/* SPDX-License-Identifier: AGPL-3.0-only */
.global _start
.section .text
_start:
    mov (%rsp), %rdi
    lea 8(%rsp), %rsi
    lea 16(%rsp,%rdi,8), %rdx
    and $-16, %rsp
    call app_main
    mov %rax, %rdi
    mov $60, %eax
    syscall
.section .note.GNU-stack,"",@progbits
