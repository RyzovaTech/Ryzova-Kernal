/* SPDX-License-Identifier: AGPL-3.0-only */
.text
.globl _main
.p2align 2
_main:
    stp x29, x30, [sp, #-16]!
    adrp x1, Lpointer@PAGE
    ldr x1, [x1, Lpointer@PAGEOFF]
    mov w0, #1
    mov w2, #21
    bl _write
    cmp x0, #21
    b.ne Lfailed
    mov w0, #53
    ldp x29, x30, [sp], #16
    ret
Lfailed:
    mov w0, #1
    ldp x29, x30, [sp], #16
    ret

.section __TEXT,__const
Lmessage:
    .ascii "FLEX_MACOS_M5_ARM64!\n"

.section __DATA_CONST,__const
.p2align 3
Lpointer:
    .quad Lmessage
