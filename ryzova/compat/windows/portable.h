/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef CW_PORTABLE_H
#define CW_PORTABLE_H
#ifdef CW_PLAN9
#include <u.h>
#include <libc.h>
typedef usize size_t;
typedef uintptr uintptr_t;
typedef u8int uint8_t;
typedef s8int int8_t;
typedef u16int uint16_t;
typedef s16int int16_t;
typedef u32int uint32_t;
typedef s32int int32_t;
typedef u64int uint64_t;
typedef s64int int64_t;
#define NULL nil
#define UINT64_C(x) ((uint64_t)(x))
#define UINT32_C(x) ((uint32_t)(x))
#define UINT64_MAX (~(uint64_t)0)
#define UINT32_MAX (~(uint32_t)0)
#define SIZE_MAX (~(size_t)0)
#else
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#endif
#endif
