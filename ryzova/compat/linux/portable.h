/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZ_COMPACT_PORTABLE_H
#define RYZ_COMPACT_PORTABLE_H
#ifdef RYZ_PLAN9
#include <u.h>
#include <libc.h>
typedef usize size_t;
typedef u8int uint8_t;
typedef s8int int8_t;
typedef u16int uint16_t;
typedef u32int uint32_t;
typedef s32int int32_t;
typedef u64int uint64_t;
typedef s64int int64_t;
#define NULL nil
#define UINT64_C(x) ((uint64_t)(x))
#define UINT32_C(x) ((uint32_t)(x))
#define UINT64_MAX (~(uint64_t)0)
#define SIZE_MAX (~(size_t)0)
#else
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#endif
#endif
