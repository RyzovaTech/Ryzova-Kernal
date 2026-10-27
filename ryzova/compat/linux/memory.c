/* SPDX-License-Identifier: AGPL-3.0-only */
#include "process.h"

int ryz_memory_access(RyzLinuxMemory *m, uint64_t address, uint64_t size, unsigned int flags)
{
    uint64_t start, end, i;
    if (address < m->base || address - m->base > m->size ||
        size > m->size - (address - m->base))
        return 0;
    if (size == 0)
        return 1;
    start = (address - m->base) / RYZ_PAGE;
    end = (address - m->base + size - 1) / RYZ_PAGE;
    for (i = start; i <= end; ++i)
        if ((m->pages[i] & (RYZ_MAP | flags)) != (RYZ_MAP | flags))
            return 0;
    return 1;
}
int ryz_memory_read(void *m, uint64_t address, uint64_t size)
{
    return ryz_memory_access(m,address,size,RYZ_READ);
}
int ryz_memory_write(void *m, uint64_t address, uint64_t size)
{
    return ryz_memory_access(m,address,size,RYZ_WRITE);
}
static uint64_t alignpage(uint64_t x)
{
    return (x + RYZ_PAGE - 1) & ~(uint64_t)(RYZ_PAGE - 1);
}
static void mark(RyzLinuxMemory *m, uint64_t lo, uint64_t hi, unsigned int flags)
{
    uint64_t i;
    for (i = (lo - m->base) / RYZ_PAGE; i < (hi - m->base) / RYZ_PAGE; ++i)
        m->pages[i] = (unsigned char)flags;
}
static int freepages(RyzLinuxMemory *m, uint64_t lo, uint64_t hi)
{
    uint64_t i;
    for (i = (lo - m->base) / RYZ_PAGE; i < (hi - m->base) / RYZ_PAGE; ++i)
        if (m->pages[i] != 0)
            return 0;
    return 1;
}
int64_t ryz_memory_call(void *context, const RyzLinuxRegs *r)
{
    RyzLinuxMemory *m = context;
    uint64_t lo, hi, size, old, at, i, ceiling;
    unsigned int flags;
    ceiling=m->stack-RYZ_PAGE; /* Unmapped guard below the initial stack. */
    if (r->rax == 12) {
        lo = r->rdi;
        if (lo == 0)
            return (int64_t)m->brk;
        if (lo < m->heap || lo > ceiling)
            return (int64_t)m->brk;
        old = alignpage(m->brk);
        hi = alignpage(lo);
        if (hi > old) {
            if (!freepages(m,old,hi))
                return (int64_t)m->brk;
            mark(m,old,hi,RYZ_MAP|RYZ_READ|RYZ_WRITE);
            memset(m->bytes + (size_t)(old-m->base),0,(size_t)(hi-old));
        } else if (hi < old) {
            mark(m,hi,old,0);
            memset(m->bytes + (size_t)(hi-m->base),0,(size_t)(old-hi));
        }
        m->brk = lo;
        return (int64_t)lo;
    }
    size = r->rsi;
    if (size == 0 || size > m->size)
        return -22;
    size = alignpage(size);
    if (r->rax == 9) {
        if (r->rdi != 0 || r->r10 != 34 || r->r8 != UINT64_MAX || r->r9 != 0)
            return -22;
        if ((r->rdx & ~UINT64_C(3)) != 0)
            return -1; /* Anonymous executable memory is outside this profile. */
        flags = RYZ_MAP | ((r->rdx & 1) ? RYZ_READ : 0) | ((r->rdx & 2) ? RYZ_WRITE : 0);
        lo = alignpage(m->brk);
        if (lo > ceiling || size > ceiling - lo)
            return -12;
        at = ceiling - size;
        for (;;) {
            if (freepages(m,at,at+size)) {
                mark(m,at,at+size,flags);
                memset(m->bytes+(size_t)(at-m->base),0,(size_t)size);
                return (int64_t)at;
            }
            if (at == lo)
                break;
            at -= RYZ_PAGE;
        }
        return -12;
    }
    lo = r->rdi;
    if ((lo & (RYZ_PAGE-1)) != 0 || lo < alignpage(m->brk) ||
        lo >= ceiling || size > ceiling-lo)
        return -22;
    hi = lo + size;
    if (r->rax == 11) {
        mark(m,lo,hi,0);
        memset(m->bytes+(size_t)(lo-m->base),0,(size_t)size);
        return 0;
    }
    if (r->rax == 10) {
        if ((r->rdx & ~UINT64_C(3)) != 0)
            return -1;
        for (i=(lo-m->base)/RYZ_PAGE;i<(hi-m->base)/RYZ_PAGE;++i)
            if ((m->pages[i] & RYZ_MAP) == 0)
                return -12; /* Validate whole range before changing any page. */
        flags = RYZ_MAP | ((r->rdx&1) ? RYZ_READ:0) | ((r->rdx&2) ? RYZ_WRITE:0);
        mark(m,lo,hi,flags);
        return 0;
    }
    return -38;
}
