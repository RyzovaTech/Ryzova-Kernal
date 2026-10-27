/* SPDX-License-Identifier: AGPL-3.0-only */
/* No host syscalls or Linux kernel code. Parsing must not execute images. */
#include "elf64.h"

#define PT_LOAD 1U
#define PT_DYNAMIC 2U
#define PT_INTERP 3U
#define PT_TLS 7U
#define PT_GNU_STACK UINT32_C(0x6474e551)
#define PF_X 1U
#define PF_W 2U
#define USER_MIN UINT64_C(0x10000)
#define USER_LIMIT UINT64_C(0x0000800000000000)

static uint16_t le16(const unsigned char *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static uint32_t le32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t le64(const unsigned char *p)
{
    return (uint64_t)le32(p) | ((uint64_t)le32(p + 4) << 32);
}
static int span(size_t total, uint64_t offset, uint64_t count)
{
    uint64_t n = (uint64_t)total;
    return offset <= n && count <= n - offset;
}
static int power2(uint64_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}
static int overlapping(uint64_t lo1, uint64_t hi1,
                       uint64_t lo2, uint64_t hi2)
{
    return lo1 < hi2 && lo2 < hi1;
}

int ryz_elf64_plan(const unsigned char *image, size_t length, RyzElf64Plan *out)
{
    RyzElf64Plan plan;
    uint64_t phoff, entry, sum = 0;
    unsigned int phnum, i, j;
    int has_entry = 0;

    if (out != NULL)
        memset(out, 0, sizeof(*out));
    if (image == NULL || out == NULL)
        return RYZ_ELF_BAD_ARG;
    if (length < 64)
        return RYZ_ELF_BAD_HEADER;

    /* ELF64, little endian, current version, System V or GNU/Linux ABI. */
    if (image[0] != 0x7f || image[1] != 'E' || image[2] != 'L' ||
        image[3] != 'F' || image[4] != 2 || image[5] != 1 ||
        image[6] != 1 || (image[7] != 0 && image[7] != 3) ||
        image[8] != 0)
        return RYZ_ELF_BAD_HEADER;

    /* ET_EXEC only: PIE / dynamic linker and relocation deferred to Phase 5.2+. */
    if (le16(image + 16) != 2 || le16(image + 18) != 62 ||
        le32(image + 20) != 1)
        return RYZ_ELF_UNSUPPORTED;
    if (le16(image + 52) != 64 || le16(image + 54) != 56)
        return RYZ_ELF_BAD_HEADER;
    phoff = le64(image + 32);
    phnum = le16(image + 56);
    if (phnum == 0 || phnum > RYZ_ELF64_MAX_PHDR ||
        !span(length, phoff, (uint64_t)phnum * 56U))
        return RYZ_ELF_BOUNDS;

    entry = le64(image + 24);
    if (entry < USER_MIN || entry >= USER_LIMIT)
        return RYZ_ELF_POLICY;

    memset(&plan, 0, sizeof(plan));
    plan.entry = entry;
    for (i = 0; i < phnum; ++i) {
        const unsigned char *p = image + (size_t)(phoff + (uint64_t)i * 56U);
        uint32_t type = le32(p);
        uint32_t flags = le32(p + 4);
        uint64_t offset = le64(p + 8);
        uint64_t vaddr = le64(p + 16);
        uint64_t file_size = le64(p + 32);
        uint64_t memory_size = le64(p + 40);
        uint64_t alignment = le64(p + 48);
        uint64_t end, start, map_end;
        RyzElf64Segment *seg;

        if (type == PT_DYNAMIC || type == PT_INTERP || type == PT_TLS)
            return RYZ_ELF_UNSUPPORTED;
        if (type == PT_GNU_STACK && (flags & PF_X))
            return RYZ_ELF_POLICY;
        if (type != PT_LOAD)
            continue;
        if (plan.load_count == RYZ_ELF64_MAX_LOAD || memory_size == 0 ||
            file_size > memory_size || (flags & ~(PF_X | PF_W | 4U)) != 0)
            return RYZ_ELF_POLICY;
        if ((flags & (PF_W | PF_X)) == (PF_W | PF_X))
            return RYZ_ELF_POLICY;
        if (alignment > 1 && (!power2(alignment) ||
                               vaddr % alignment != offset % alignment))
            return RYZ_ELF_POLICY;
        if (vaddr % RYZ_ELF64_PAGE_SIZE != offset % RYZ_ELF64_PAGE_SIZE)
            return RYZ_ELF_POLICY;
        if (!span(length, offset, file_size))
            return RYZ_ELF_BOUNDS;
        if (vaddr < USER_MIN || vaddr >= USER_LIMIT ||
            memory_size > USER_LIMIT - vaddr)
            return RYZ_ELF_BOUNDS;
        end = vaddr + memory_size;
        if (end > USER_LIMIT || end > UINT64_MAX - (RYZ_ELF64_PAGE_SIZE - 1))
            return RYZ_ELF_BOUNDS;
        start = vaddr & ~(RYZ_ELF64_PAGE_SIZE - 1);
        map_end = (end + RYZ_ELF64_PAGE_SIZE - 1) &
                  ~(RYZ_ELF64_PAGE_SIZE - 1);
        if (start < USER_MIN || map_end > USER_LIMIT || start >= map_end ||
            map_end - start > RYZ_ELF64_MAX_MAPPED ||
            sum > RYZ_ELF64_MAX_MAPPED - (map_end - start))
            return RYZ_ELF_POLICY;
        for (j = 0; j < plan.load_count; ++j) {
            if (overlapping(start, map_end, plan.loads[j].map_start,
                            plan.loads[j].map_end))
                return RYZ_ELF_POLICY;
        }

        seg = &plan.loads[plan.load_count++];
        seg->file_offset = offset;
        seg->file_bytes = file_size;
        seg->address = vaddr;
        seg->memory_bytes = memory_size;
        seg->map_start = start;
        seg->map_end = map_end;
        seg->flags = flags;
        sum += map_end - start;

        /* Entrypoint must be executable bytes in the input, not zero-fill. */
        if ((flags & PF_X) && entry >= vaddr &&
            entry - vaddr < file_size)
            has_entry = 1;
    }

    if (plan.load_count == 0 || !has_entry)
        return RYZ_ELF_NO_ENTRY;
    plan.mapped_bytes = sum;
    *out = plan;
    return RYZ_ELF_OK;
}

int ryz_elf64_materialize(const unsigned char *image, size_t image_length,
                          const RyzElf64Segment *segment,
                          unsigned char *destination, size_t capacity)
{
    if (image == NULL || segment == NULL || destination == NULL)
        return RYZ_ELF_BAD_ARG;
    if (segment->file_bytes > segment->memory_bytes ||
        segment->memory_bytes > RYZ_ELF64_MAX_MAPPED ||
        segment->memory_bytes > (uint64_t)capacity ||
        segment->memory_bytes > SIZE_MAX ||
        segment->file_bytes > SIZE_MAX ||
        !span(image_length, segment->file_offset, segment->file_bytes))
        return RYZ_ELF_BOUNDS;
    memset(destination, 0, (size_t)segment->memory_bytes);
    memcpy(destination, image + (size_t)segment->file_offset,
           (size_t)segment->file_bytes);
    return RYZ_ELF_OK;
}
const char *ryz_elf64_error(int error)
{
    switch (error) {
    case RYZ_ELF_OK: return "ok";
    case RYZ_ELF_BAD_ARG: return "invalid-argument";
    case RYZ_ELF_BAD_HEADER: return "invalid-elf-header";
    case RYZ_ELF_UNSUPPORTED: return "unsupported-elf-feature";
    case RYZ_ELF_BOUNDS: return "out-of-bounds";
    case RYZ_ELF_POLICY: return "unsafe-memory-layout";
    case RYZ_ELF_NO_ENTRY: return "missing-executable-entry";
    default: return "unknown-error";
    }
}
