/* SPDX-License-Identifier: AGPL-3.0-only */
/* Host-only test probe: NEVER transfers control to ELF entry. */
#include "elf64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_IMAGE (16U * 1024U * 1024U)
int main(int argc, char **argv)
{
    FILE *fp;
    unsigned char *image;
    long n;
    size_t length;
    unsigned int i;
    int result, copy = 0;
    RyzElf64Plan plan;

    if (argc < 2 || argc > 3 ||
        (argc == 3 && strcmp(argv[2], "--materialize") != 0)) {
        fprintf(stderr, "usage: %s file [--materialize]\n", argv[0]);
        return 64;
    }
    copy = argc == 3;
    fp = fopen(argv[1], "rb");
    if (fp == NULL || fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "cannot-open-input\n");
        if (fp != NULL) fclose(fp);
        return 65;
    }
    n = ftell(fp);
    if (n < 0 || (unsigned long)n > MAX_IMAGE ||
        fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        fprintf(stderr, "input-size-not-supported\n");
        return 65;
    }
    length = (size_t)n;
    image = (unsigned char *)malloc(length == 0 ? 1 : length);
    if (image == NULL || fread(image, 1, length, fp) != length) {
        fclose(fp);
        free(image);
        fprintf(stderr, "read-failed\n");
        return 65;
    }
    fclose(fp);
    result = ryz_elf64_plan(image, length, &plan);
    if (result != RYZ_ELF_OK) {
        printf("{\"status\":\"rejected\",\"reason\":\"%s\"}\n", ryz_elf64_error(result));
        free(image);
        return 2;
    }
    if (copy) {
        for (i = 0; i < plan.load_count; ++i) {
            const RyzElf64Segment *seg = &plan.loads[i];
            unsigned char *dst = (unsigned char *)malloc((size_t)seg->memory_bytes);
            if (dst == NULL) {
                free(image);
                return 70;
            }
            result = ryz_elf64_materialize(image, length, seg, dst,
                                            (size_t)seg->memory_bytes);
            if (result == RYZ_ELF_OK &&
                memcmp(dst, image + seg->file_offset,
                       (size_t)seg->file_bytes) != 0)
                result = RYZ_ELF_POLICY;
            if (result == RYZ_ELF_OK) {
                size_t j;
                for (j = (size_t)seg->file_bytes; j < (size_t)seg->memory_bytes; ++j)
                    if (dst[j] != 0) { result = RYZ_ELF_POLICY; break; }
            }
            free(dst);
            if (result != RYZ_ELF_OK) {
                free(image);
                fprintf(stderr, "materialization-check-failed\n");
                return 70;
            }
        }
    }
    printf("{\"status\":\"ok\",\"segment_count\":%u,\"entry\":%llu,"
           "\"mapped_bytes\":%llu,\"materialized\":%s}\n",
           plan.load_count, (unsigned long long)plan.entry,
           (unsigned long long)plan.mapped_bytes, copy ? "true" : "false");
    free(image);
    return 0;
}
