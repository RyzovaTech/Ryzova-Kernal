/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZ_WINDOWS_FILES_HOST_H
#define RYZ_WINDOWS_FILES_HOST_H
#include "files.h"
typedef struct CwFileHost CwFileHost;
/* Hosted Linux adapter only; native Flex resource transport is separate W6 work. */
CwFileHost *cw_file_host_new(void);
int cw_file_host_add_root(CwFileHost *,int); /* duplicates an already authorized directory fd */
void cw_file_host_destroy(CwFileHost *);
const CwFileOps *cw_file_host_ops(void);
uint32_t cw_file_host_open_count(const CwFileHost *);
#endif
