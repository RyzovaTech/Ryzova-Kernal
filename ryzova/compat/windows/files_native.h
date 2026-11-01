/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef CW_FILES_NATIVE_H
#define CW_FILES_NATIVE_H
#include "files.h"
typedef struct CwFileNative CwFileNative;
/* Caller owns a private namespace; root is an explicit trusted capability.
   syncfd, if present, must belong to the owning hjfs control service. */
CwFileNative *cw_file_native_new(const char *,int);
void cw_file_native_destroy(CwFileNative *);
const CwFileOps *cw_file_native_ops(void);
uint32_t cw_file_native_open_count(CwFileNative *);
uint32_t cw_file_native_peak_count(CwFileNative *);
#endif
