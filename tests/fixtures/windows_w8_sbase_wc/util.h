/* SPDX-License-Identifier: AGPL-3.0-only
 * Only the declarations used by unmodified sbase wc.c. This is NOT the
 * full upstream util.h implementation. The original MIT source is under
 * upstream/ alongside the unabridged license notice.
 */
#ifndef CW_W8_SBASE_HOST_SHIM_H
#define CW_W8_SBASE_HOST_SHIM_H
#include <stdio.h>
#include <stdlib.h>
#include "upstream/arg.h"
extern char *argv0;
void eprintf(const char *,...);
void weprintf(const char *,...);
int fshut(FILE *,const char *);
/* Opt-in Windows guest-target candidate: the original upstream wc.c stays
 * byte-for-byte untouched. Replace only the libc *surface* it consumes with
 * a finite, independently implemented Win32 adapter. No dynamic CRT. */
#ifdef CW_W8_MINCRT
FILE *cw_w8_stdin(void);
FILE *cw_w8_stdout(void);
FILE *cw_w8_stderr(void);
FILE *cw_w8_fopen(const char *,const char *);
int cw_w8_printf(const char *,...);
int cw_w8_putchar(int);
int cw_w8_strcmp(const char *,const char *);
#undef stdin
#undef stdout
#undef stderr
#define stdin cw_w8_stdin()
#define stdout cw_w8_stdout()
#define stderr cw_w8_stderr()
#define fopen cw_w8_fopen
#define printf cw_w8_printf
#define putchar cw_w8_putchar
#define strcmp cw_w8_strcmp
#endif
#endif
