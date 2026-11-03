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
#endif
