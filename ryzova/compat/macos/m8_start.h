/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef MAC_M8_START_H
#define MAC_M8_START_H

typedef struct Mac8Stop Mac8Stop;
struct Mac8Stop {
    unsigned long long pc, last_pc, arg0, arg1;
    unsigned int steps, name;
};

/* Start the pinned --version profile and stop at an unresolved import.
 * The caller supplies separate immutable image, arena and receipt storage. */
int mac8_start(const unsigned char *, unsigned int, unsigned char *,
               unsigned int, Mac8Stop *);

#endif
