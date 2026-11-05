/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef MAC_DYNAMIC_H
#define MAC_DYNAMIC_H

enum { MacPage = 4096, MacImageLimit = 3*MacPage, MacBase = 0x200000, MacWriteThunk = 0x10000 };
typedef struct MacDynamic MacDynamic;
struct MacDynamic {
    unsigned int entry;
    unsigned int write_slot;
    unsigned int rebases;
};

int mac_dynamic_load(const unsigned char *, unsigned int, unsigned char *,
                     unsigned char *, MacDynamic *);
#endif
