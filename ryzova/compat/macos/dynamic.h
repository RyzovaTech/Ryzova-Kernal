/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef MAC_DYNAMIC_H
#define MAC_DYNAMIC_H

enum { MacPage = 4096, MacArmPage = 16384, MacImageLimit = 3*MacArmPage, MacBase = 0x200000, MacWriteThunk = 0x10000 };
enum { MacWrite, MacOpen, MacRead, MacClose, MacImports };
typedef struct MacDynamic MacDynamic;
struct MacDynamic {
    unsigned int entry;
    unsigned int write_slot;
    unsigned int slots[MacImports];
    unsigned int bound;
    unsigned int rebases;
};

int mac_dynamic_load(const unsigned char *, unsigned int, unsigned char *,
                     unsigned char *, MacDynamic *, int, int);
#endif
