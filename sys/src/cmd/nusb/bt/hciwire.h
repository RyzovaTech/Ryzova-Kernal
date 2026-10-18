/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZOVA_NUSB_BT_HCIWIRE_H
#define RYZOVA_NUSB_BT_HCIWIRE_H

enum { BthciEventMax = 257 };

/* One complete HCI event: 2-byte header followed by 0..255 payload bytes. */
int bthcieventvalid(const unsigned char *packet, unsigned long n);
/* Build HCI_Reset opcode 0x0c03; only used by explicit -r. */
int bthcireset(unsigned char *buf, unsigned long cap);

#endif
