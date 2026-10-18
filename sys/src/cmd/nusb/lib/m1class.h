/* SPDX-License-Identifier: AGPL-3.0-only */
/*
 * M1 reusable USB class transport boundary checks.
 * No device IDs or automatic binding rules are introduced.
 */
#ifndef RYZOVA_M1_USB_CLASS_H
#define RYZOVA_M1_USB_CLASS_H

int m1usbdevdescvalid(const unsigned char *buf, unsigned long n);
int m1uac1freqvalid(const unsigned char *body, unsigned long desclen);
int m1diskcapacityvalid(unsigned long long lastlba, unsigned long blocksize);
int m1cdcmacvalid(const char *mac, unsigned long len);
int m1hidpacketvalid(unsigned long packet, unsigned long limit);

#endif
