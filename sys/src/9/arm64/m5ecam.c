/* SPDX-License-Identifier: AGPL-3.0-only */
#include "m5ecam.h"

/*
 * PCIe ECAM is one MiB per bus, 32 devices, 8 functions and 4 KiB
 * per function. QEMU's mapped window on this target is only 16 MiB.
 * Reject out-of-window requests without pointer arithmetic.
 */
int
m5ecamoffset(unsigned int bus, unsigned int dev, unsigned int fn,
	int reg, unsigned int width, unsigned long window, unsigned long *off)
{
	unsigned long address;

	if(off == 0 || dev >= 32 || fn >= 8 ||
	   (width != 1 && width != 2 && width != 4) ||
	   reg < 0 || reg > 4096-(int)width ||
	   (reg & (width-1)) != 0 || bus >= 256)
		return -1;
	address = ((unsigned long)bus << 20) |
		  ((unsigned long)dev << 15) |
		  ((unsigned long)fn << 12) | (unsigned long)reg;
	if(address >= window || window - address < width)
		return -1;
	*off = address;
	return 0;
}
