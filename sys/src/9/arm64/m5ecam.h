/* SPDX-License-Identifier: AGPL-3.0-only */
/*
 * M5: bounded ARM64 QEMU PCI ECAM offset calculation.
 * Pure arithmetic only. No PCI attach, MMIO, DMA or IRQ operation.
 */
#ifndef RYZOVA_M5_ECAM_H
#define RYZOVA_M5_ECAM_H

int m5ecamoffset(unsigned int bus, unsigned int dev, unsigned int fn,
	int reg, unsigned int width, unsigned long window, unsigned long *off);

#endif
