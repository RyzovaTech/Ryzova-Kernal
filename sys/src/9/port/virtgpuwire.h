/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZOVA_VIRTGPUWIRE_H
#define RYZOVA_VIRTGPUWIRE_H

enum {
	VgpuHdrLen = 24,
	VgpuCreate2DLen = 40,
	VgpuCmdGetDisplay = 0x0100,
	VgpuCmdCreate2D = 0x0101,
	VgpuFmtB8G8R8X8 = 2,
	VgpuMaxPrototypeDimension = 8192,
};

/* Original wire-format builders only, not yet linked into an AMD64 kernel. */
int vgpudisplayinfo(unsigned char *out, unsigned long cap);
int vgpucreate2d(unsigned char *out, unsigned long cap,
	unsigned int id, unsigned int fmt, unsigned int width, unsigned int height);

#endif
