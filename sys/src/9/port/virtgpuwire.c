/* SPDX-License-Identifier: AGPL-3.0-only */
#include "virtgpuwire.h"

static void
put32(unsigned char *p, unsigned int v)
{
	p[0] = v;
	p[1] = v >> 8;
	p[2] = v >> 16;
	p[3] = v >> 24;
}

static void
clearbytes(unsigned char *p, unsigned long n)
{
	unsigned long i;

	for(i = 0; i < n; i++)
		p[i] = 0;
}

int
vgpudisplayinfo(unsigned char *out, unsigned long cap)
{
	if(out == 0 || cap < VgpuHdrLen)
		return -1;
	clearbytes(out, VgpuHdrLen);
	put32(out, VgpuCmdGetDisplay);
	return VgpuHdrLen;
}

int
vgpucreate2d(unsigned char *out, unsigned long cap,
	unsigned int id, unsigned int fmt, unsigned int width, unsigned int height)
{
	if(out == 0 || cap < VgpuCreate2DLen || id == 0 ||
	   width == 0 || height == 0 ||
	   width > VgpuMaxPrototypeDimension ||
	   height > VgpuMaxPrototypeDimension)
		return -1;
	if(fmt != VgpuFmtB8G8R8X8)
		return -1;
	clearbytes(out, VgpuCreate2DLen);
	put32(out, VgpuCmdCreate2D);
	put32(out+24, id);
	put32(out+28, fmt);
	put32(out+32, width);
	put32(out+36, height);
	return VgpuCreate2DLen;
}
