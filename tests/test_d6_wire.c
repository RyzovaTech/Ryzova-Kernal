/* SPDX-License-Identifier: AGPL-3.0-only */
#include <assert.h>
#include <string.h>
#include "../sys/src/cmd/nusb/bt/hciwire.h"
#include "../sys/src/9/port/virtgpuwire.h"

int
main(void)
{
	unsigned char p[257] = {0};
	unsigned char out[64];
	unsigned int i;

	assert(!bthcieventvalid(0, 0));
	assert(!bthcieventvalid(p, 0));
	p[0] = 0x0e; p[1] = 0;
	assert(bthcieventvalid(p, 2));
	assert(!bthcieventvalid(p, 3));
	p[1] = 255;
	assert(!bthcieventvalid(p, 256));
	assert(bthcieventvalid(p, 257));
	assert(!bthcieventvalid(p, 258));
	assert(bthcireset(0, 3) == -1);
	assert(bthcireset(out, 2) == -1);
	assert(bthcireset(out, 3) == 3);
	assert(out[0] == 3 && out[1] == 0x0c && out[2] == 0);

	assert(vgpudisplayinfo(0, 24) == -1);
	assert(vgpudisplayinfo(out, 23) == -1);
	memset(out, 0xff, sizeof out);
	assert(vgpudisplayinfo(out, sizeof out) == VgpuHdrLen);
	assert(out[0] == 0 && out[1] == 1);
	for(i = 2; i < VgpuHdrLen; i++)
		assert(out[i] == 0);
	assert(vgpucreate2d(out, 39, 1, VgpuFmtB8G8R8X8, 800, 600) == -1);
	assert(vgpucreate2d(out, sizeof out, 0, VgpuFmtB8G8R8X8, 800, 600) == -1);
	assert(vgpucreate2d(out, sizeof out, 1, VgpuFmtB8G8R8X8, 0, 600) == -1);
	assert(vgpucreate2d(out, sizeof out, 1, VgpuFmtB8G8R8X8, 8193, 600) == -1);
	assert(vgpucreate2d(out, sizeof out, 1, 99, 800, 600) == -1);
	assert(vgpucreate2d(out, sizeof out, 7, VgpuFmtB8G8R8X8, 800, 600) == 40);
	assert(out[0] == 1 && out[1] == 1);
	assert(out[24] == 7 && out[28] == 2);
	assert(out[32] == 0x20 && out[33] == 3);
	assert(out[36] == 0x58 && out[37] == 2);
	return 0;
}
