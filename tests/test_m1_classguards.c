/* SPDX-License-Identifier: AGPL-3.0-only */
#include <assert.h>
#include <string.h>
#include "../sys/src/cmd/nusb/lib/m1class.h"

int
main(void)
{
	unsigned char dev[18] = {18,1,0x00,0x02,0,0,0,8};
	unsigned char audio[32] = {2,1,0,2,16,0};
	unsigned long long edge;

	assert(m1usbdevdescvalid(dev, 18));
	assert(m1usbdevdescvalid(dev, 17)); /* legacy short hub */
	assert(!m1usbdevdescvalid(dev, 16));
	assert(!m1usbdevdescvalid(0, 18));
	dev[7] = 0; assert(!m1usbdevdescvalid(dev, 18));
	dev[7] = 64; assert(m1usbdevdescvalid(dev, 18));
	dev[1] = 2; assert(!m1usbdevdescvalid(dev, 18));
	dev[1] = 1;
	dev[2] = 0; dev[3] = 3; dev[7] = 9;
	assert(m1usbdevdescvalid(dev, 18));
	dev[7] = 64; assert(!m1usbdevdescvalid(dev, 18));

	assert(!m1uac1freqvalid(0, 14));
	assert(!m1uac1freqvalid(audio, 13));
	assert(m1uac1freqvalid(audio, 14)); /* continuous: 2x24-bit */
	audio[5] = 2;
	assert(!m1uac1freqvalid(audio, 13));
	assert(m1uac1freqvalid(audio, 14));
	audio[5] = 255;
	assert(!m1uac1freqvalid(audio, 14));
	audio[5] = 1;
	assert(m1uac1freqvalid(audio, 11));
	audio[0] = 3; assert(!m1uac1freqvalid(audio, 11));

	assert(m1diskcapacityvalid(0ULL, 512UL));
	assert(m1diskcapacityvalid(4095ULL, 4096UL));
	assert(!m1diskcapacityvalid(4095ULL, 0UL));
	assert(!m1diskcapacityvalid(4095ULL, 520UL));
	assert(!m1diskcapacityvalid(1ULL, 131072UL));
	assert(!m1diskcapacityvalid(~0ULL, 512UL));
	edge = 0x7fffffffffffffffULL / 512ULL;
	assert(m1diskcapacityvalid(edge - 1ULL, 512UL));
	assert(!m1diskcapacityvalid(edge, 512UL));

	assert(m1cdcmacvalid("001122aAbBcC", 12));
	assert(!m1cdcmacvalid("001122aAbBcG", 12));
	assert(!m1cdcmacvalid("123", 3));
	assert(!m1cdcmacvalid(0, 12));
	assert(!m1cdcmacvalid("001122aAbBcC", 13));

	assert(!m1hidpacketvalid(0, 64));
	assert(m1hidpacketvalid(8, 64));
	assert(m1hidpacketvalid(64, 64));
	assert(!m1hidpacketvalid(65, 64));
	assert(!m1hidpacketvalid(1, 0));
	return 0;
}
