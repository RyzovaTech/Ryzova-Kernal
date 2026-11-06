/* SPDX-License-Identifier: AGPL-3.0-only */
#include <assert.h>
#include "../sys/src/9/arm64/m5ecam.h"

int
main(void)
{
	unsigned long off=0xdeadbeefUL, x;
	unsigned int bus, dev, fn;
	assert(m5ecamoffset(0, 0, 0, 0, 4, 0x1000000UL, &off)==0 && off==0);
	assert(m5ecamoffset(15,31,7,4092,4,0x1000000UL,&off)==0 &&
	       off==0xfffffcUL);
	assert(m5ecamoffset(15,31,7,4095,1,0x1000000UL,&off)==0 &&
	       off==0xffffffUL);
	assert(m5ecamoffset(16,0,0,0,4,0x1000000UL,&off)<0);
	assert(m5ecamoffset(255,31,7,4092,4,0x1000000UL,&off)<0);
	assert(m5ecamoffset(0,32,0,0,4,0x1000000UL,&off)<0);
	assert(m5ecamoffset(0,0,8,0,4,0x1000000UL,&off)<0);
	assert(m5ecamoffset(0,0,0,-1,4,0x1000000UL,&off)<0);
	assert(m5ecamoffset(0,0,0,4096,1,0x1000000UL,&off)<0);
	assert(m5ecamoffset(0,0,0,4095,4,0x1000000UL,&off)<0);
	assert(m5ecamoffset(0,0,0,3,4,0x1000000UL,&off)<0);
	assert(m5ecamoffset(0,0,0,3,2,0x1000000UL,&off)<0);
	assert(m5ecamoffset(0,0,0,0,0,0x1000000UL,&off)<0);
	assert(m5ecamoffset(0,0,0,0,8,0x1000000UL,&off)<0);
	assert(m5ecamoffset(0,0,0,0,1,0,&off)<0);
	assert(m5ecamoffset(0,0,0,0,1,0x1000000UL,0)<0);

	/* All BDF combinations within a 16-bus window remain unique. */
	for(bus=0;bus<16;bus++)
	for(dev=0;dev<32;dev++)
	for(fn=0;fn<8;fn++){
		assert(m5ecamoffset(bus,dev,fn,4092,4,0x1000000UL,&off)==0);
		x=((unsigned long)bus<<20)|((unsigned long)dev<<15)|
		  ((unsigned long)fn<<12)|4092UL;
		assert(off==x);
	}
	/* Invalid requests never overwrite the old caller-provided offset. */
	off=0xdeadbeefUL;
	assert(m5ecamoffset(16,0,0,0,4,0x1000000UL,&off)<0 &&
	       off==0xdeadbeefUL);
	return 0;
}
