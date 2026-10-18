/* SPDX-License-Identifier: AGPL-3.0-only */
#include "m1class.h"

/*
 * Ryzova retains the 17-byte descriptor exception for legacy hubs in
 * nusb/lib/dev.c, but rejects a truncated packet-size/type field.
 */
int
m1usbdevdescvalid(const unsigned char *b, unsigned long n)
{
	unsigned int bcd, packet;

	if(b == 0 || n < 17 || b[0] < 17 || b[1] != 1)
		return 0;
	bcd = b[2] | b[3]<<8;
	packet = b[7];
	if(bcd >= 0x0300)
		return packet == 9;	/* SuperSpeed EP0 encodes 2^9 = 512 */
	return packet == 8 || packet == 16 || packet == 32 || packet == 64;
}

/* body starts at the class-specific descriptor subtype, after length/type. */
int
m1uac1freqvalid(const unsigned char *b, unsigned long len)
{
	unsigned long count;

	if(b == 0 || len < 8 || b[0] != 2 || b[1] != 1)
		return 0;
	count = b[5];
	if(count == 0)
		return len >= 14;	/* continuous: two 24-bit bounds */
	return count <= (len - 8)/3;
}

/* Returns false before (lastlba+1)*blocksize can wrap signed 64-bit. */
int
m1diskcapacityvalid(unsigned long long lastlba, unsigned long blocksize)
{
	unsigned long long blocks;

	if(blocksize == 0 || blocksize > 65536 ||
	   (blocksize & (blocksize-1)) != 0 ||
	   lastlba == ~0ULL)
		return 0;
	blocks = lastlba + 1;
	return blocks <= 0x7fffffffffffffffULL / blocksize;
}

int
m1cdcmacvalid(const char *mac)
{
	int i;
	unsigned char c;

	if(mac == 0)
		return 0;
	for(i = 0; i < 12; i++){
		c = mac[i];
		if(!((c >= '0' && c <= '9') ||
		     (c >= 'a' && c <= 'f') ||
		     (c >= 'A' && c <= 'F')))
			return 0;
	}
	return mac[12] == 0;
}

int
m1hidpacketvalid(unsigned long packet, unsigned long limit)
{
	return packet > 0 && packet <= limit;
}
