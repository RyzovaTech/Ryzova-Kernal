/* SPDX-License-Identifier: AGPL-3.0-only */
#include "hciwire.h"

int
bthcieventvalid(const unsigned char *packet, unsigned long n)
{
	if(packet == 0 || n < 2 || n > BthciEventMax)
		return 0;
	return n == (unsigned long)packet[1] + 2;
}

int
bthcireset(unsigned char *buf, unsigned long cap)
{
	if(buf == 0 || cap < 3)
		return -1;
	buf[0] = 0x03;
	buf[1] = 0x0c;
	buf[2] = 0;
	return 3;
}
