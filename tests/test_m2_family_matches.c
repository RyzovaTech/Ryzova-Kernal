/* SPDX-License-Identifier: AGPL-3.0-only */
/* M2 exact source candidates, NOT a physical hardware certification test. */
#include <assert.h>
#include <string.h>
#include "../sys/src/9/port/ryzovadrvmatch.h"
#include "../sys/src/9/port/ryzovapcirules.h"

typedef struct M2case M2case;
struct M2case {
	unsigned int vendor, device, classcode, subclass, protocol;
	const char *rule;
};

int
main(void)
{
	static const M2case cases[] = {
		{0x8086, 0x100e, 2, 0, 0, "m2-intel-e1000-82540em-candidate"},
		{0x8086, 0x15c8, 2, 0, 0, "m2-intel-x550-15c8-candidate"},
		{0x10ec, 0x8139, 2, 0, 0, "m2-realtek-rtl8139-candidate"},
		{0x10ec, 0x8168, 2, 0, 0, "m2-realtek-rtl8168-candidate"},
		{0x10ec, 0x8169, 2, 0, 0, "m2-realtek-rtl8169-candidate"},
		{0x1022, 0x2000, 2, 0, 0, "m2-amd-pcnet-2000-candidate"},
		{0x8086, 0x27d8, 4, 3, 0, "m2-intel-hda-ich7-candidate"},
		{0x8086, 0xa0c8, 4, 3, 0, "m2-intel-hda-tigerlake-candidate"},
		{0x1022, 0x1487, 4, 3, 0, "m2-amd-hda-matisse-candidate"},
		{0x1022, 0x15e3, 4, 3, 0, "m2-amd-hda-raven-candidate"},
		{0x8086, 0x4222, 2, 0x80, 0, "m2-intel-wpi-4222-candidate"},
		{0x8086, 0x4227, 2, 0x80, 0, "m2-intel-wpi-4227-candidate"},
	};
	const unsigned long n = sizeof(rzpcirules)/sizeof(rzpcirules[0]);
	unsigned long i, rev;
	int index;
	Rzdevkey key;
	Rzdrvrule two[2];

	assert(n == sizeof(rzpciruleids)/sizeof(rzpciruleids[0]));
	for(i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i){
		for(rev=0; rev<256; ++rev){
			memset(&key, 0, sizeof(key));
			key.bus = RzbusPci;
			key.vendor = cases[i].vendor;
			key.device = cases[i].device;
			key.classcode = cases[i].classcode;
			key.subclass = cases[i].subclass;
			key.protocol = cases[i].protocol;
			key.revision = rev;
			index = rzdrvmatch(&key, rzpcirules, n);
			assert(index >= 0);
			assert(strcmp(rzpciruleids[index], cases[i].rule) == 0);
		}
	}
	memset(&key, 0, sizeof(key));
	key.bus = RzbusPci;
	key.vendor = 0xffff; key.device = 0xffff;
	key.classcode = 2; key.subclass = 0;
	assert(rzdrvmatch(&key, rzpcirules, n) == RzmatchUnknown);
	key.classcode = 4; key.subclass = 3;
	index = rzdrvmatch(&key, rzpcirules, n);
	assert(index >= 0);
	assert(strcmp(rzpciruleids[index], "pci-hda-class-candidate") == 0);
	key.revision = 256;
	assert(rzdrvmatch(&key, rzpcirules, n) == RzmatchInvalid);
	key.revision = 0;
	two[0] = rzpcirules[0];
	two[1] = two[0];
	/* A clash must fail closed even when classes are broad. */
	key.classcode = 1; key.subclass = 8; key.protocol = 2;
	assert(rzdrvmatch(&key, two, 2) == RzmatchAmbiguous);
	return 0;
}
