/* SPDX-License-Identifier: AGPL-3.0-only */
#include <assert.h>
#include "../sys/src/9/port/ryzovadrvmatch.h"

int
main(void)
{
	const Rzdevkey pci = {RzbusPci, 0x8086, 0x15f3, 2, 0, 0, 3};
	const Rzdevkey nvme = {RzbusPci, 0x1234, 0xabcd, 1, 8, 2, 0};
	const Rzdevkey unknown = {RzbusUsb, 1, 2, 255, 255, 255, 1};
	const Rzdrvrule rules[] = {
		{RzbusPci, RzruleClass, 0, 0, 2, 0, 0, 0, 255},
		{RzbusPci, RzruleExact, 0x8086, 0x15f3, 0, 0, 0, 0, 255},
		{RzbusPci, RzruleClassProtocol, 0, 0, 1, 8, 2, 0, 255},
	};
	Rzdrvrule bad[] = {{RzbusPci, RzruleExact, 0x8086, 0x15f3, 0, 0, 0, 0, 255},
	                  {RzbusPci, RzruleExact, 0x8086, 0x15f3, 0, 0, 0, 0, 255}};
	Rzdevkey broken = pci;
	assert(rzdrvmatch(&pci, rules, 3) == 1);
	assert(rzdrvmatch(&nvme, rules, 3) == 2);
	assert(rzdrvmatch(&unknown, rules, 3) == RzmatchUnknown);
	assert(rzdrvmatch(&pci, bad, 2) == RzmatchAmbiguous);
	assert(rzdrvmatch(0, rules, 3) == RzmatchInvalid);
	assert(rzdrvmatch(&pci, 0, 1) == RzmatchInvalid);
	assert(rzdrvmatch(&pci, 0, 0) == RzmatchUnknown);
	broken.revision = 256;
	assert(rzdrvmatch(&broken, rules, 3) == RzmatchInvalid);
	broken = pci;
	bad[0].kind = 0;
	assert(rzdrvmatch(&broken, bad, 2) == RzmatchInvalid);
	return 0;
}
