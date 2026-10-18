/* SPDX-License-Identifier: AGPL-3.0-only */
/* M0.3 portable driver-family matcher; prototype only, NOT kernel-linked. */
#ifndef RYZOVA_DRVMATCH_H
#define RYZOVA_DRVMATCH_H

enum {
	RzbusPci = 1,
	RzbusUsb = 2,
	RzruleExact = 1,
	RzruleClass = 2,
	RzruleClassProtocol = 3,

	RzmatchUnknown = -1,
	RzmatchAmbiguous = -2,
	RzmatchInvalid = -3,
};

typedef struct Rzdevkey Rzdevkey;
typedef struct Rzdrvrule Rzdrvrule;

struct Rzdevkey {
	unsigned int bus;
	unsigned int vendor;
	unsigned int device;
	unsigned int classcode;
	unsigned int subclass;
	unsigned int protocol;
	unsigned int revision;
};

struct Rzdrvrule {
	unsigned int bus;
	unsigned int kind;
	unsigned int vendor;
	unsigned int device;
	unsigned int classcode;
	unsigned int subclass;
	unsigned int protocol;
	unsigned int firstrevision;
	unsigned int lastrevision;
	/* Rule index identifies a review candidate, not an attached driver. */
};

int rzdrvmatch(const Rzdevkey *observed, const Rzdrvrule *rules, unsigned long count);

#endif
