/* SPDX-License-Identifier: AGPL-3.0-only */
#include "ryzovadrvmatch.h"

/*
 * Side-effect-free family candidate selection. Never touches hardware,
 * allocates DMA, enables IRQs, or binds a driver. This file is unlinked.
 */
int
rzdrvmatch(const Rzdevkey *d, const Rzdrvrule *rules, unsigned long count)
{
	unsigned int maxrev;
	unsigned long i;
	int chosen, best, score;

	if(d == 0 || (rules == 0 && count != 0))
		return RzmatchInvalid;
	if(d->bus != RzbusPci && d->bus != RzbusUsb)
		return RzmatchInvalid;
	maxrev = d->bus == RzbusPci ? 255U : 65535U;
	if(d->vendor > 65535U || d->device > 65535U ||
	   d->classcode > 255U || d->subclass > 255U ||
	   d->protocol > 255U || d->revision > maxrev)
		return RzmatchInvalid;
	chosen = RzmatchUnknown;
	best = 0;
	for(i=0; i<count; i++){
		const Rzdrvrule *r = &rules[i];
		if((r->bus != RzbusPci && r->bus != RzbusUsb) ||
		   r->firstrevision > r->lastrevision ||
		   r->lastrevision > (r->bus == RzbusPci ? 255U : 65535U) ||
		   r->vendor > 65535U ||
		   r->device > 65535U || r->classcode > 255U ||
		   r->subclass > 255U || r->protocol > 255U ||
		   r->kind < RzruleExact || r->kind > RzruleClassProtocol)
			return RzmatchInvalid;
		/* Rules for other buses are valid, but cannot match this device. */
		if(r->bus != d->bus || d->revision < r->firstrevision ||
		   d->revision > r->lastrevision)
			continue;
		score = 0;
		if(r->kind == RzruleExact && r->vendor == d->vendor &&
		   r->device == d->device)
			score = 3;
		else if(r->kind == RzruleClassProtocol &&
			r->classcode == d->classcode && r->subclass == d->subclass &&
			r->protocol == d->protocol)
			score = 2;
		else if(r->kind == RzruleClass && r->classcode == d->classcode &&
			r->subclass == d->subclass)
			score = 1;
		if(score == 0)
			continue;
		if(score > best){
			best = score;
			chosen = (int)i;
		}else if(score == best)
			chosen = RzmatchAmbiguous;
	}
	return chosen;
}
