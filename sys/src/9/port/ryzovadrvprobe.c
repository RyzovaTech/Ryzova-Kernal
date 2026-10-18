/* SPDX-License-Identifier: AGPL-3.0-only */
/*
 * M0 native AMD64 PCI candidate observation interface:
 *    #P/drivercandidates
 *
 * This does NOT bind devices, reset chips, touch BARs, load firmware,
 * enable DMA/IRQs or claim that any device works.
 *
 * The rule table is generated from reviewed source-candidate metadata.
 * The existing 9front-derived probe/attach order is unchanged.
 */
#include "u.h"
#include "../port/lib.h"
#include "mem.h"
#include "dat.h"
#include "fns.h"
#include "../port/pci.h"
#include "../port/ryzovadrvmatch.h"
#include "../port/ryzovapcirules.h"

enum {
	Rzscanlimit = 512,
	Rzshowlimit = 24,
	Rzreportlen = 4096,
};

static long
rzpciread(Chan*, void *va, long n, vlong off)
{
	Pcidev *p;
	Rzdevkey key;
	char report[Rzreportlen];
	int used, count, candidates, ambiguous, shown, truncated, rule;

	used = snprint(report, sizeof(report),
		"# Ryzova M0 PCI source candidates; not driver-bound or hardware-verified\n");
	count = candidates = ambiguous = shown = truncated = 0;
	for(p = nil; (p = pcimatch(p, 0, 0)) != nil; ){
		if(count >= Rzscanlimit){
			truncated = 1;
			break;
		}
		count++;
		memset(&key, 0, sizeof(key));
		key.bus = RzbusPci;
		key.vendor = p->vid;
		key.device = p->did;
		key.classcode = p->ccrb;
		key.subclass = p->ccru;
		key.protocol = p->ccrp;
		key.revision = p->rid;
		rule = rzdrvmatch(&key, rzpcirules, nelem(rzpcirules));
		if(rule >= 0){
			candidates++;
			if(shown < Rzshowlimit && used < Rzreportlen-160){
				used += snprint(report+used, sizeof(report)-used,
					"%T %.4ux:%.4ux class %.2ux:%.2ux:%.2ux rev %.2ux candidate=%s verified=no\n",
					p->tbdf, p->vid, p->did, p->ccrb, p->ccru,
					p->ccrp, p->rid, rzpciruleids[rule]);
				shown++;
			}
		}else if(rule == RzmatchAmbiguous || rule == RzmatchInvalid)
			ambiguous++;
	}
	if(used < Rzreportlen-160)
		snprint(report+used, sizeof(report)-used,
			"pci-observed=%d candidates=%d ambiguous-or-invalid=%d reported=%d capped=%d auto-bind=no\n",
			count, candidates, ambiguous, shown, truncated || shown < candidates);
	return readstr(off, va, n, report);
}

void
ryzovadrvprobeinit(void)
{
	/*
	 * Registration is cheap and read-only. Enumeration happens only
	 * when the diagnostic is read; no new probe is run during boot.
	 */
	if(addarchfile("drivercandidates", 0444, rzpciread, nil) == nil)
		print("ryzova: M0 read-only PCI candidate file unavailable\n");
}
