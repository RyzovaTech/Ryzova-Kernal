/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 Ryzova contributors.
 *
 * Ryzova-specific, read-only Plan 9 device interface. This source was
 * independently authored for Ryzova and is not an upstream 9front driver.
 */
#include "u.h"
#include "../port/lib.h"
#include "mem.h"
#include "dat.h"
#include "fns.h"
#include "../port/error.h"

enum {
	Qdir,
	Qversion,
	Qfoundation,
	Qabi,
};

static Dirtab ryzovadir[] = {
	{".",		{Qdir, 0, QTDIR},	0,	DMDIR|0555},
	{"version",	{Qversion, 0, 0},	0,	0444},
	{"foundation",	{Qfoundation, 0, 0},	0,	0444},
	{"abi",		{Qabi, 0, 0},		0,	0444},
};

static Chan*
ryzovaattach(char *spec)
{
	return devattach('Z', spec);
}

static Walkqid*
ryzovawalk(Chan *c, Chan *nc, char **name, int nname)
{
	return devwalk(c, nc, name, nname, ryzovadir, nelem(ryzovadir), devgen);
}

static int
ryzovastat(Chan *c, uchar *db, int n)
{
	return devstat(c, db, n, ryzovadir, nelem(ryzovadir), devgen);
}

static Chan*
ryzovaopen(Chan *c, int omode)
{
	return devopen(c, omode, ryzovadir, nelem(ryzovadir), devgen);
}

static long
ryzovaread(Chan *c, void *va, long n, vlong off)
{
	switch((ulong)c->qid.path){
	case Qdir:
		return devdirread(c, va, n, ryzovadir, nelem(ryzovadir), devgen);
	case Qversion:
		return readstr(off, va, n, "Ryzova Kernel 0.1.0-dev\n");
	case Qfoundation:
		return readstr(off, va, n, "9front-derived\n");
	case Qabi:
		return readstr(off, va, n, "experimental-0\n");
	}
	error(Eperm);
	return 0;
}

static long
ryzovawrite(Chan*, void*, long, vlong)
{
	error(Eperm);
	return 0;
}

Dev ryzovadevtab = {
	'Z',
	"ryzova",

	devreset,
	devinit,
	devshutdown,
	ryzovaattach,
	ryzovawalk,
	ryzovastat,
	ryzovaopen,
	devcreate,
	devclose,
	ryzovaread,
	devbread,
	ryzovawrite,
	devbwrite,
	devremove,
	devwstat,
};
