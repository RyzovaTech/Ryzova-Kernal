#include "u.h"
#include "../port/lib.h"
#include "mem.h"
#include "dat.h"
#include "fns.h"
#include "io.h"
#include "../port/pci.h"
#include "m5ecam.h"

#define MMIOBASE 0x10000000
#define ECAMBASE 0x3F000000
#define ECAMSIZE 0x01000000

typedef struct Intvec Intvec;

struct Intvec {
	Pcidev *p;
	void (*f)(Ureg*, void*);
	void *a;
};

static uchar *ecam;
static Intvec vec[32];

static void*
cfgaddr(int tbdf, int rno, unsigned int width)
{
	unsigned long off;

	if(ecam == nil || BUSTYPE(tbdf) != BusPCI ||
	   m5ecamoffset(BUSBNO(tbdf), BUSDNO(tbdf), BUSFNO(tbdf),
		rno, width, ECAMSIZE, &off) < 0)
		return nil;
	return ecam + off;
}

int
pcicfgrw32(int tbdf, int rno, int data, int read)
{
	u32int *p;

	if((p = cfgaddr(tbdf, rno & ~3, 4)) != nil){
		if(read)
			data = *p;
		else
			*p = data;
	} else {
		data = -1;
	}
	return data;
}

int
pcicfgrw16(int tbdf, int rno, int data, int read)
{
	u16int *p;

	if((p = cfgaddr(tbdf, rno & ~1, 2)) != nil){
		if(read)
			data = *p;
		else
			*p = data;
	} else {
		data = -1;
	}
	return data;
}

int
pcicfgrw8(int tbdf, int rno, int data, int read)
{
	u8int *p;

	if((p = cfgaddr(tbdf, rno, 1)) != nil){
		if(read)
			data = *p;
		else
			*p = data;
	} else {
		data = -1;
	}
	return data;
}

static void
pciinterrupt(Ureg *ureg, void *)
{
	int i;
	Intvec *v;

	for(i = 0; i < nelem(vec); i++){
		v = &vec[i];
		if(v->f)
			v->f(ureg, v->a);
	}
}

static void
pciintrinit(void)
{
	intrenable(IRQpci1, pciinterrupt, nil, BUSUNKNOWN, "pci");
	intrenable(IRQpci2, pciinterrupt, nil, BUSUNKNOWN, "pci");
	intrenable(IRQpci3, pciinterrupt, nil, BUSUNKNOWN, "pci");
	intrenable(IRQpci4, pciinterrupt, nil, BUSUNKNOWN, "pci");
}

void
pciintrenable(int tbdf, void (*f)(Ureg*, void*), void *a)
{
	Pcidev *p;
	int i;
	Intvec *v;

	if((p = pcimatchtbdf(tbdf)) == nil){
		print("pciintrenable: %T: unknown device\n", tbdf);
		return;
	}

	for(i = 0; i < nelem(vec); i++){
		v = &vec[i];
		if(v->f == nil){
			v->p = p;
			v->f = f;
			v->a = a;
			return;
		}
	}
}

void
pciintrdisable(int tbdf, void (*f)(Ureg*, void*), void *a)
{
	Pcidev *p;
	int i;
	Intvec *v;

	if((p = pcimatchtbdf(tbdf)) == nil){
		print("pciintrdisable: %T: unknown device\n", tbdf);
		return;
	}

	for(i = 0; i < nelem(vec); i++){
		v = &vec[i];
		if(v->p == p && v->f == f && v->a == a)
			v->f = nil;
	}
}

static void
pcicfginit(void)
{
	char *p;
	Pcidev *pciroot;
	ulong ioa;
	uvlong base;

	fmtinstall('T', tbdffmt);

	pcimaxdno = 32;
	if(p = getconf("*pcimaxdno")){
		pcimaxdno = strtoul(p, 0, 0);
		if(pcimaxdno < 1 || pcimaxdno > 32)
			pcimaxdno = 32;
	}

	pciscan(0, &pciroot, nil);
	if(pciroot == nil)
		return;

	pciintrinit();

	ioa = 0;
	base = MMIOBASE;
	pcibusmap(pciroot, &base, &ioa, 1);

	if(getconf("*pcihinv"))
		pcihinv(pciroot);
}

void
pciqemulink(void)
{
	ecam = vmap(ECAMBASE, ECAMSIZE);
	if(ecam == nil){
		print("arm64 pci: ECAM window unavailable; PCI disabled\n");
		return;
	}
	pcicfginit();
}
