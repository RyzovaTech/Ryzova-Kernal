/*
 * generic CDC
 */

#include <u.h>
#include <libc.h>
#include <thread.h>

#include "usb.h"
#include "../lib/m1class.h"
#include "dat.h"

#include <ip.h>

static int
cdcreceive(Dev *ep)
{
	Block *b;
	int n;

	b = allocb(Maxpkt);
	if((n = read(ep->dfd, b->wp, b->lim - b->base)) < 0){
		freeb(b);
		return -1;
	}
	b->wp += n;
	etheriq(b);
	return 0;
}

static void
cdctransmit(Dev *ep, Block *b)
{
	int n;

	n = BLEN(b);
	if(write(ep->dfd, b->rp, n) < 0){
		freeb(b);
		return;
	}
	freeb(b);

	/*
	 * this may not work with all CDC devices. the
	 * linux driver sends one more random byte
	 * instead of a zero byte transaction. maybe we
	 * should do the same?
	 */
	if(ep->maxpkt > 0 && (n % ep->maxpkt) == 0)
		write(ep->dfd, "", 0);
}

int
cdcinit(Dev *d)
{
	int i;
	Usbdev *ud;
	uchar *b;
	Desc *dd;
	char *mac;

	ud = d->usb;
	for(i = 0; i < nelem(ud->ddesc); i++)
		if((dd = ud->ddesc[i]) != nil){
			b = (uchar*)&dd->data;
			if(dd->data.bLength >= 4 && b[1] == Dfunction && b[2] == Fnether){
				mac = loaddevstr(d, b[3]);
				if(mac != nil && !m1cdcmacvalid(mac, strlen(mac))){
					free(mac);
					mac = nil;
				}
				if(mac != nil){
					parseether(macaddr, mac);
					free(mac);

					epreceive = cdcreceive;
					eptransmit = cdctransmit;
					return 0;
				}
			}
		}
	return -1;
}
