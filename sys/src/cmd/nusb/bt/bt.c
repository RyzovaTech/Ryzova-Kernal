/* SPDX-License-Identifier: AGPL-3.0-only */
/*
 * Opt-in USB Bluetooth HCI event transport diagnostic for Ryzova.
 * Not a Bluetooth host stack; no pairing, encryption, ACL, SCO or LE connection
 * management. The device is never auto-claimed and no commands are sent unless
 * -r is explicitly requested.
 */
#include <u.h>
#include <libc.h>
#include <thread.h>
#include "usb.h"
#include "hciwire.h"

enum { Btclass = 0xe0, Btsubclass = 1, Btprotocol = 1 };

static void
usage(void)
{
	fprint(2, "usage: %s [-r] [-n events] devid\n", argv0);
	threadexitsall("usage");
}

static Ep*
findeventep(Dev *dev)
{
	Conf *conf;
	Iface *iface;
	Ep *ep;
	int c, i, e;

	if(dev == nil || dev->usb == nil)
		return nil;
	for(c = 0; c < nelem(dev->usb->conf); c++){
		conf = dev->usb->conf[c];
		if(conf == nil)
			continue;
		for(i = 0; i < nelem(conf->iface); i++)
		for(iface = conf->iface[i]; iface != nil; iface = iface->next){
			if(iface->alt != 0 || iface->csp != CSP(Btclass, Btsubclass, Btprotocol))
				continue;
			for(e = 0; e < nelem(iface->ep); e++){
				ep = iface->ep[e];
				if(ep == nil || ep->iface != iface)
					continue;
				if(ep->type == Eintr && ep->dir == Ein &&
				   ep->maxpkt > 0 && ep->maxpkt <= BthciEventMax)
					return ep;
			}
		}
	}
	return nil;
}

void
threadmain(int argc, char **argv)
{
	Dev *dev, *events;
	Ep *ep;
	uchar buf[BthciEventMax], reset[3];
	int n, count, limit, dorestart, i, bad;

	limit = 1;
	dorestart = 0;
	ARGBEGIN{
	case 'r':
		dorestart = 1;
		break;
	case 'n':
		limit = atoi(EARGF(usage()));
		if(limit < 1 || limit > 4096)
			usage();
		break;
	default:
		usage();
	}ARGEND;
	if(argc != 1)
		usage();
	if((dev = getdev(argv[0])) == nil)
		sysfatal("bt: getdev: %r");
	if((ep = findeventep(dev)) == nil)
		sysfatal("bt: no standard USB HCI interrupt event interface");
	if((events = openep(dev, ep)) == nil)
		sysfatal("bt: open event endpoint: %r");
	if(opendevdata(events, OREAD) < 0)
		sysfatal("bt: open event data: %r");

	if(dorestart){
		if(bthcireset(reset, sizeof reset) != sizeof reset ||
		   usbcmd(dev, Rh2d|Rclass|Rdev, 0, 0, 0, reset, sizeof reset) != sizeof reset)
			sysfatal("bt: HCI reset command failed: %r");
	}

	bad = 0;
	for(count = 0; count < limit; ){
		n = read(events->dfd, buf, sizeof buf);
		if(n <= 0)
			sysfatal("bt: event endpoint detached or read failed: %r");
		if(!bthcieventvalid(buf, n)){
			fprint(2, "bt: malformed HCI event transfer (%d bytes)\n", n);
			if(++bad == 3)
				sysfatal("bt: repeated malformed events");
			continue;
		}
		bad = 0;
		print("event %.2ux len %d", buf[0], buf[1]);
		for(i = 2; i < n; i++)
			print(" %.2ux", buf[i]);
		print("\n");
		count++;
	}
	closedev(events);
	closedev(dev);
	threadexitsall(nil);
}
