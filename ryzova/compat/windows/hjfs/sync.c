/* SPDX-License-Identifier: AGPL-3.0-only */
/* Windows-owned barrier for an explicitly qualified virtio-SCSI resource disk. */
#include <u.h>
#include <libc.h>
#include <thread.h>
#include "dat.h"
#include "fns.h"
extern Fs *fsmain;
static int rawfd = -1;

static int
storageflush(void)
{
	uchar cdb[10] = {0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	char status[64], *end;
	int n;
	long code;

	/* IMMED=0: the GOOD status must follow completion of SYNCHRONIZE CACHE. */
	if(write(rawfd, cdb, sizeof cdb) != sizeof cdb)
		return -1;
	/* The Plan 9 SCSI adapter may return the requested dummy byte count
	 * even for a no-data CDB. Completion is established by the following
	 * separately validated SCSI status, not this data-phase length. */
	if(read(rawfd, status, 1) < 0)
		return -1;
	n = read(rawfd, status, sizeof(status)-1);
	if(n <= 0){
		werrstr("missing SCSI completion status");
		return -1;
	}
	status[n] = 0;
	code = strtol(status, &end, 10);
	if(end == status){
		werrstr("malformed SCSI completion status");
		return -1;
	}
	while(*end == ' ' || *end == '\n' || *end == '\t')
		end++;
	if(code != 0 || *end != 0){
		werrstr("SCSI synchronize cache failed: %s", status);
		return -1;
	}
	return 0;
}

int
cwsyncinit(char *file)
{
	char ctl[4096];
	int fd, n;

	/* Version 1 qualifies only the dedicated QEMU virtio-SCSI unit. In
	 * particular it must never ream or issue control commands to the boot disk.
	 * Other drivers may fake a successful SCSI flush; do not accept them. */
	if(strcmp(file, "/dev/sd01/data") != 0){
		werrstr("barrier v1 requires the dedicated /dev/sd01/data unit");
		return -1;
	}
	fd = open("/dev/sdctl", OREAD);
	if(fd < 0)
		return -1;
	n = read(fd, ctl, sizeof(ctl)-1);
	close(fd);
	if(n <= 0)
		return -1;
	ctl[n] = 0;
	if(strncmp(ctl, "sd0 virtio ", 11) != 0 && strstr(ctl, "\nsd0 virtio ") == nil){
		werrstr("unqualified storage controller");
		return -1;
	}
	rawfd = open("/dev/sd01/raw", ORDWR);
	if(rawfd < 0)
		return -1;
	return storageflush();
}

int
cwsync(void)
{
	Dev *d;
	int rc;

	if(!cwstrict || rawfd < 0){
		werrstr("no qualified storage barrier");
		return -1;
	}
	/* Quiesce filesystem readers/writers, drain queued putbuf operations,
	 * enqueue dirty cache writes, and wait behind every device write. */
	dprint("CW_BARRIER quiesce\n");
	wlock(fsmain);
	dprint("CW_BARRIER cache-drain\n");
	sync(1);
	dprint("CW_BARRIER device-flush\n");
	rc = 0;
	for(d = devs; d != nil; d = d->next)
		if(d->writefailed)
			rc = -1;
	if(rc == 0)
		rc = storageflush();
	if(rc < 0){
		/* Once persistence is uncertain, fail closed for this server lifetime. */
		for(d = devs; d != nil; d = d->next)
			d->writefailed = 1;
		werrstr("resource storage barrier failed");
	}
	dprint("CW_BARRIER %s\n", rc < 0 ? "failed" : "complete");
	wunlock(fsmain);
	return rc;
}
