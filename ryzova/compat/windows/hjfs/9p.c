#include <u.h>
#include <libc.h>
#include <thread.h>
#include <fcall.h>
#include <9p.h>
#include "dat.h"
#include "fns.h"
#include "../sync_protocol.h"

extern Fs *fsmain;

/* This virtual control fid belongs to this filesystem connection. An ordinary
 * file cannot acknowledge a request by merely echoing its bytes. */
#define CWSYNCNAME ".ryzova-sync-v1"
#define CWSYNCQID (~(uvlong)1)
typedef struct SyncFid SyncFid;
struct SyncFid {
	QLock lock;
	int opened;
	char reply[64];
};

static SyncFid *
newsyncfid(void)
{
	SyncFid *s;
	s = emalloc(sizeof(*s));
	strcpy(s->reply, "CWFS_SYNC_V1\n");
	return s;
}

static void
syncreq(void *v)
{
	Req *r;
	SyncFid *s;
	int rc;
	CwSyncNonce nonce;
	char error[ERRMAX];

	r = v;
	s = r->fid->aux;
	rc = 0;
	qlock(&s->lock);
	switch(r->ifcall.type){
	case Twalk:
		if(s->opened || r->ifcall.nwname != 0)
			goto bad;
		if(r->newfid != r->fid){
			r->newfid->aux = newsyncfid();
			r->newfid->qid = r->fid->qid;
		}
		r->ofcall.nwqid = 0;
		break;
	case Topen:
		if(s->opened || r->ifcall.mode != ORDWR)
			goto bad;
		s->opened = 1;
		r->ofcall.qid = r->fid->qid;
		break;
	case Tstat:
		memset(&r->d, 0, sizeof r->d);
		r->d.qid = r->fid->qid;
		r->d.mode = 0600;
		r->d.name = estrdup(CWSYNCNAME);
		r->d.uid = estrdup("glenda");
		r->d.gid = estrdup("glenda");
		r->d.muid = estrdup("glenda");
		r->d.length = strlen(s->reply);
		break;
	case Tread:
		if(!s->opened)
			goto bad;
		readstr(r, s->reply);
		break;
	case Twrite:
		/* Exact bounded request, offset zero; invalidate any previous ACK first. */
		strcpy(s->reply, "CWFS_SYNC_V1\n");
		if(!s->opened || r->ifcall.offset != 0 || !cw_sync_parse(r->ifcall.data, r->ifcall.count, &nonce))
			goto bad;
		if(cwsync() < 0){
			rc = -1;
			break;
		}
		cw_sync_reply(nonce, s->reply);
		s->reply[21] = 0;
		r->ofcall.count = r->ifcall.count;
		break;
	default:
	bad:
		werrstr(Einval);
		rc = -1;
	}
	if(rc < 0)
		rerrstr(error, sizeof error);
	qunlock(&s->lock);
	respond(r, rc < 0 ? error : nil);
	threadexits(nil);
}


static void
tauth(Req *req)
{
	if((fsmain->flags & FSNOAUTH) != 0
	|| strcmp(req->ifcall.uname, "none") == 0)
		respond(req, "no authentication required");
	else if(*req->ifcall.aname == 0 || strcmp(req->ifcall.aname, "dump") == 0)
		auth9p(req);
	else
		respond(req, Ebadspec);
}

static void
tattach(Req *req)
{
	Chan *ch;
	int flags;
	short uid;

	if((fsmain->flags & FSNOAUTH) == 0){
		if(strcmp(req->ifcall.uname, "none") == 0){
			if(!req->srv->authok){
				respond(req, "require prior authentication for 'none'");
				return;
			}
		} else {
			if(authattach(req) < 0)
				return;
			req->srv->authok = 1;	/* none attaches allowed now */
		}
	}
	if(name2uid(fsmain, req->ifcall.uname, &uid) <= 0){
		respond(req, "no such user");
		return;
	}
	if(*req->ifcall.aname == 0)
		flags = 0;
	else if(strcmp(req->ifcall.aname, "dump") == 0){
		if(uid == 0){
			/* dont give "none" access to dump */
			respond(req, Eperm);
			return;
		}
		flags = CHFDUMP|CHFRO;
	} else {
		respond(req, Ebadspec);
		return;
	}
	ch = chanattach(fsmain, flags);
	ch->uid = uid;
	req->fid->aux = ch;
	req->fid->qid = ch->loc->Qid;
	req->ofcall.qid = ch->loc->Qid;
	respond(req, nil);
}

static void
tqueue(Req *req)
{
	Chan *ch;

	if((req->fid->qid.type & QTAUTH) != 0){
		switch(req->ifcall.type){
		case Tread:
			authread(req);
			return;
		case Twrite:
			authwrite(req);
			return;
		default:
			respond(req, Einval);
			return;
		}
	}
	if(cwstrict && req->fid->qid.path == CWSYNCQID){
		threadcreate(syncreq, req, mainstacksize);
		return;
	}
	ch = req->fid->aux;
	if(ch == nil){
		respond(req, "operation on closed fid");
		return;
	}
	qlock(&chanqu);
	req->aux = nil;
	if(ch->freq == nil)
		ch->freq = req;
	if(ch->lreq != nil)
		((Req *) ch->lreq)->aux = req;
	ch->lreq = req;
	if(ch->qnext == nil && (ch->wflags & CHWBUSY) == 0){
		ch->qnext = &readych;
		ch->qprev = ch->qnext->qprev;
		ch->qnext->qprev = ch;
		ch->qprev->qnext = ch;
		rwakeup(&chanre);
	}
	if(req->ifcall.type == Tremove)
		req->fid->aux = nil;
	qunlock(&chanqu);
}

static void
tdestroyfid(Fid *fid)
{
	Chan *ch;

	if((fid->qid.type & QTAUTH) != 0){
		authdestroy(fid);
		return;
	}
	if(cwstrict && fid->qid.path == CWSYNCQID){
		free(fid->aux);
		fid->aux = nil;
		return;
	}
	qlock(&chanqu);
	ch = fid->aux;
	fid->aux = nil;
	if(ch != nil){
		ch->wflags |= CHWCLUNK;
		if(ch->qnext == nil && (ch->wflags & CHWBUSY) == 0){
			ch->qnext = &readych;
			ch->qprev = ch->qnext->qprev;
			ch->qnext->qprev = ch;
			ch->qprev->qnext = ch;
			rwakeup(&chanre);
		}
	}
	qunlock(&chanqu);
}

static void
tend(Srv *)
{
	shutdown();
}

static Srv mysrv = {
	.auth = tauth,
	.attach = tattach,
	.walk = tqueue,
	.open = tqueue,
	.create = tqueue,
	.read = tqueue,
	.write = tqueue,
	.stat = tqueue,
	.wstat = tqueue,
	.remove = tqueue,
	.destroyfid = tdestroyfid,
	.end = tend,
};

void
start9p(char *service, char **nets, int stdio)
{
	while(nets && *nets){
		mysrv.end = nil;	/* disable shutdown */
		threadlistensrv(&mysrv, *nets++);
	}
	if(stdio){
		mysrv.infd = 0;
		mysrv.outfd = 1;
		srv(&mysrv);
	}else
		threadpostmountsrv(&mysrv, service, nil, 0);
}

static int
twalk(Chan *ch, Fid *fid, Fid *nfid, int n, char **name, Qid *qid)
{
	int i;

	if(cwstrict && n == 1 && ch->loc->path == ROOTQID
	&& strcmp(name[0], CWSYNCNAME) == 0 && ch->uid != 0){
		if(ch->open != 0 || nfid == fid){
			werrstr(Einval);
			return -1;
		}
		nfid->aux = newsyncfid();
		nfid->qid.path = CWSYNCQID;
		nfid->qid.type = 0;
		nfid->qid.vers = 1;
		qid[0] = nfid->qid;
		return 1;
	}
	if(nfid != fid){
		if(ch->open != 0){
			werrstr("trying to clone an open fid");
			return -1;
		}
		ch = chanclone(ch);
		if(ch == nil)
			return -1;
		nfid->aux = ch;
		nfid->qid = ch->loc->Qid;
	}
	for(i = 0; i < n; i++){
		if(chanwalk(ch, name[i]) <= 0)
			return i > 0 ? i : -1;
		qid[i] = ch->loc->Qid;
		nfid->qid = ch->loc->Qid;
	}
	return n;
}

static void
workerproc(void *)
{
	Chan *ch;
	Req *req;
	int rc;
	Fcall *i, *o;

	qlock(&chanqu);
	for(;;){
		while(readych.qnext == &readych)
			rsleep(&chanre);
		ch = readych.qnext;
		ch->qnext->qprev = ch->qprev;
		ch->qprev->qnext = ch->qnext;
		ch->qprev = nil;
		ch->qnext = nil;
		assert((ch->wflags & CHWBUSY) == 0);
		ch->wflags |= CHWBUSY;
		while(ch != nil && ch->freq != nil){
			req = ch->freq;
			ch->freq = req->aux;
			if(ch->lreq == req)
				ch->lreq = nil;
			req->aux = nil;
			qunlock(&chanqu);
			assert(req->responded == 0);
			i = &req->ifcall;
			o = &req->ofcall;
			switch(req->ifcall.type){
			case Twalk:
				rc = twalk(ch, req->fid, req->newfid, i->nwname, i->wname, o->wqid);
				if(rc >= 0)
					o->nwqid = rc;
				break;
			case Topen:
				rc = chanopen(ch, i->mode);
				break;
			case Tcreate:
				rc = chancreat(ch, i->name, i->perm, i->mode);
				if(rc >= 0){
					o->qid = ch->loc->Qid;
					req->fid->qid = o->qid;
				}
				break;
			case Tread:
				rc = o->count = chanread(ch, o->data, i->count, i->offset);
				break;
			case Twrite:
				rc = o->count = chanwrite(ch, i->data, i->count, i->offset);
				break;
			case Tremove:
				rc = chanremove(ch);
				req->fid->aux = ch = nil;
				break;
			case Tstat:
				rc = chanstat(ch, &req->d);
				break;
			case Twstat:
				rc = chanwstat(ch, &req->d);
				break;
			default:
				werrstr(Einval);
				rc = -1;
			}
			if(rc < 0)
				responderror(req);
			else
				respond(req, nil);
			qlock(&chanqu);
		}
		if(ch != nil){
			ch->wflags &= ~CHWBUSY;
			if((ch->wflags & CHWCLUNK) != 0)
				chanclunk(ch);
		}
	}
}

QLock chanqu;
Chan readych;
Rendez chanre;

void
workerinit(void)
{
	int i;
	
	readych.qnext = readych.qprev = &readych;
	chanre.l = &chanqu;
	for(i = 0; i < NWORKERS; i++)
		threadcreate(workerproc, nil, mainstacksize);
}

