/* SPDX-License-Identifier: AGPL-3.0-only */
/* CLX-06: bounded, namespace-owned raw PTY research; no host PTY forwarding.
 * Included by syscall.c after new_description, before do_read/do_write.
 * No canonical-mode, echo, PTY resize signals or job-control claims. */
#ifndef RYZOVA_LINUX_SYSCALL_PTY_H
#define RYZOVA_LINUX_SYSCALL_PTY_H

static unsigned int pty_refs(RyzLinuxWorld *w,unsigned int slot,enum RyzLinuxNode node)
{
    unsigned int i,n=0;
    for(i=0;i<RYZ_WORLD_DESCRIPTIONS;i++)
        if(w->descriptions[i].used && w->descriptions[i].fd.node==node
           && w->descriptions[i].fd.pty==slot)n+=w->descriptions[i].refs;
    return n;
}
static void pty_cleanup(RyzLinuxWorld *w)
{
    unsigned int i;
    for(i=0;i<RYZ_WORLD_PTYS;i++)
        if(w->ptys[i].used && !pty_refs(w,i,RYZ_NS_PTY_MASTER)
           && !pty_refs(w,i,RYZ_NS_PTY_SLAVE))
            memset(&w->ptys[i],0,sizeof(w->ptys[i]));
}
static int64_t pty_open(RyzLinuxProcess *p,const char *path,uint64_t dirfd,uint64_t flags)
{
    unsigned int i,slot=RYZ_WORLD_PTYS,id;int fd,master;
    if(!p->world || dirfd!=L_AT_FDCWD)return -L_EINVAL;
    if((flags&L_O_ACCMODE)!=L_O_RDWR || (flags&~(uint64_t)(L_O_ACCMODE|L_O_CLOEXEC|04000U)))return -L_EINVAL;
    master=strcmp(path,"/dev/ptmx")==0;
    if(master){
        for(i=0;i<RYZ_WORLD_PTYS;i++)if(!p->world->ptys[i].used){slot=i;break;}
        if(slot==RYZ_WORLD_PTYS)return -28; /* bounded PTY instances */
    }else{
        size_t n=strlen(path);
        if(n!=10 || strncmp(path,"/dev/pts/",9)!=0 || path[9]<'0'
           || path[9]>='0'+(int)RYZ_WORLD_PTYS)return -L_ENOENT;
        slot=(unsigned int)(path[9]-'0');
        if(!p->world->ptys[slot].used || p->world->ptys[slot].locked
           || p->world->ptys[slot].namespace_id!=p->ns.namespace_id
           || p->world->ptys[slot].uid!=p->ns.uid
           || !pty_refs(p->world,slot,RYZ_NS_PTY_MASTER))return -L_EACCES;
    }
    for(fd=0;fd<(int)p->file_limit;fd++)if(!p->fds[fd].open)break;
    if(fd==(int)p->file_limit)return -L_EMFILE;
    id=new_description(p);if(!id)return -L_EMFILE;
    if(master){
        RyzLinuxPty *pty=&p->world->ptys[slot];
        memset(pty,0,sizeof(*pty));
        pty->used=1;pty->locked=1;pty->namespace_id=p->ns.namespace_id;
        pty->uid=p->ns.uid;pty->rows=24;pty->columns=80;
    }
    memset(&p->fds[fd],0,sizeof p->fds[fd]);
    p->fds[fd].open=1;p->fds[fd].mode=2;
    p->fds[fd].node=master?RYZ_NS_PTY_MASTER:RYZ_NS_PTY_SLAVE;
    p->fds[fd].pty=slot;p->fds[fd].description=id;
    p->fds[fd].cloexec=(flags&L_O_CLOEXEC)!=0;
    p->fds[fd].nonblock=(flags&04000U)!=0;
    return fd;
}
static int64_t pty_io(RyzLinuxProcess *p,uint64_t fd,unsigned char *buf,uint64_t count,int writing)
{
    RyzLinuxFD *desc=&p->fds[fd];
    RyzLinuxPty *pty=&p->world->ptys[desc->pty];
    unsigned int incoming=desc->node==RYZ_NS_PTY_MASTER?0:1;
    unsigned int peer=desc->node==RYZ_NS_PTY_MASTER?RYZ_NS_PTY_SLAVE:RYZ_NS_PTY_MASTER;
    unsigned int ring=writing?1-incoming:incoming;
    uint64_t i,available;
    if(!pty->used || pty->namespace_id!=p->ns.namespace_id)return -L_EACCES;
    if(writing){
        if(!pty_refs(p->world,desc->pty,(enum RyzLinuxNode)peer))return -5;
        if(p->world->pty_bytes>=RYZ_PTY_TOTAL_BYTES)return -28;
        available=RYZ_PTY_BUFFER-pty->size[ring];
        if(!available)return desc->nonblock?-11:RYZ_LINUX_BLOCKED;
        if(count>available)count=available;
        if(count>RYZ_PTY_TOTAL_BYTES-p->world->pty_bytes)count=RYZ_PTY_TOTAL_BYTES-p->world->pty_bytes;
        for(i=0;i<count;i++)pty->bytes[ring][(pty->head[ring]+pty->size[ring]+(size_t)i)%RYZ_PTY_BUFFER]=buf[i];
        pty->size[ring]+=(size_t)count;p->world->pty_bytes+=count;
    }else{
        available=pty->size[ring];
        if(!available)return pty_refs(p->world,desc->pty,(enum RyzLinuxNode)peer)?
                            (desc->nonblock?-11:RYZ_LINUX_BLOCKED):0;
        if(count>available)count=available;
        for(i=0;i<count;i++)buf[i]=pty->bytes[ring][(pty->head[ring]+(size_t)i)%RYZ_PTY_BUFFER];
        pty->head[ring]=(pty->head[ring]+(size_t)count)%RYZ_PTY_BUFFER;
        pty->size[ring]-=(size_t)count;
    }
    return (int64_t)count;
}
static unsigned int pty_poll(RyzLinuxProcess *p,uint64_t fd,unsigned int events)
{
    RyzLinuxFD *desc=&p->fds[fd];
    RyzLinuxPty *pty=&p->world->ptys[desc->pty];
    unsigned int read=desc->node==RYZ_NS_PTY_MASTER?0:1,other=1-read,flags=0;
    enum RyzLinuxNode peer=desc->node==RYZ_NS_PTY_MASTER?RYZ_NS_PTY_SLAVE:RYZ_NS_PTY_MASTER;
    if(!pty->used)return 8;
    if(pty->size[read])flags|=events&1U;
    if(pty_refs(p->world,desc->pty,peer)){
        if(pty->size[other]<RYZ_PTY_BUFFER && p->world->pty_bytes<RYZ_PTY_TOTAL_BYTES)flags|=events&4U;
    }else flags|=16;
    return flags;
}
static int64_t pty_ioctl(RyzLinuxProcess *p,const RyzLinuxRegs *r)
{
    RyzLinuxFD *fd=&p->fds[r->rdi];RyzLinuxPty *pty=&p->world->ptys[fd->pty];
    unsigned char *buf=NULL;uint64_t code=r->rsi;unsigned int value;
    int reading=(code==0x40045431U || code==0x5402U || code==0x5414U);
    size_t bytes=(code==0x80045430U || code==0x40045431U)?4:
                 (code==0x5413U || code==0x5414U)?8:
                 (code==0x5401U || code==0x5402U)?36:0;
    if(!bytes)return -25;
    if(!pty->used || pty->namespace_id!=p->ns.namespace_id)return -L_EACCES;
    if((code==0x80045430U || code==0x40045431U) && fd->node!=RYZ_NS_PTY_MASTER)return -25;
    if(!guest_range(p,r->rdx,bytes,&buf) ||
       (reading?(p->memory_read && !p->memory_read(p->memory_context,r->rdx,bytes)):
                (p->memory_write && !p->memory_write(p->memory_context,r->rdx,bytes))))return -L_EFAULT;
    if(code==0x80045430U){encode(buf,fd->pty,4);return 0;} /* TIOCGPTN */
    if(code==0x40045431U){
        value=(unsigned int)buf[0]|((unsigned int)buf[1]<<8)|((unsigned int)buf[2]<<16)|((unsigned int)buf[3]<<24);
        if(value>1)return -L_EINVAL;
        if(value && pty_refs(p->world,fd->pty,RYZ_NS_PTY_SLAVE))return -L_EINVAL;
        pty->locked=value;return 0;
    }
    if(code==0x5413U){ /* TIOCGWINSZ */
        encode(buf,pty->rows,2);encode(buf+2,pty->columns,2);
        encode(buf+4,0,4);return 0;
    }
    if(code==0x5414U){ /* TIOCSWINSZ: no synthetic SIGWINCH */
        unsigned int rows=(unsigned int)buf[0]|((unsigned int)buf[1]<<8);
        unsigned int cols=(unsigned int)buf[2]|((unsigned int)buf[3]<<8);
        if(!rows || !cols || rows>1000 || cols>1000)return -L_EINVAL;
        pty->rows=rows;pty->columns=cols;return 0;
    }
    if(code==0x5401U){ /* TCGETS, initial raw 8-bit profile only */
        memset(buf,0,36);encode(buf+8,0xb0,4);buf[17+6]=1;return 0;
    }
    if(code==0x5402U){ /* TCSETS: only actual raw mode; no fake canonical/echo */
        {unsigned int i;for(i=0;i<8;i++)if(buf[i])return -95;
         for(i=12;i<16;i++)if(buf[i])return -95;}
        value=(unsigned int)buf[8]|((unsigned int)buf[9]<<8)|((unsigned int)buf[10]<<16)|((unsigned int)buf[11]<<24);
        if(value!=0xb0 || buf[16]!=0 || buf[22]!=0 || buf[23]!=1)return -95;
        return 0;
    }
    return -25;
}
#endif
