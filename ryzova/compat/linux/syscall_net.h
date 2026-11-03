/* SPDX-License-Identifier: AGPL-3.0-only */
/* Bounded streams with opt-in, caller-owned native resource adapters. */
int ryz_network_budget(RyzLinuxWorld *w)
{
    uint64_t now,limit;
    if(!w->network)return 1;
    if(w->network_failed)return 0;
    now=w->network->now_ns(w->network->context);limit=(uint64_t)(w->network->wall_milliseconds?w->network->wall_milliseconds:5000)*1000000;
    if(now==UINT64_MAX || now<w->network_last || now-w->network_start>=limit){w->network_failed=1;return 0;}
    w->network_last=now;return 1;
}
static void net_elapsed(RyzLinuxWorld *w,uint64_t before)
{
    uint64_t elapsed;
    if(!ryz_network_budget(w))return;
    elapsed=(w->network_last-before)/1000;
    w->clock=elapsed>UINT64_MAX-w->clock?UINT64_MAX:w->clock+elapsed;
}
int ryz_network_idle(RyzLinuxWorld *w)
{
    unsigned int i,limit;uint64_t before;
    if(!w->network)return 0;
    for(i=0;i<RYZ_NET_SOCKETS;i++)if(w->sockets[i].used && w->sockets[i].external && w->sockets[i].external_handle>=0)break;
    if(i==RYZ_NET_SOCKETS)return 0;
    limit=w->network->wall_milliseconds?w->network->wall_milliseconds:5000;
    if(!ryz_network_budget(w) || ++w->network_waits>limit)return -1;
    before=w->network_last;w->network->wait(w->network->context);net_elapsed(w,before);
    return w->network_failed?-1:1;
}
static void net_external_close(RyzLinuxWorld *w,RyzLinuxSocket *s)
{
    const RyzNetworkGrant *g;
    if(!s->external || s->external_handle<0)return;
    g=&w->network->grants[s->external-1];g->ops->close(g->context,s->external_handle);
    w->network_busy[s->external-1]=0;s->external_handle=-1;s->external_eof=s->external_hup=1;
}
static int net_external_ready(RyzLinuxWorld *w,RyzLinuxSocket *s)
{
    const RyzNetworkGrant *g;uint64_t before;int ready;
    if(s->external_handle<0)return 17;
    if(!ryz_network_budget(w))return 8;
    g=&w->network->grants[s->external-1];before=w->network_last;
    ready=g->ops->ready(g->context,s->external_handle);net_elapsed(w,before);
    if(ready==-11)return 0;
    if(ready<0){if(ready< -4095)w->network_failed=1;s->external_error=5;return 8;}
    if(ready&~(1|4|8|16|8192)){w->network_failed=1;s->external_error=5;return 8;}
    if(ready&8)s->external_error=5;
    if(ready&16)s->external_hup=1;
    return ready;
}
static void net_external_fill(RyzLinuxWorld *w,RyzLinuxSocket *s)
{
    const RyzNetworkGrant *g;size_t at,count;int ready;int64_t n;uint64_t before;
    if(s->external_eof || s->read_closed || s->external_error || s->size==RYZ_NET_BUFFER)return;
    ready=net_external_ready(w,s);if(!(ready&(1|16|8192)))return;
    if(w->network_bytes>=4U*1024U*1024U){s->external_error=28;return;}
    at=(s->head+s->size)%RYZ_NET_BUFFER;count=RYZ_NET_BUFFER-at;
    if(count>RYZ_NET_BUFFER-s->size)count=RYZ_NET_BUFFER-s->size;
    if(count>4U*1024U*1024U-w->network_bytes)count=(size_t)(4U*1024U*1024U-w->network_bytes);
    g=&w->network->grants[s->external-1];before=w->network_last;
    n=g->ops->read(g->context,s->external_handle,s->bytes+at,count);net_elapsed(w,before);
    if(n==-11)return;
    if(n<0){if(n< -4095)w->network_failed=1;s->external_error=n>=-4095?(int)-n:5;return;}
    if((uint64_t)n>count){w->network_failed=1;s->external_error=5;return;}
    if(!n)s->external_eof=1;
    else{s->size+=(size_t)n;w->network_bytes+=(uint64_t)n;}
}
static void net_cleanup(RyzLinuxWorld *w)
{
    unsigned int i,j;unsigned char keep[RYZ_NET_SOCKETS];
    memset(keep,0,sizeof keep);
    for(i=0;i<RYZ_WORLD_DESCRIPTIONS;i++)if(w->descriptions[i].used && w->descriptions[i].refs && w->descriptions[i].fd.node==RYZ_NS_SOCKET)keep[w->descriptions[i].fd.socket]=1;
    for(i=0;i<RYZ_NET_SOCKETS;i++)if(keep[i] && w->sockets[i].listening)
        for(j=0;j<w->sockets[i].pending_count;j++)keep[w->sockets[i].pending[j]]=1;
    for(i=0;i<RYZ_NET_SOCKETS;i++)if(w->sockets[i].used && !keep[i]){
        int peer=w->sockets[i].peer;
        net_external_close(w,&w->sockets[i]);
        if(peer>=0 && peer<(int)RYZ_NET_SOCKETS && w->sockets[peer].used && w->sockets[peer].peer==(int)i)w->sockets[peer].peer=-1;
        memset(&w->sockets[i],0,sizeof w->sockets[i]);
    }
}
static int net_slot(RyzLinuxWorld *w)
{
    unsigned int i;
    for(i=0;i<RYZ_NET_SOCKETS;i++)if(!w->sockets[i].used){memset(&w->sockets[i],0,sizeof w->sockets[i]);w->sockets[i].used=1;w->sockets[i].peer=-1;return (int)i;}
    return -1;
}
static int net_fd(RyzLinuxProcess *p,unsigned int socket,uint64_t flags)
{
    unsigned int i,id;
    for(i=0;i<p->file_limit;i++)if(!p->fds[i].open)break;
    if(i==p->file_limit)return -24;
    id=new_description(p);if(!id)return -24;
    memset(&p->fds[i],0,sizeof p->fds[i]);p->fds[i].open=1;p->fds[i].mode=2;
    p->fds[i].node=RYZ_NS_SOCKET;p->fds[i].socket=socket;p->fds[i].description=id;
    p->fds[i].cloexec=(flags&02000000)!=0;p->fds[i].nonblock=(flags&04000)!=0;return (int)i;
}
static RyzLinuxSocket *net_socket(RyzLinuxProcess *p,uint64_t fd,int *error)
{
    if(fd>=RYZ_LINUX_FD_MAX || !p->fds[fd].open){*error=-9;return NULL;}
    if(p->fds[fd].node!=RYZ_NS_SOCKET){*error=-88;return NULL;}
    return &p->world->sockets[p->fds[fd].socket];
}
static int net_input(RyzLinuxProcess *p,uint64_t at,uint64_t size,int domain,unsigned char *out,unsigned int *length)
{
    unsigned char *in;unsigned int i;
    if(size<2 || size>128)return -22;
    if(!buffer(p,at,(size_t)size,0,&in))return -14;
    if(in[0]!=domain || in[1])return -97;
    memset(out,0,128);
    if(domain==2){
        if(size<16)return -22;
        memcpy(out,in,8);*length=16;return 0;
    }
    if(domain!=1 || size<3 || in[2]!=0)return -95; /* abstract Unix names only */
    for(i=0;i<(unsigned int)size;i++)out[i]=in[i];
    *length=(unsigned int)size;return 0;
}
static int net_output_check(RyzLinuxProcess *p,uint64_t address,uint64_t length)
{
    unsigned char *size,*out;uint64_t n;
    if(!address)return 0;
    if(!buffer(p,length,4,0,&size) || !buffer(p,length,4,1,&size))return -14;
    n=(uint64_t)size[0]|((uint64_t)size[1]<<8)|((uint64_t)size[2]<<16)|((uint64_t)size[3]<<24);
    if(n>128)n=128;
    return n && !buffer(p,address,(size_t)n,1,&out)?-14:0;
}
static void net_output(RyzLinuxProcess *p,uint64_t address,uint64_t length,const unsigned char *value,unsigned int n)
{
    unsigned char *size,*out;unsigned int count;
    if(!address)return;
    buffer(p,length,4,1,&size);count=(unsigned int)size[0]|((unsigned int)size[1]<<8)|((unsigned int)size[2]<<16)|((unsigned int)size[3]<<24);
    if(count>n)count=n;
    if(count){buffer(p,address,count,1,&out);memcpy(out,value,count);}
    encode(size,n,4);
}
static int net_bound(RyzLinuxWorld *w,int domain,const unsigned char *address,unsigned int length,int skip)
{
    unsigned int i;
    for(i=0;i<RYZ_NET_SOCKETS;i++)if((int)i!=skip && w->sockets[i].used && w->sockets[i].bound && !w->sockets[i].connected && w->sockets[i].domain==domain){
        RyzLinuxSocket *s=&w->sockets[i];
        if(domain==1){if(length==s->local_length && !memcmp(s->local,address,length))return (int)i;}
        else if(!memcmp(s->local+2,address+2,2) && (!s->local[4] || !address[4] || !memcmp(s->local+4,address+4,4)))return (int)i;
    }
    return -1;
}
static int net_autobind(RyzLinuxWorld *w,RyzLinuxSocket *s)
{
    unsigned int attempt,port;
    if(s->domain==1)return 0;
    for(attempt=0;attempt<RYZ_NET_SOCKETS+1;attempt++){
        port=40000+(w->next_port++%20000);s->local[2]=(unsigned char)(port>>8);s->local[3]=(unsigned char)port;
        if(net_bound(w,2,s->local,16,(int)(s-w->sockets))<0){s->bound=1;return 0;}
    }
    return -98;
}
static unsigned int net_poll(RyzLinuxProcess *p,uint64_t fd,unsigned int events)
{
    RyzLinuxSocket *s=&p->world->sockets[p->fds[fd].socket];unsigned int out=0;
    if(s->listening)return s->pending_count?(events&1U):0;
    if(!s->connected)return (events&4U)|16U;
    if(s->external){
        int ready;net_external_fill(p->world,s);ready=net_external_ready(p->world,s);
        if(s->size || s->read_closed || s->external_eof)out|=events&1U;
        if(!s->write_closed && !s->external_error)out|=events&(unsigned int)ready&4U;
        if(s->external_eof)out|=events&8192U;
        if(s->external_hup || (s->read_closed && s->write_closed))out|=16U;
        if(s->external_error)out|=8U;
        return out;
    }
    if(s->size || s->read_closed || s->peer<0 || p->world->sockets[s->peer].write_closed)out|=events&1U;
    if(!s->write_closed && s->peer>=0 && !p->world->sockets[s->peer].read_closed && p->world->sockets[s->peer].size<RYZ_NET_BUFFER)out|=events&4U;
    if(s->peer<0 || (s->read_closed && s->write_closed))out|=16U;
    if((events&8192U) && (s->peer<0 || p->world->sockets[s->peer].write_closed))out|=8192U;
    return out;
}
static int64_t net_io(RyzLinuxProcess *p,uint64_t fd,uint64_t address,uint64_t count,uint64_t flags,int write)
{
    int error=0;RyzLinuxSocket *s=net_socket(p,fd,&error),*peer;unsigned char *bytes;size_t n,i;
    if(!s)return error;
    if(flags & ~(uint64_t)(2|64|16384))return -95;
    if(write && (flags&(2|256)))return -95;
    if(count>RYZ_LINUX_IO_MAX)return -22;
    if(count && !buffer(p,address,(size_t)count,!write,&bytes))return -14;
    if(!s->connected)return write?-32:-107;
    if(write && s->external){
        const RyzNetworkGrant *g=&p->world->network->grants[s->external-1];int64_t result;uint64_t before;int ready;
        if(s->write_closed || s->external_handle<0){if(!(flags&16384))p->generated_signals|=UINT64_C(1)<<12;return -32;}
        if(!count)return 0;
        if(p->world->network_bytes>=4U*1024U*1024U)return -28;
        ready=net_external_ready(p->world,s);
        if((ready&16) && !(ready&4)){if(!(flags&16384))p->generated_signals|=UINT64_C(1)<<12;return -32;}
        if(!(ready&4))return s->external_error?-s->external_error:(p->fds[fd].nonblock || (flags&64)?-11:RYZ_LINUX_BLOCKED);
        n=(size_t)count;if(n>RYZ_NET_BUFFER)n=RYZ_NET_BUFFER;
        if(n>4U*1024U*1024U-p->world->network_bytes)n=(size_t)(4U*1024U*1024U-p->world->network_bytes);
        before=p->world->network_last;result=g->ops->write(g->context,s->external_handle,bytes,n);net_elapsed(p->world,before);
        if(result==-11)return p->fds[fd].nonblock || (flags&64)?-11:RYZ_LINUX_BLOCKED;
        if(result<0){if(result< -4095)p->world->network_failed=1;if(result==-32 && !(flags&16384))p->generated_signals|=UINT64_C(1)<<12;return result>=-4095?result:-5;}
        if((uint64_t)result>n){p->world->network_failed=1;return -5;}
        if(!result)return -5;
        p->world->network_bytes+=(uint64_t)result;return result;
    }
    if(write){
        if(s->write_closed || s->peer<0 || p->world->sockets[s->peer].read_closed){if(!(flags&16384))p->generated_signals|=UINT64_C(1)<<12;return -32;}
        if(!count)return 0;
        peer=&p->world->sockets[s->peer];n=RYZ_NET_BUFFER-peer->size;
        if(!n)return p->fds[fd].nonblock || (flags&64)?-11:RYZ_LINUX_BLOCKED;
        if(p->world->network_bytes>=4U*1024U*1024U)return -28;
        if(n>count)n=(size_t)count;
        if(n>4U*1024U*1024U-p->world->network_bytes)n=(size_t)(4U*1024U*1024U-p->world->network_bytes);
        for(i=0;i<n;i++)peer->bytes[(peer->head+peer->size+i)%RYZ_NET_BUFFER]=bytes[i];
        peer->size+=n;p->world->network_bytes+=n;return (int64_t)n;
    }
    if(!count || s->read_closed)return 0;
    if(s->external){
        if(!s->external_no_fill)net_external_fill(p->world,s);
        if(!s->size){if(s->external_error)return -s->external_error;if(s->external_eof)return 0;return p->fds[fd].nonblock || (flags&64)?-11:RYZ_LINUX_BLOCKED;}
    }
    if(!s->size)return s->peer<0 || p->world->sockets[s->peer].write_closed?0:(p->fds[fd].nonblock || (flags&64)?-11:RYZ_LINUX_BLOCKED);
    n=s->size;if(n>count)n=(size_t)count;
    for(i=0;i<n;i++)bytes[i]=s->bytes[(s->head+i)%RYZ_NET_BUFFER];
    if(!(flags&2)){s->head=(s->head+n)%RYZ_NET_BUFFER;s->size-=n;}
    return (int64_t)n;
}
static int64_t net_message(RyzLinuxProcess *p,const RyzLinuxRegs *r)
{
    unsigned char header[56],vectors[16*16],*in,*ignored;uint64_t n,i,total=0,done=0,at,count,name;
    int receiving=r->rax==47;int64_t result;RyzLinuxSocket *socket=&p->world->sockets[p->fds[r->rdi].socket];
    size_t saved_head,saved_size;
    if(r->rdx & ~(uint64_t)(2|64|16384))return -95;
    if(!receiving && (r->rdx&2))return -95;
    if(!buffer(p,r->rsi,56,0,&in) || (receiving && !buffer(p,r->rsi,56,1,&in)))return -14;
    memcpy(header,in,56);name=word64(header);n=word64(header+24);
    if(!receiving && (name || word64(header+40)))return -95;
    if(receiving && (result=net_output_check(p,name,r->rsi+8)))return result;
    if(n>16)return -90;
    if(n && !buffer(p,word64(header+16),(size_t)n*16,0,&in))return -14;
    if(n)memcpy(vectors,in,(size_t)n*16);
    for(i=0;i<n;i++){
        at=word64(vectors+i*16);count=word64(vectors+i*16+8);
        if(count>RYZ_LINUX_IO_MAX-total)return -90;
        total+=count;if(count && !receiving && !buffer(p,at,(size_t)count,0,&ignored))return -14;
    }
    if(receiving && (r->rdx&2) && socket->external){net_external_fill(p->world,socket);socket->external_no_fill=1;}
    saved_head=socket->head;saved_size=socket->size;
    if(!n){result=net_io(p,r->rdi,0,0,r->rdx,!receiving);if(result<0){socket->external_no_fill=0;return result;}}
    for(i=0;i<n;i++){
        at=word64(vectors+i*16);count=word64(vectors+i*16+8);
        if(!count)continue;
        if(receiving && done && !socket->size)break;
        if(receiving && socket->size && count>socket->size)count=socket->size;
        result=net_io(p,r->rdi,at,count,receiving?(r->rdx&~UINT64_C(2)):r->rdx,!receiving);
        if(result<0){if(!done){socket->external_no_fill=0;return result;}break;}
        done+=(uint64_t)result;if((uint64_t)result<count)break;
    }
    if(receiving && (r->rdx&2)){socket->head=saved_head;socket->size=saved_size;}
    socket->external_no_fill=0;
    if(receiving){
        net_output(p,name,r->rsi+8,socket->remote,socket->remote_length);
        buffer(p,r->rsi,56,1,&in);encode(in+40,0,8);encode(in+48,0,4);
    }
    return (int64_t)done;
}
static int64_t net_call(RyzLinuxProcess *p,const RyzLinuxRegs *r)
{
    RyzLinuxWorld *w=p->world;RyzLinuxSocket *s,*peer;unsigned char address[128],*out;unsigned int length=0,i;int error=0,slot,fd,other;uint64_t flags=0;
    if(r->rax==41 || r->rax==53){
        if(r->rdi!=1 && r->rdi!=2)return -97;
        if((r->rsi & ~(uint64_t)(15|04000|02000000)) || (r->rsi&15)!=1)return -94;
        if(r->rdx && !(r->rdi==2 && r->rdx==6))return -93;
        if(r->rax==53 && r->rdi!=1)return -95;
        if(r->rax==53 && !buffer(p,r->r10,8,1,&out))return -14;
        slot=net_slot(w);if(slot<0)return -23;
        s=&w->sockets[slot];s->domain=(int)r->rdi;s->local[0]=(unsigned char)r->rdi;s->local_length=r->rdi==2?16:2;
        fd=net_fd(p,(unsigned int)slot,r->rsi);if(fd<0){s->used=0;return fd;}
        if(r->rax==41)return fd;
        other=net_slot(w);if(other<0){p->fds[fd].open=0;s->used=0;return -23;}
        peer=&w->sockets[other];peer->domain=1;peer->local[0]=1;peer->local_length=2;
        error=net_fd(p,(unsigned int)other,r->rsi);
        if(error<0){w->descriptions[p->fds[fd].description-1].used=0;p->fds[fd].open=0;s->used=peer->used=0;return error;}
        s->connected=peer->connected=1;s->peer=other;peer->peer=slot;
        memcpy(s->remote,peer->local,2);memcpy(peer->remote,s->local,2);s->remote_length=peer->remote_length=2;
        encode(out,(uint64_t)fd,4);encode(out+4,(uint64_t)error,4);return 0;
    }
    s=net_socket(p,r->rdi,&error);if(!s)return error;
    if(r->rax==49 || r->rax==42){
        error=net_input(p,r->rsi,r->rdx,s->domain,address,&length);if(error)return error;
        if(r->rax==49){
            if(s->domain==2 && address[4]!=0 && address[4]!=127)return -101;
            if(s->domain==2 && !address[4] && (address[5] || address[6] || address[7]))return -101;
            if(s->bound || s->connected)return -22;
            if(net_bound(w,s->domain,address,length,-1)>=0)return -98;
            memcpy(s->local,address,length);s->local_length=length;
            if(s->domain==2 && !address[2] && !address[3])return net_autobind(w,s);
            s->bound=1;return 0;
        }
        if(s->connected)return -106;
        if(s->listening)return -22;
        if(s->domain==2 && !address[4])return -101;
        if(s->domain==2 && w->network){
            unsigned int gi;
            for(gi=0;gi<w->network->count;gi++){
                const RyzNetworkGrant *g=&w->network->grants[gi];int64_t handle;uint64_t before;
                if(memcmp(address+4,g->address,4) || g->port!=((unsigned int)address[2]*256+address[3]))continue;
                if(w->network_busy[gi])return -98;
                if(s->keepalive || s->nodelay)return -95;
                if(!ryz_network_budget(w))return -110;
                if(!s->bound && (error=net_autobind(w,s)))return error;
                before=w->network_last;handle=g->ops->open(g->context);net_elapsed(w,before);
                if(handle<0){if(handle< -4095)w->network_failed=1;return handle>=-4095?handle:-5;}
                s->external=gi+1;s->external_handle=handle;w->network_busy[gi]=1;s->connected=1;
                if(!s->local[4]){s->local[4]=127;s->local[7]=1;}
                memcpy(s->remote,address,length);s->remote_length=length;return p->fds[r->rdi].nonblock?-115:0;
            }
        }
        if(s->domain==2 && address[4]!=127)return -101;
        other=net_bound(w,s->domain,address,length,-1);
        if(other<0 || !w->sockets[other].listening)return -111;
        peer=&w->sockets[other];
        if(peer->pending_count>=peer->backlog)return p->fds[r->rdi].nonblock?-11:RYZ_LINUX_BLOCKED;
        slot=net_slot(w);if(slot<0)return -23;
        if(!s->bound && (error=net_autobind(w,s))){w->sockets[slot].used=0;return error;}
        if(s->domain==2 && !s->local[4]){s->local[4]=127;s->local[7]=1;}
        w->sockets[slot].domain=s->domain;w->sockets[slot].connected=1;w->sockets[slot].peer=(int)(s-w->sockets);
        w->sockets[slot].reuseaddr=peer->reuseaddr;w->sockets[slot].keepalive=peer->keepalive;w->sockets[slot].nodelay=peer->nodelay;
        memcpy(w->sockets[slot].local,address,length);w->sockets[slot].local_length=length;
        memcpy(w->sockets[slot].remote,s->local,s->local_length);w->sockets[slot].remote_length=s->local_length;
        peer->pending[peer->pending_count++]=(unsigned int)slot;
        s->connected=1;s->peer=slot;memcpy(s->remote,address,length);s->remote_length=length;return 0;
    }
    if(r->rax==50){
        if(s->connected)return -22;
        if(!s->bound){if(s->domain==1)return -22;error=net_autobind(w,s);if(error)return error;}
        s->listening=1;s->backlog=(int32_t)r->rsi<0?RYZ_NET_BACKLOG:(r->rsi<RYZ_NET_BACKLOG?(unsigned int)r->rsi:RYZ_NET_BACKLOG);
        if(!s->backlog)s->backlog=1;
        return 0;
    }
    if(r->rax==43 || r->rax==288){
        if(!s->listening)return -22;
        flags=r->rax==288?r->r10:0;if(flags&~(uint64_t)(04000|02000000))return -22;
        error=net_output_check(p,r->rsi,r->rdx);if(error)return error;
        if(!s->pending_count)return p->fds[r->rdi].nonblock?-11:RYZ_LINUX_BLOCKED;
        slot=(int)s->pending[0];fd=net_fd(p,(unsigned int)slot,flags);if(fd<0)return fd;
        peer=&w->sockets[slot];net_output(p,r->rsi,r->rdx,peer->remote,peer->remote_length);
        for(i=1;i<s->pending_count;i++)s->pending[i-1]=s->pending[i];
        s->pending_count--;return fd;
    }
    if(r->rax==51 || r->rax==52){
        if(r->rax==52 && !s->connected)return -107;
        if(!r->rsi)return -14;
        error=net_output_check(p,r->rsi,r->rdx);if(error)return error;
        net_output(p,r->rsi,r->rdx,r->rax==51?s->local:s->remote,r->rax==51?s->local_length:s->remote_length);return 0;
    }
    if(r->rax==48){
        if(r->rsi>2)return -22;
        if(!s->connected)return -107;
        if(s->external && r->rsi==1)return -95;
        if(s->external && r->rsi==2)net_external_close(w,s);
        if(r->rsi!=1){s->read_closed=1;s->size=0;}
        if(r->rsi!=0)s->write_closed=1;
        return 0;
    }
    if(r->rax==46 || r->rax==47)return net_message(p,r);
    if(r->rax==44){if(r->r8)return -106;return net_io(p,r->rdi,r->rsi,r->rdx,r->r10,1);}
    if(r->rax==45){
        error=net_output_check(p,r->r8,r->r9);if(error)return error;
        {int64_t n=net_io(p,r->rdi,r->rsi,r->rdx,r->r10,0);if(n>=0)net_output(p,r->r8,r->r9,s->remote,s->remote_length);return n;}
    }
    if(r->rax==54 || r->rax==55){
        unsigned int option=(unsigned int)r->rdx,value=0,count;
        if(r->rsi!=1 && !(r->rsi==6 && s->domain==2 && option==1))return -92;
        if(r->rax==54){
            if(s->external)return -95;
            if(r->r8<4)return -22;
            if(!buffer(p,r->r10,4,0,&out))return -14;
            value=(unsigned int)out[0]|((unsigned int)out[1]<<8)|((unsigned int)out[2]<<16)|((unsigned int)out[3]<<24);
            if(r->rsi==6)s->nodelay=value!=0;
            else if(option==2)s->reuseaddr=value!=0;
            else if(option==9)s->keepalive=value!=0;
            else return -92;
            return 0;
        }
        if(!buffer(p,r->r8,4,0,&out) || !buffer(p,r->r8,4,1,&out))return -14;
        count=(unsigned int)out[0]|((unsigned int)out[1]<<8)|((unsigned int)out[2]<<16)|((unsigned int)out[3]<<24);
        if(r->rsi==6)value=(unsigned int)s->nodelay;
        else if(option==3)value=1;
        else if(option==4){value=(unsigned int)s->external_error;s->external_error=0;}
        else if(option==30)value=(unsigned int)s->listening;
        else if(option==7 || option==8)value=RYZ_NET_BUFFER;
        else if(option==2)value=(unsigned int)s->reuseaddr;
        else if(option==9)value=(unsigned int)s->keepalive;
        else return -92;
        if(count>4)count=4;
        {unsigned char *value_out=NULL,*length_out=out;
         if(count && !buffer(p,r->r10,count,1,&value_out))return -14;
         if(count)encode(value_out,value,count);
         encode(length_out,count,4);}
        return 0;
    }
    return -38;
}
