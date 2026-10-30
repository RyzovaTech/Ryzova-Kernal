/* SPDX-License-Identifier: AGPL-3.0-only */
/* Live filesystem capabilities. No host pathname is constructed in this core. */
static int resource_find(RyzLinuxWorld *w,const char *path)
{
    size_t i,n;if(!w->resources)return -1;
    for(i=0;i<w->resources->count;i++){n=strlen(w->resources->mounts[i].path);if(!strncmp(path,w->resources->mounts[i].path,n) && (!path[n] || path[n]=='/'))return (int)i;}
    return -1;
}
static const char *resource_relative(RyzLinuxWorld *w,unsigned int i,const char *path)
{const char *p=path+strlen(w->resources->mounts[i].path);return *p=='/'?p+1:p;}
static int resource_rights(RyzLinuxProcess *p,unsigned int i,unsigned int rights)
{
    RyzLinuxWorld *w=p->world;const RyzFsMount *m=&w->resources->mounts[i];unsigned int bit=1U<<i;
    if((w->resource_revoked&bit) || ((rights&1) && !(p->fs_read_mask&bit)) || ((rights&2) && !(p->fs_write_mask&bit)) || (rights & ~m->rights))return -13;
    if(m->allowed && !m->allowed(m->context,rights)){w->resource_revoked|=bit;return -13;}
    return 0;
}
static int64_t resource_call(RyzLinuxProcess *p,unsigned int i,unsigned int rights,RyzFsCall *c)
{
    RyzLinuxWorld *w=p->world;const RyzFsMount *m=&w->resources->mounts[i];int error=resource_rights(p,i,rights);
    if(error)return error;
    if(w->resource_calls>=RYZ_FS_CALLS)return -28;
    w->resource_calls++;return m->call(m->context,c);
}
static void resource_cleanup(RyzLinuxWorld *w)
{
    unsigned int i;RyzFsCall call;
    if(!w->resources)return;
    for(i=0;i<RYZ_WORLD_DESCRIPTIONS;i++)if(w->resource_open[i].used && !w->descriptions[i].refs){
        RyzFsOpen *o=&w->resource_open[i];const RyzFsMount *m=&w->resources->mounts[o->mount];
        memset(&call,0,sizeof call);call.operation=RYZ_FS_CLOSE;call.handle=o->handle;
        m->call(m->context,&call);memset(o,0,sizeof(*o));
    }
}
void ryz_resource_exec_view(RyzLinuxProcess *p,const char *path)
{
    size_t i;const RyzFsResources *r=p->world->resources;if(!r)return;
    for(i=0;i<r->view_count;i++)if(!strcmp(path,r->views[i].executable)){
        p->fs_read_mask &= r->views[i].read_mask;p->fs_write_mask &= r->views[i].write_mask;
    }
}
static int resource_valid_path(const char *path)
{
    size_t i,start=1,n;
    if(!path || path[0]!='/' || !path[1])return 0;
    for(n=0;n<RYZ_NS_PATH_MAX && path[n];n++);
    if(n==RYZ_NS_PATH_MAX || vfs_reserved(path))return 0;
    for(i=1;i<=n;i++)if(!path[i] || path[i]=='/'){
        size_t length=i-start;if(!length || (length==1 && path[start]=='.') || (length==2 && path[start]=='.' && path[start+1]=='.'))return 0;start=i+1;
    }
    return 1;
}
int ryz_resources_install(RyzLinuxWorld *w)
{
    const RyzFsResources *r=w->resources;size_t i,j,n;unsigned int mask,node;char path[RYZ_NS_PATH_MAX],*part,*end;int next;
    if(!r)return 1;
    if(!w->root_tree || !r->count || r->count>RYZ_FS_MOUNTS || !r->mounts || r->view_count>16U || (r->view_count && !r->views))return 0;
    mask=(1U<<r->count)-1;
    for(i=0;i<r->count;i++)if(!resource_valid_path(r->mounts[i].path) || !r->mounts[i].call || !(r->mounts[i].rights&1) || (r->mounts[i].rights&~3U))return 0;
    for(i=0;i<r->count;i++){
        const RyzFsMount *m=&r->mounts[i];
        if(!resource_valid_path(m->path) || !m->call || !(m->rights&1) || (m->rights&~3U))return 0;
        n=strlen(m->path);
        for(j=0;j<r->count;j++)if(i!=j && !strncmp(m->path,r->mounts[j].path,n) && (!r->mounts[j].path[n] || r->mounts[j].path[n]=='/'))return 0;
        for(j=0;j<w->exec_count;j++)if(!strncmp(m->path,w->execs[j].path,n) && (!w->execs[j].path[n] || w->execs[j].path[n]=='/'))return 0;
    }
    for(i=0;i<r->view_count;i++){
        const RyzFsView *v=&r->views[i];int found=!strcmp(v->executable?v->executable:"","@entry");
        if(!v->executable || (v->read_mask&~mask) || (v->write_mask&~v->read_mask))return 0;
        for(j=0;j<w->exec_count;j++)if(!strcmp(v->executable,w->execs[j].path))found=1;
        for(j=0;j<i;j++)if(!strcmp(v->executable,r->views[j].executable))return 0;
        if(!found)return 0;
    }
    vfs_init(w);
    for(i=0;i<r->count;i++){
        memcpy(path,r->mounts[i].path,strlen(r->mounts[i].path)+1);node=0;part=path+1;
        for(;;){
            end=strchr(part,'/');if(end)*end=0;
            next=vfs_child(w,node,part);
            if(next==-2){
                next=vfs_slot(w);if(next<0)return 0;
                {RyzVnode *v=&w->nodes[next];memset(v,0,sizeof(*v));v->used=v->linked=v->directory=1;v->permissions=0700;v->parent=node;v->inode=w->next_inode++;memcpy(v->name,part,strlen(part)+1);}
            }
            if(next<0 || !w->nodes[next].directory)return 0;
            node=(unsigned int)next;if(!end)break;part=end+1;
        }
        w->resource_anchors[i]=node;
    }
    return 1;
}
static int resource_directory(RyzLinuxProcess *p,const char *path,int *handled)
{
    int i=resource_find(p->world,path);RyzFsCall c;int64_t result;*handled=i>=0;if(i<0)return 0;
    memset(&c,0,sizeof c);c.operation=RYZ_FS_STAT;c.handle=-1;c.path=resource_relative(p->world,(unsigned int)i,path);
    result=resource_call(p,(unsigned int)i,1,&c);if(result<0)return (int)result;
    return (c.stat.mode&0170000)!=0040000?-20:((c.stat.mode&0100)?0:-13);
}
static int resource_cwd(RyzLinuxProcess *p,char *out)
{
    int handled,error=resource_directory(p,p->resource_cwd,&handled);
    if(!handled)return -2;
    if(error)return error;
    memcpy(out,p->resource_cwd,strlen(p->resource_cwd)+1);return 0;
}
static int resource_dirfd(RyzLinuxProcess *p,uint64_t fd,char *out)
{
    RyzFsOpen *o=&p->world->resource_open[p->fds[fd].description-1];int error;
    if(!o->directory)return -20;
    error=resource_rights(p,o->mount,1);if(error)return error;
    memcpy(out,o->path,strlen(o->path)+1);return 0;
}
static int resource_visible(RyzLinuxProcess *p,unsigned int node)
{
    size_t i;if(!p->world->resources)return 1;
    for(i=0;i<p->world->resources->count;i++)if(node==p->world->resource_anchors[i])return !resource_rights(p,(unsigned int)i,1);
    return 1;
}
static int64_t resource_stat(RyzLinuxProcess *p,unsigned int i,RyzFsCall *c,uint64_t address)
{
    unsigned char *out;int64_t result=resource_call(p,i,1,c);if(result<0)return result;
    if(c->stat.size>RYZ_LINUX_FILE_MAX)return -27;
    if(!buffer(p,address,144,1,&out))return -14;
    memset(out,0,144);encode(out,((uint64_t)p->ns.namespace_id<<8)|16U|i,8);encode(out+8,c->stat.inode,8);encode(out+16,1,8);
    encode(out+24,c->stat.mode,4);encode(out+28,p->ns.uid,4);encode(out+32,p->ns.gid,4);encode(out+48,c->stat.size,8);encode(out+56,4096,8);encode(out+64,(c->stat.size+511)/512,8);
    encode(out+72,c->stat.mtime,8);encode(out+88,c->stat.mtime,8);encode(out+104,c->stat.mtime,8);return 0;
}
static int64_t resource_io_at(RyzLinuxProcess *p,uint64_t fd,uint64_t address,uint64_t count,int write,uint64_t offset,int positioned)
{
    RyzLinuxFD *f=&p->fds[fd];RyzFsOpen *o=&p->world->resource_open[f->description-1];RyzFsCall c;int64_t n;unsigned char *data;
    if((write && f->mode==0) || (!write && f->mode==1))return -9;
    if(o->directory)return -21;
    if(count>RYZ_LINUX_IO_MAX)return -22;
    if(!buffer(p,address,(size_t)count,!write,&data))return -14;
    memset(&c,0,sizeof c);c.handle=o->handle;c.path=resource_relative(p->world,o->mount,o->path);
    if(write && f->append){c.operation=RYZ_FS_STAT;n=resource_call(p,o->mount,2,&c);if(n<0)return n;offset=c.stat.size;}
    if(write && (offset>RYZ_LINUX_FILE_MAX || count>RYZ_LINUX_FILE_MAX-offset))return -27;
    if(!write && offset>(UINT64_MAX>>1))return -22;
    if(count>RYZ_FS_TRAFFIC-p->world->resource_bytes)return -28;
    c.operation=write?RYZ_FS_WRITE_OP:RYZ_FS_READ_OP;c.bytes=data;c.size=(size_t)count;c.offset=offset;
    n=resource_call(p,o->mount,write?2:1,&c);if(n<0)return n;if((uint64_t)n>count)return -5;
    p->world->resource_bytes+=(uint64_t)n;if(!positioned)set_offset(p,fd,(size_t)(offset+(uint64_t)n));return n;
}
static int64_t resource_io(RyzLinuxProcess *p,uint64_t fd,uint64_t address,uint64_t count,int write)
{return resource_io_at(p,fd,address,count,write,p->fds[fd].offset,0);}
static int64_t resource_dents(RyzLinuxProcess *p,uint64_t fd,uint64_t address,uint64_t count)
{
    RyzLinuxFD *f=&p->fds[fd];RyzFsOpen *o=&p->world->resource_open[f->description-1];RyzFsCall c;unsigned char *out;size_t used=0,n,record,cursor=f->offset;int64_t result;
    if(!o->directory)return -20;
    if(count>RYZ_LINUX_IO_MAX)return -22;
    if(!buffer(p,address,(size_t)count,1,&out))return -14;
    while(cursor<=RYZ_VFS_NODES+2){
        memset(&c,0,sizeof c);c.handle=o->handle;c.path=resource_relative(p->world,o->mount,o->path);
        if(cursor<2){
            char parent[RYZ_NS_PATH_MAX];
            c.operation=RYZ_FS_STAT;
            if(cursor==1 && c.path[0]){
                char *slash;memcpy(parent,c.path,strlen(c.path)+1);slash=strrchr(parent,'/');if(slash)*slash=0;else parent[0]=0;
                c.path=parent;c.handle=-1;
            }
            result=resource_call(p,o->mount,1,&c);if(result<0)return result;
            if(cursor==1 && !resource_relative(p->world,o->mount,o->path)[0])c.stat.inode=p->world->nodes[p->world->nodes[p->world->resource_anchors[o->mount]].parent].inode;
            memcpy(c.name,cursor?"..":".",cursor?3:2);
        }
        else{c.operation=RYZ_FS_LIST;c.offset=cursor-2;result=resource_call(p,o->mount,1,&c);if(result<0)return used?(int64_t)used:result;if(!result)break;if(cursor>=RYZ_VFS_NODES+2)return -75;}
        for(n=0;n<sizeof c.name && c.name[n];n++)if(c.name[n]=='/')return -5;
        if(!n || n==sizeof c.name)return -5;
        n++;record=(19+n+7)&~(size_t)7;if(record>count-used){if(!used)return -22;break;}
        memset(out+used,0,record);encode(out+used,c.stat.inode,8);encode(out+used+8,cursor+1,8);encode(out+used+16,record,2);out[used+18]=(c.stat.mode&0040000)?4:8;memcpy(out+used+19,c.name,n);used+=record;cursor++;
    }
    set_offset(p,fd,cursor);return (int64_t)used;
}
static int resource_ancestor(RyzLinuxWorld *w,const char *path)
{
    size_t i,n=strlen(path);for(i=0;i<w->resources->count;i++)if(!strncmp(path,w->resources->mounts[i].path,n) && w->resources->mounts[i].path[n]=='/')return 1;return 0;
}
static int64_t resource_dispatch(RyzLinuxProcess *p,const RyzLinuxRegs *r,int *handled)
{
    RyzLinuxWorld *w=p->world;RyzFsCall c;RyzFsOpen *o;RyzLinuxFD *f;uint64_t nr=r->rax,fd=r->rdi,address=r->rdi,dirfd=L_AT_FDCWD,flags=r->rsi,mode=r->rdx;char path[RYZ_NS_PATH_MAX],other[RYZ_NS_PATH_MAX];int i,j,trailing,error,follow=1;unsigned int k,id,rights,creating=0;int64_t result;
    *handled=0;if(!w->resources)return 0;
    if(nr==157 && r->rdi==RYZ_FS_RESTRICT){*handled=1;if(r->r10 || r->r8 || (r->rsi&~((1U<<w->resources->count)-1)) || r->rdx>15 || (r->rdx&~r->rsi) || (r->rsi&~p->fs_read_mask) || (r->rdx&~p->fs_write_mask))return -1;p->fs_read_mask=(unsigned int)r->rsi;p->fs_write_mask=(unsigned int)r->rdx;return 0;}
    if(fd<RYZ_LINUX_FD_MAX && p->fds[fd].open && p->fds[fd].node==RYZ_NS_RESOURCE){
        f=&p->fds[fd];o=&w->resource_open[f->description-1];memset(&c,0,sizeof c);c.handle=o->handle;c.path=resource_relative(w,o->mount,o->path);
        switch(nr){case 0:case 1:case 5:case 8:case 17:case 18:case 74:case 75:case 77:case 81:case 91:case 217:break;default:goto resource_paths;}
        *handled=1;error=resource_rights(p,o->mount,1);if(error)return error;
        if(nr==0 || nr==1)return resource_io(p,fd,r->rsi,r->rdx,nr==1);
        if(nr==17 || nr==18)return resource_io_at(p,fd,r->rsi,r->rdx,nr==18,r->r10,1);
        if(nr==217)return resource_dents(p,fd,r->rsi,r->rdx);
        if(nr==5){c.operation=RYZ_FS_STAT;return resource_stat(p,o->mount,&c,r->rsi);}
        if(nr==81){if(!o->directory)return -20;memcpy(p->resource_cwd,o->path,strlen(o->path)+1);return 0;}
        if(nr==8){uint64_t base=0,offset;
            if(r->rdx>2)return -22;
            if(r->rdx==1)base=f->offset;
            if(r->rdx==2){c.operation=RYZ_FS_STAT;result=resource_call(p,o->mount,1,&c);if(result<0)return result;base=c.stat.size;}
            if(r->rsi>>63){offset=-r->rsi;if(offset>base)return -22;offset=base-offset;}else{if(r->rsi>RYZ_LINUX_FILE_MAX || base>RYZ_LINUX_FILE_MAX-r->rsi)return -22;offset=base+r->rsi;}
            set_offset(p,fd,(size_t)offset);return (int64_t)offset;
        }
        if(nr==77 && (f->mode==0 || r->rsi>RYZ_LINUX_FILE_MAX))return f->mode==0?-22:-27;
        c.operation=nr==77?RYZ_FS_TRUNCATE:(nr==91?RYZ_FS_CHMOD:RYZ_FS_SYNC);c.offset=r->rsi;c.mode=(unsigned int)r->rsi&0777;
        return resource_call(p,o->mount,nr==74 || nr==75?1:2,&c);
    }
 resource_paths:
    switch(nr){
    case 2:case 4:case 6:case 21:case 76:case 80:case 82:case 83:case 84:case 86:case 87:case 88:case 89:case 90:break;
    case 257:dirfd=r->rdi;address=r->rsi;flags=r->rdx;mode=r->r10;break;
    case 258:case 262:case 263:case 267:dirfd=r->rdi;address=r->rsi;mode=r->rdx;break;
    case 265:dirfd=r->rdi;address=r->rsi;break;
    case 266:dirfd=r->rsi;address=r->rdx;break;
    case 280:if(!r->rsi)return 0;dirfd=r->rdi;address=r->rsi;break;
    default:return 0;
    }
    if(nr==88)address=r->rsi;
    if(nr==6 || nr==82 || nr==84 || nr==86 || nr==87 || nr==88 || nr==89 || nr==263 || nr==266 || nr==267 || (nr==262 && (r->r10&256)) || (nr==265 && !(r->r8&1024)) || ((nr==2 || nr==257) && ((flags&0400000) || (flags&0300)==0300)))follow=0;
    if(nr==82 || nr==84 || nr==87 || nr==263)follow=-1;
    if(nr==83 || nr==258 || nr==88 || nr==266)follow=-2;
    error=ryz_linux_path(p,dirfd,address,path,follow,&trailing);if(error){*handled=1;return error;}
    i=resource_find(w,path);
    if(nr==82 || nr==86 || nr==265){
        error=ryz_linux_path(p,nr==265?r->rdx:L_AT_FDCWD,nr==265?r->r10:r->rsi,other,nr==82?-1:0,&trailing);if(error){*handled=1;return error;}
        j=resource_find(w,other);
        if(i<0 && j<0){if(nr==82 && (resource_ancestor(w,path) || resource_ancestor(w,other))){*handled=1;return -16;}return 0;}
        *handled=1;if(i<0 || i!=j)return -18;if(nr!=82)return -95;
        if(!strcmp(path,w->resources->mounts[i].path) || !strcmp(other,w->resources->mounts[i].path))return -16;
        memset(&c,0,sizeof c);c.handle=-1;c.operation=RYZ_FS_RENAME;c.path=resource_relative(w,(unsigned int)i,path);c.other=resource_relative(w,(unsigned int)i,other);return resource_call(p,(unsigned int)i,2,&c);
    }
    if(i<0){if((nr==84 || nr==87 || nr==263) && resource_ancestor(w,path)){*handled=1;return -16;}return 0;}
    *handled=1;memset(&c,0,sizeof c);c.handle=-1;c.path=resource_relative(w,(unsigned int)i,path);
    if(nr==4 || nr==6 || nr==262){if(nr==262 && (r->r10&~UINT64_C(256)))return -22;c.operation=RYZ_FS_STAT;return resource_stat(p,(unsigned int)i,&c,nr==262?r->rdx:r->rsi);}
    if(nr==80){error=resource_directory(p,path,&j);if(error)return error;memcpy(p->resource_cwd,path,strlen(path)+1);return 0;}
    if(nr==21){if(r->rsi&~UINT64_C(7))return -22;if(r->rsi&1)return -13;return resource_rights(p,(unsigned int)i,(r->rsi&2)?3:1);}
    if(nr==2 || nr==257){
        if((flags&01000) && !(flags&3))return -22;
        if(flags & ~(uint64_t)(3|0100|0200|01000|02000|04000|0100000|0200000|0400000|02000000) || (flags&3)==3)return -22;
        rights=(flags&3) || (flags&(0100|01000))?3:1;error=resource_rights(p,(unsigned int)i,rights);if(error)return error;
        for(k=0;k<RYZ_LINUX_FD_MAX && p->fds[k].open;k++);
        if(k==RYZ_LINUX_FD_MAX)return -24;
        if(flags&0100){
            c.operation=RYZ_FS_STAT;result=resource_call(p,(unsigned int)i,rights,&c);
            if(result==-2){if(w->resource_creates>=RYZ_VFS_NODES)return -28;creating=1;}
            else if(result<0)return result;
        }
        id=new_description(p);if(!id)return -24;c.operation=RYZ_FS_OPEN;c.flags=(unsigned int)flags;c.mode=(unsigned int)mode&~p->file_umask&0777;
        result=resource_call(p,(unsigned int)i,rights,&c);if(result<0){w->descriptions[id-1].used=0;return result;}
        if(creating)w->resource_creates++;
        o=&w->resource_open[id-1];o->used=1;o->mount=(unsigned int)i;o->handle=result;o->directory=(c.stat.mode&0170000)==0040000;memcpy(o->path,path,strlen(path)+1);
        f=&p->fds[k];memset(f,0,sizeof(*f));f->open=1;f->node=RYZ_NS_RESOURCE;f->description=id;f->mode=(int)(flags&3);f->append=(flags&02000)!=0;f->cloexec=(flags&02000000)!=0;return k;
    }
    if(!c.path[0] && (nr==84 || nr==87 || nr==263))return -16;
    if(nr==76 && r->rsi>RYZ_LINUX_FILE_MAX)return -27;
    if(nr==263 && (r->rdx&~UINT64_C(512)))return -22;
    c.operation=nr==83 || nr==258?RYZ_FS_MKDIR:(nr==84 || (nr==263 && r->rdx==512)?RYZ_FS_RMDIR:(nr==87 || nr==263?RYZ_FS_UNLINK:(nr==90?RYZ_FS_CHMOD:(nr==76?RYZ_FS_TRUNCATE:0))));
    if(!c.operation)return -95;
    c.mode=(unsigned int)(nr==83 || nr==90?r->rsi:mode)&0777;if(c.operation==RYZ_FS_MKDIR)c.mode &= ~p->file_umask;c.offset=r->rsi;
    if(c.operation==RYZ_FS_MKDIR && w->resource_creates>=RYZ_VFS_NODES)return -28;
    result=resource_call(p,(unsigned int)i,2,&c);
    if(!result && c.operation==RYZ_FS_MKDIR)w->resource_creates++;
    return result;
}
