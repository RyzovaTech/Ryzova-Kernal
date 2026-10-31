/* SPDX-License-Identifier: AGPL-3.0-only */
/* Internal syscall implementation: invocation-local guest tree, never host paths.
 * Kept in this translation unit so all existing portable ABI consumers use it. */
#include "filesystem_tree.h"
static unsigned int vfs_nlink(RyzLinuxWorld *w,unsigned int index)
{
    unsigned int i,count=0;index=RYZ_VFS_INDEX(w,index);
    for(i=0;i<RYZ_VFS_NODES;i++)if(w->nodes[i].used && w->nodes[i].linked && RYZ_VFS_INDEX(w,i)==index)count++;
    return count;
}
static void vfs_stamp(RyzLinuxProcess *p,RyzVnode *node,int data)
{
    uint64_t now=RYZ_TICK(p->world);
    node->ctime=now/1000000;node->ctime_ns=(now%1000000)*1000;
    if(data){node->mtime=node->ctime;node->mtime_ns=node->ctime_ns;}
}
static int vfs_child(RyzLinuxWorld *w,unsigned int parent,const char *name)
{
    unsigned int i;
    for(i=1;i<RYZ_VFS_NODES;i++)if(w->nodes[i].used && w->nodes[i].linked &&
        w->nodes[i].parent==parent && strcmp(w->nodes[i].name,name)==0)return (int)i;
    return -2;
}
static int vfs_lookup(RyzLinuxWorld *w,const char *path)
{
    unsigned int node=0;size_t at=4,n;char name[RYZ_NS_PATH_MAX];int next;
    if(w->root_tree){
        if(vfs_reserved(path))return -10000;
        if(!strcmp(path,"/"))return 0;
        if(path[0]!='/')return -10000;
        at=0;
    }else{
        if(strcmp(path,"/tmp")==0)return 0;
        if(strncmp(path,"/tmp/",5)!=0)return -10000;
    }
    while(path[at]){
        at++;n=0;while(path[at] && path[at]!='/')name[n++]=path[at++];name[n]=0;
        if(!w->nodes[node].directory)return -20;
        next=vfs_child(w,node,name);if(next<0)return next;node=(unsigned int)next;
    }
    return (int)node;
}
static int resource_directory(RyzLinuxProcess *,const char *,int *);
static int resource_cwd(RyzLinuxProcess *,char *);
static int resource_dirfd(RyzLinuxProcess *,uint64_t,char *);
static int resource_visible(RyzLinuxProcess *,unsigned int);
static int vfs_node_path(RyzLinuxWorld *w,unsigned int node,char *out)
{
    unsigned int chain[RYZ_VFS_NODES],count=0;size_t n,k;
    while(node){
        if(count>=RYZ_VFS_NODES || !w->nodes[node].linked)return -2;
        chain[count++]=node;node=w->nodes[node].parent;
    }
    if(w->root_tree){memcpy(out,"/",2);n=1;}else{memcpy(out,"/tmp",5);n=4;}
    while(count){
        node=chain[--count];k=strlen(w->nodes[node].name);
        if(n+k+(n>1?1:0)+1>RYZ_NS_PATH_MAX)return -36;
        if(n>1)out[n++]='/';
        memcpy(out+n,w->nodes[node].name,k+1);n+=k;
    }
    return 0;
}
static int vfs_cwd(RyzLinuxProcess *p,char *out)
{
    if(p->resource_cwd[0])return resource_cwd(p,out);
    if(!p->vfs_cwd){
        const char *cwd=p->cwd==RYZ_NS_TMP?"/tmp":(p->cwd==RYZ_NS_PROC_SELF?"/proc/self":"/");
        memcpy(out,cwd,strlen(cwd)+1);return 0;
    }
    return vfs_node_path(p->world,p->vfs_cwd-1,out);
}
/* Only guest namespace directories are traversed. A link is a path string,
 * never authority to resolve a host path or acquire a new resource grant. */
static int vfs_directory(RyzLinuxProcess *p,const char *path)
{
    int node=vfs_lookup(p->world,path);size_t i,n=strlen(path);
    {int handled,answer=resource_directory(p,path,&handled);if(handled)return answer;}
    for(i=0;i<p->world->exec_count;i++)if(!strcmp(path,p->world->execs[i].path))return -20;
    if(node>=0){
        if(!p->world->nodes[node].directory)return -20;
        return p->world->nodes[node].permissions & 0100?0:-13;
    }
    if(!strcmp(path,"/") || !strcmp(path,"/dev") || !strcmp(path,"/proc") || !strcmp(path,"/proc/self"))return 0;
    for(i=0;i<p->world->exec_count;i++)if(!strncmp(path,p->world->execs[i].path,n) && p->world->execs[i].path[n]=='/')return 0;
    return node==-10000?-2:node;
}
static int vfs_normalize(RyzLinuxProcess *p,uint64_t dirfd,const char *source,char *out,int follow,int *trailing)
{
    char pending[RYZ_NS_PATH_MAX],part[RYZ_NS_PATH_MAX],expanded[RYZ_NS_PATH_MAX];
    size_t length=strlen(source),i=0,n,k,parent,rest,target;int code,node,links=0;
    if(!length)return -2;
    if(length>=RYZ_NS_PATH_MAX)return -36;
    memcpy(pending,source,length+1);*trailing=length>1 && source[length-1]=='/';
    if(source[0]=='/'){out[0]='/';out[1]=0;}
    else if(dirfd==L_AT_FDCWD){code=vfs_cwd(p,out);if(code)return code;}
    else{
        if(dirfd<RYZ_LINUX_FD_MAX && p->fds[dirfd].open && p->fds[dirfd].node==RYZ_NS_RESOURCE){code=resource_dirfd(p,dirfd,out);if(code)return code;goto relative_ready;}
        if(dirfd>=RYZ_LINUX_FD_MAX || !p->fds[dirfd].open)return -9;
        if(p->fds[dirfd].node!=RYZ_NS_VFS || !p->world->nodes[p->fds[dirfd].vnode].directory)return -20;
        code=vfs_node_path(p->world,p->fds[dirfd].vnode,out);if(code)return code;
    }
 relative_ready:
    n=strlen(out);
    while(pending[i]){
        while(pending[i]=='/')i++;
        if(!pending[i])break;
        code=vfs_directory(p,out);if(code)return code;
        k=0;while(pending[i] && pending[i]!='/')part[k++]=pending[i++];part[k]=0;
        if(!strcmp(part,"."))continue;
        if(!strcmp(part,"..")){while(n>1 && out[n-1]!='/')n--;if(n>1)n--;out[n]=0;continue;}
        parent=n;
        if(n+k+(n>1?1:0)+1>RYZ_NS_PATH_MAX)return -36;
        if(n>1)out[n++]='/';
        memcpy(out+n,part,k+1);n+=k;
        node=vfs_lookup(p->world,out);
        {size_t grant;for(grant=0;grant<p->world->exec_count;grant++)if(!strcmp(out,p->world->execs[grant].path)){node=-10000;break;}}
        if(node>=0 && RYZ_VFS_NODE(p->world,node)->symlink && (follow>0 || pending[i] || *trailing)){
            RyzVnode *link=RYZ_VFS_NODE(p->world,node);
            rest=i;while(pending[rest]=='/')rest++;
            if(follow<0 && !pending[rest])return follow==-2?-17:-20;
            if(++links>40)return -40;
            target=link->size;rest=strlen(pending+i);
            if(!target)return -2;
            if(target+rest+1>sizeof expanded)return -36;
            memcpy(expanded,link->bytes,target);memcpy(expanded+target,pending+i,rest+1);
            if(!rest && expanded[target-1]=='/')*trailing=1;
            if(expanded[0]=='/'){out[0]='/';out[1]=0;n=1;}
            else{n=parent;out[n]=0;}
            memcpy(pending,expanded,target+rest+1);i=0;
        }
    }
    if(*trailing){code=vfs_directory(p,out);if(code && code!=-2)return code;}
    return 0;
}
int ryz_linux_path(RyzLinuxProcess *p,uint64_t dirfd,uint64_t address,char *out,int follow,int *trailing)
{
    const char *path;size_t length;int code;
    /* Exec reaches this resolver without the ordinary syscall state pull. */
    world_pull(p);code=guest_path(p,address,&path,&length);
    if(code)return code;
    vfs_init(p->world);return vfs_normalize(p,dirfd,path,out,follow,trailing);
}
static int vfs_parent(RyzLinuxWorld *w,char *path,char **name)
{
    size_t n=strlen(path);int parent;
    while(n && path[n-1]!='/')n--;
    if(n<=1){
        if(!w->root_tree || n!=1 || !path[1] || vfs_reserved(path))return -13;
        *name=path+1;parent=0;
    }else{path[n-1]=0;*name=path+n;parent=vfs_lookup(w,path);}
    if(parent<0)return parent==-10000?-13:parent;
    if(!w->nodes[parent].directory)return -20;
    if((w->nodes[parent].permissions & 0300)!=0300)return -13;
    return parent;
}
static int vfs_slot(RyzLinuxWorld *w)
{
    unsigned int i,j;int held;
    for(i=1;i<RYZ_VFS_NODES;i++){
        if(!w->nodes[i].used)return (int)i;
        if(w->nodes[i].linked || w->nodes[i].directory)continue;
        if(w->nodes[i].backing)return (int)i;
        if(vfs_nlink(w,i) || w->mapped_nodes[i])continue;
        held=0;
        for(j=0;j<RYZ_WORLD_DESCRIPTIONS;j++)if(w->descriptions[j].used && w->descriptions[j].refs &&
            w->descriptions[j].fd.node==RYZ_NS_VFS && w->descriptions[j].fd.vnode==i)held=1;
        if(!held)return (int)i;
    }
    return -28;
}
static int vfs_create(RyzLinuxProcess *p,char *path,int directory,unsigned int mode)
{
    char *name;int parent,slot;RyzVnode *node;
    parent=vfs_parent(p->world,path,&name);if(parent<0)return parent;
    slot=vfs_slot(p->world);if(slot<0)return slot;
    node=&p->world->nodes[slot];memset(node,0,sizeof(*node));
    node->used=node->linked=1;node->directory=directory;node->parent=(unsigned int)parent;
    vfs_stamp(p,node,1);node->atime=node->mtime;node->atime_ns=node->mtime_ns;
    node->permissions=mode & ~p->file_umask & 0777;node->inode=p->world->next_inode++;
    memcpy(node->name,name,strlen(name)+1);return slot;
}
static int64_t vfs_write(RyzLinuxProcess *p,uint64_t fd,uint64_t address,uint64_t count)
{
    RyzLinuxFD *f=&p->fds[fd];RyzVnode *node=RYZ_VFS_NODE(p->world,f->vnode);
    unsigned char *bytes;size_t at=f->append?node->size:f->offset;
    if(node->directory)return -21;
    if(f->mode==0)return -9;
    if(count>RYZ_LINUX_IO_MAX)return -22;
    if(!buffer(p,address,(size_t)count,0,&bytes))return -14;
    if(at>RYZ_LINUX_FILE_MAX || count>RYZ_LINUX_FILE_MAX-at)return -28;
    if(count){
        if(at>node->size)memset(node->bytes+node->size,0,at-node->size);
        memcpy(node->bytes+at,bytes,(size_t)count);
        if(at+count>node->size)node->size=at+(size_t)count;
        vfs_stamp(p,node,1);
    }
    set_offset(p,fd,at+(size_t)count);return (int64_t)count;
}
static int64_t vfs_stat(RyzLinuxProcess *p,unsigned int index,uint64_t destination)
{
    unsigned char *out;RyzVnode *node=RYZ_VFS_NODE(p->world,index);
    if(!buffer(p,destination,144,1,&out))return -14;
    memset(out,0,144);encode(out,p->ns.namespace_id,8);encode(out+8,node->inode,8);
    encode(out+16,vfs_nlink(p->world,index),8);encode(out+24,(node->directory?0040000:(node->symlink?0120000:0100000))|node->permissions,4);
    encode(out+28,p->ns.uid,4);encode(out+32,p->ns.gid,4);encode(out+48,node->size,8);
    encode(out+56,4096,8);encode(out+64,(node->size+511)/512,8);
    encode(out+72,node->atime,8);encode(out+80,node->atime_ns,8);
    encode(out+88,node->mtime,8);encode(out+96,node->mtime_ns,8);encode(out+104,node->ctime,8);encode(out+112,node->ctime_ns,8);return 0;
}
static int64_t vfs_getdents(RyzLinuxProcess *p,uint64_t fd,uint64_t address,uint64_t count)
{
    RyzLinuxFD *f=&p->fds[fd];RyzVnode *node=&p->world->nodes[f->vnode],*entry;
    unsigned char *out;size_t used=0,cursor=f->offset,n,record;const char *name;uint64_t ino;
    if(!node->directory)return -20;
    if(count>RYZ_LINUX_IO_MAX)return -22;
    if(!buffer(p,address,(size_t)count,1,&out))return -14;
    while(cursor<RYZ_VFS_NODES+2){
        entry=node;
        if(cursor==0){name=".";ino=node->inode;}
        else if(cursor==1){name="..";ino=f->vnode?p->world->nodes[node->parent].inode:(p->world->root_tree?node->inode:RYZ_NS_ROOT+1);}
        else{
            entry=&p->world->nodes[cursor-2];
            if(cursor==2 || !entry->used || !entry->linked || entry->parent!=f->vnode){cursor++;continue;}
            if(!resource_visible(p,(unsigned int)(cursor-2))){cursor++;continue;}
            name=entry->name;entry=RYZ_VFS_NODE(p->world,cursor-2);ino=entry->inode;
        }
        n=strlen(name)+1;record=(19+n+7)&~(size_t)7;
        if(record>count-used){if(!used)return -22;break;}
        memset(out+used,0,record);encode(out+used,ino,8);encode(out+used+8,cursor+1,8);
        encode(out+used+16,record,2);out[used+18]=entry->directory?4:(entry->symlink?10:8);
        memcpy(out+used+19,name,n);used+=record;cursor++;
    }
    set_offset(p,fd,cursor);return (int64_t)used;
}
static int64_t vfs_link(RyzLinuxProcess *p,const RyzLinuxRegs *r)
{
    uint64_t olddir=r->rax==86?L_AT_FDCWD:r->rdi,oldpath=r->rax==86?r->rdi:r->rsi;
    uint64_t newdir=r->rax==86?L_AT_FDCWD:r->rdx,newpath=r->rax==86?r->rsi:r->r10;
    char old[RYZ_NS_PATH_MAX],path[RYZ_NS_PATH_MAX],*name;int trailing,code,index,parent,slot,target;size_t i;
    RyzVnode *entry,*node;
    if(r->rax==265 && (r->r8 & ~UINT64_C(1024)))return -22;
    code=ryz_linux_path(p,olddir,oldpath,old,r->rax==265 && (r->r8 & 1024)?1:0,&trailing);if(code)return code;
    for(i=0;i<p->world->exec_count;i++)if(!strcmp(old,p->world->execs[i].path))return -13;
    index=vfs_lookup(p->world,old);if(index<0)return index==-10000?-18:index;
    node=RYZ_VFS_NODE(p->world,index);if(node->directory)return -1;
    code=ryz_linux_path(p,newdir,newpath,path,-2,&trailing);if(code)return code;
    for(i=0;i<p->world->exec_count;i++)if(!strcmp(path,p->world->execs[i].path))return -13;
    target=vfs_lookup(p->world,path);if(target>=0)return -17;
    if(target!=-2)return target==-10000?-18:target;
    if(trailing)return -2;
    parent=vfs_parent(p->world,path,&name);if(parent<0)return parent;
    slot=vfs_slot(p->world);if(slot<0)return slot;
    entry=&p->world->nodes[slot];memset(entry,0,sizeof(*entry));entry->used=entry->linked=1;
    entry->parent=(unsigned int)parent;entry->backing=RYZ_VFS_INDEX(p->world,index)+1;
    memcpy(entry->name,name,strlen(name)+1);vfs_stamp(p,node,0);return 0;
}
static int64_t vfs_dispatch(RyzLinuxProcess *p,const RyzLinuxRegs *r,int *handled)
{
    uint64_t nr=r->rax,dirfd=L_AT_FDCWD,address=r->rdi,flags=0,mode=r->rdx,fd=r->rdi;
    char path[RYZ_NS_PATH_MAX],other[RYZ_NS_PATH_MAX],*name;int code,index,trailing,parent,target,slot,follow=1;
    unsigned int i,id;RyzLinuxFD *f=NULL;RyzVnode *node;unsigned char *bytes;
    *handled=1;vfs_init(p->world);
    if(nr==86 || nr==265)return vfs_link(p,r);
    if(nr==228 || nr==229 || nr==201){
        uint64_t now;
        if(nr!=201 && r->rdi!=0 && r->rdi!=1 && r->rdi!=7)return -22;
        now=RYZ_TICK(p->world);
        if(nr==201){
            if(r->rdi){if(!buffer(p,r->rdi,8,1,&bytes))return -14;encode(bytes,now/1000000,8);}
            return (int64_t)(now/1000000);
        }
        if(!r->rsi && nr==229)return 0;
        if(!buffer(p,r->rsi,16,1,&bytes))return -14;
        encode(bytes,nr==229?0:now/1000000,8);encode(bytes+8,nr==229?1000:(now%1000000)*1000,8);return 0;
    }
    if(nr==280){
        uint64_t times[4],now;unsigned int k;
        if(r->r10 & ~UINT64_C(256))return -22;
        if(!r->rsi){
            if(r->rdi>=RYZ_LINUX_FD_MAX || !p->fds[r->rdi].open)return -9;
            if(p->fds[r->rdi].node!=RYZ_NS_VFS)return -13;
            index=(int)p->fds[r->rdi].vnode;
        }else{
            code=ryz_linux_path(p,r->rdi,r->rsi,path,!(r->r10 & 256),&trailing);if(code)return code;
            for(i=0;i<p->world->exec_count;i++)if(!strcmp(path,p->world->execs[i].path))return -13;
            index=vfs_lookup(p->world,path);if(index<0)return index==-10000?-13:index;
            if(trailing && !p->world->nodes[index].directory)return -20;
        }
        if(r->rdx){
            if(!buffer(p,r->rdx,32,0,&bytes))return -14;
            for(k=0;k<4;k++)times[k]=word64(bytes+k*8);
            for(k=1;k<4;k+=2)if(times[k]>=1000000000 && times[k]!=1073741822 && times[k]!=1073741823)return -22;
        }else{times[0]=times[2]=0;times[1]=times[3]=1073741823;}
        if(times[1]==1073741822 && times[3]==1073741822)return 0;
        node=RYZ_VFS_NODE(p->world,index);now=RYZ_TICK(p->world);
        if(times[1]!=1073741822){node->atime=times[1]==1073741823?now/1000000:times[0];node->atime_ns=times[1]==1073741823?(now%1000000)*1000:times[1];}
        if(times[3]!=1073741822){node->mtime=times[3]==1073741823?now/1000000:times[2];node->mtime_ns=times[3]==1073741823?(now%1000000)*1000:times[3];}
        node->ctime=now/1000000;node->ctime_ns=(now%1000000)*1000;return 0;
    }
    if(nr==95){unsigned int old=p->file_umask;p->file_umask=(unsigned int)r->rdi & 0777;return old;}
    if(nr==79){
        code=vfs_cwd(p,path);if(code)return code;
        if(!r->rsi)return -22;
        if(r->rsi<strlen(path)+1)return -34;
        if(!buffer(p,r->rdi,strlen(path)+1,1,&bytes))return -14;
        memcpy(bytes,path,strlen(path)+1);return (int64_t)strlen(path)+1;
    }
    if(fd<RYZ_LINUX_FD_MAX && p->fds[fd].open && p->fds[fd].node==RYZ_NS_VFS)f=&p->fds[fd];
    if(nr==0 || nr==1 || nr==5 || nr==8 || nr==74 || nr==75 || nr==77 || nr==81 || nr==91 || nr==217){
        if(!f){*handled=0;return 0;}
        node=RYZ_VFS_NODE(p->world,f->vnode);
        if(nr==1)return vfs_write(p,fd,r->rsi,r->rdx);
        if(nr==0){
            size_t n;
            if(node->directory)return -21;
            if(f->mode==1)return -9;
            if(r->rdx>RYZ_LINUX_IO_MAX)return -22;
            if(!buffer(p,r->rsi,(size_t)r->rdx,1,&bytes))return -14;
            n=f->offset>=node->size?0:node->size-f->offset;if(n>r->rdx)n=(size_t)r->rdx;
            if(n)memcpy(bytes,node->bytes+f->offset,n);
            set_offset(p,fd,f->offset+n);return (int64_t)n;
        }
        if(nr==5)return vfs_stat(p,f->vnode,r->rsi);
        if(nr==217)return vfs_getdents(p,fd,r->rsi,r->rdx);
        if(nr==74 || nr==75)return 0;
        if(nr==81){if(!node->directory)return -20;if(!(node->permissions & 0100))return -13;p->resource_cwd[0]=0;p->vfs_cwd=f->vnode+1;return 0;}
        if(nr==91){node->permissions=(unsigned int)r->rsi & 0777;vfs_stamp(p,node,0);return 0;}
        if(nr==77){
            if(node->directory)return -21;
            if(f->mode==0)return -22;
            if(r->rsi>RYZ_LINUX_FILE_MAX)return -27;
            if(r->rsi>node->size)memset(node->bytes+node->size,0,(size_t)r->rsi-node->size);
            if(r->rsi<node->size)memset(node->bytes+(size_t)r->rsi,0,RYZ_LINUX_FILE_MAX-(size_t)r->rsi);
            node->size=(size_t)r->rsi;vfs_stamp(p,node,1);return 0;
        }
        if(nr==8){
            uint64_t base,at,delta=r->rsi;
            if(r->rdx>2)return -22;
            base=r->rdx==0?0:(r->rdx==1?f->offset:node->size);
            if(delta>>63){delta=-delta;if(delta>base)return -22;at=base-delta;}
            else{if(delta>RYZ_LINUX_FILE_MAX || base>RYZ_LINUX_FILE_MAX-delta)return -22;at=base+delta;}
            set_offset(p,fd,(size_t)at);return (int64_t)at;
        }
    }
    switch(nr){
    case 2:flags=r->rsi;break;
    case 257:dirfd=r->rdi;address=r->rsi;flags=r->rdx;mode=r->r10;break;
    case 4:case 6:case 21:case 76:case 80:case 82:case 83:case 84:case 87:case 89:case 90:break;
    case 88:address=r->rsi;break;
    case 266:dirfd=r->rsi;address=r->rdx;break;
    case 267:dirfd=r->rdi;address=r->rsi;break;
    case 258:dirfd=r->rdi;address=r->rsi;mode=r->rdx;break;
    case 262:dirfd=r->rdi;address=r->rsi;if(r->r10 & ~UINT64_C(256))return -22;break;
    case 263:dirfd=r->rdi;address=r->rsi;if(r->rdx & ~UINT64_C(512))return -22;break;
    default:*handled=0;return 0;
    }
    if(nr==6 || nr==82 || nr==83 || nr==84 || nr==87 || nr==88 || nr==89 || nr==258 || nr==263 || nr==266 || nr==267 || (nr==262 && (r->r10 & 256)) || ((nr==2 || nr==257) && ((flags & 0400000) || (flags & 0300)==0300)))follow=0;
    if(nr==82 || nr==84 || nr==87 || nr==263)follow=-1;
    if(nr==83 || nr==258 || nr==88 || nr==266)follow=-2;
    code=ryz_linux_path(p,dirfd,address,path,follow,&trailing);if(code)return code;
    index=vfs_lookup(p->world,path);
    /* Explicit executable grants are immutable even beneath /tmp. */
    if(index!=-10000)for(i=0;i<p->world->exec_count;i++)if(strcmp(path,p->world->execs[i].path)==0){
        if(nr==4 || nr==6 || nr==262){
            uint64_t dest=nr==262?r->rdx:r->rsi;
            if(!buffer(p,dest,144,1,&bytes))return -14;
            memset(bytes,0,144);encode(bytes,p->ns.namespace_id,8);encode(bytes+8,1000+i,8);encode(bytes+16,1,8);
            encode(bytes+24,0100555,4);encode(bytes+28,p->ns.uid,4);encode(bytes+32,p->ns.gid,4);
            encode(bytes+48,p->world->execs[i].size,8);encode(bytes+56,4096,8);return 0;
        }
        if((nr==2 || nr==257) && (flags & 0200000))return -20;
        if((nr==2 || nr==257) && !(flags & ~(uint64_t)(02000000|0100000|0400000|04000))){*handled=0;return 0;}
        if(nr==21)return (r->rsi & ~UINT64_C(5))?-13:0;
        if(nr==89 || nr==267)return -22;
        return -13;
    }
    if(index==-10000){
        if((nr==83 || nr==258) && (strcmp(path,"/")==0 || strcmp(path,"/proc/self")==0))return -17;
        if(nr==80 && strcmp(path,"/")==0){p->resource_cwd[0]=0;p->vfs_cwd=0;p->cwd=RYZ_NS_ROOT;return 0;}
        /* Protected resources use the same canonical guest path resolver. */
        if(nr==82 || nr==83 || nr==84 || nr==87 || nr==88 || nr==258 || nr==263 || nr==266 || nr==76 || nr==90)return -13;
        if(nr==89 || nr==267)return -22;
        *handled=0;return 0;
    }
    if(index<0 && index!=-2)return index;
    if(trailing && index>=0 && !p->world->nodes[index].directory)return -20;
    if(nr==2 || nr==257){
        if(flags & ~(uint64_t)(3|0100|0200|01000|02000|04000|0100000|0200000|0400000|02000000))return -22;
        if((flags & 3)==3)return -22;
        if(index>=0 && (flags & 0300)==0300)return -17;
        if(index>=0 && RYZ_VFS_NODE(p->world,index)->symlink)return -40;
        if(index<0 && (!(flags & 0100) || trailing))return -2;
        if(index>=0 && ((RYZ_VFS_NODE(p->world,index)->permissions & ((flags & 3)==0?0400:((flags & 3)==1?0200:0600)))!=((flags & 3)==0?0400:((flags & 3)==1?0200:0600))))return -13;
        if(index>=0 && p->world->nodes[index].directory && ((flags & 3) || (flags & 01000)))return -21;
        if((flags & 0200000) && index>=0 && !p->world->nodes[index].directory)return -20;
        if(index<0 && (flags & 0200000))return -20;
        if((flags & 01000) && !(flags & 3))return -22;
        for(i=0;i<p->file_limit;i++)if(!p->fds[i].open)break;
        if(i==p->file_limit)return -24;
        slot=-1;
        if(index<0){slot=vfs_slot(p->world);if(slot<0)return slot;}
        id=new_description(p);if(!id)return -24;
        if(index<0){index=vfs_create(p,path,0,(unsigned int)mode);if(index<0){p->world->descriptions[id-1].used=0;return index;}}
        f=&p->fds[i];memset(f,0,sizeof(*f));f->description=id;f->open=1;f->node=RYZ_NS_VFS;f->vnode=RYZ_VFS_INDEX(p->world,index);
        f->mode=(int)(flags & 3);f->cloexec=(flags & 02000000)!=0;f->append=(flags & 02000)!=0;f->nonblock=(flags & 04000)!=0;
        if(flags & 01000){memset(RYZ_VFS_NODE(p->world,index)->bytes,0,RYZ_LINUX_FILE_MAX);RYZ_VFS_NODE(p->world,index)->size=0;vfs_stamp(p,RYZ_VFS_NODE(p->world,index),1);}
        return i;
    }
    if(nr==88 || nr==266){
        const char *link;size_t length;
        if(index>=0)return -17;
        if(trailing)return -2;
        code=guest_path(p,r->rdi,&link,&length);if(code)return code;
        if(length==1)return -2;
        index=vfs_create(p,path,0,0777 | p->file_umask);if(index<0)return index;
        node=&p->world->nodes[index];node->symlink=1;node->permissions=0777;node->size=length-1;
        memcpy(node->bytes,link,length);return 0;
    }
    if(nr==83 || nr==258){
        if(index>=0)return -17;
        return (code=vfs_create(p,path,1,(unsigned int)(nr==83?r->rsi:mode)))<0?code:0;
    }
    if(index<0)return index;
    node=RYZ_VFS_NODE(p->world,index);
    if(nr==89 || nr==267){
        uint64_t dest=nr==89?r->rsi:r->rdx,count=nr==89?r->rdx:r->r10;size_t n;
        if(!node->symlink)return -22;
        if(!count || count>(UINT64_MAX>>1))return -22;
        n=count<node->size?(size_t)count:node->size;
        if(!buffer(p,dest,n,1,&bytes))return -14;
        memcpy(bytes,node->bytes,n);return (int64_t)n;
    }
    if(nr==4 || nr==6 || nr==262)return vfs_stat(p,(unsigned int)index,nr==262?r->rdx:r->rsi);
    if(nr==21){if(r->rsi & ~UINT64_C(7))return -22;return (r->rsi & ~(uint64_t)(node->permissions>>6))?-13:0;}
    if(nr==80){if(!node->directory)return -20;if(!(node->permissions & 0100))return -13;p->resource_cwd[0]=0;p->vfs_cwd=(unsigned int)index+1;return 0;}
    if(nr==90){node->permissions=(unsigned int)r->rsi & 0777;vfs_stamp(p,node,0);return 0;}
    if(nr==76){
        if(!(node->permissions & 0200))return -13;
        if(node->directory)return -21;
        if(r->rsi>RYZ_LINUX_FILE_MAX)return -27;
        if(r->rsi>node->size)memset(node->bytes+node->size,0,(size_t)r->rsi-node->size);
        if(r->rsi<node->size)memset(node->bytes+(size_t)r->rsi,0,RYZ_LINUX_FILE_MAX-(size_t)r->rsi);
        node->size=(size_t)r->rsi;vfs_stamp(p,node,1);return 0;
    }
    if(nr==82){
        code=ryz_linux_path(p,L_AT_FDCWD,r->rsi,other,-1,&trailing);if(code)return code;
        for(i=0;i<p->world->exec_count;i++)if(strcmp(other,p->world->execs[i].path)==0)return -13;
        target=vfs_lookup(p->world,other);
        if(trailing && target>=0 && !p->world->nodes[target].directory)return -20;
        if(target>=0 && RYZ_VFS_INDEX(p->world,target)==RYZ_VFS_INDEX(p->world,index))return 0;
        if(target<0 && target!=-2)return target==-10000?-18:target;
        if(!index)return -16;
        if((p->world->nodes[p->world->nodes[index].parent].permissions & 0300)!=0300)return -13;
        if(trailing && !node->directory)return -20;
        parent=vfs_parent(p->world,other,&name);if(parent<0)return parent;
        if(node->directory){
            unsigned int ancestor=(unsigned int)parent;
            for(;;){if(ancestor==(unsigned int)index)return -22;if(!ancestor)break;ancestor=p->world->nodes[ancestor].parent;}
        }
        if(target>=0){
            RyzVnode *dest=&p->world->nodes[target];
            if(node->directory!=dest->directory)return node->directory?-20:-21;
            if(!target)return -16;
            if(dest->directory)for(i=1;i<RYZ_VFS_NODES;i++)if(p->world->nodes[i].linked && p->world->nodes[i].parent==(unsigned int)target)return -39;
            dest->linked=0;vfs_stamp(p,RYZ_VFS_NODE(p->world,target),0);
        }
        p->world->nodes[index].parent=(unsigned int)parent;memcpy(p->world->nodes[index].name,name,strlen(name)+1);vfs_stamp(p,node,0);return 0;
    }
    if(nr==84 || nr==87 || nr==263){
        int directory=nr==84 || (nr==263 && r->rdx==512);
        if(!index)return -16;
        if((p->world->nodes[p->world->nodes[index].parent].permissions & 0300)!=0300)return -13;
        if(directory!=node->directory)return directory?-20:-21;
        if(directory)for(i=1;i<RYZ_VFS_NODES;i++)if(p->world->nodes[i].linked && p->world->nodes[i].parent==(unsigned int)index)return -39;
        p->world->nodes[index].linked=0;vfs_stamp(p,node,0);return 0;
    }
    return -38;
}
