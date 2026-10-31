/* SPDX-License-Identifier: AGPL-3.0-only */
/* Internal coherent mirrors of bounded guest file pages; never host mappings. */
static unsigned char *file_backing(RyzLinuxWorld *w,const RyzFilePage *f)
{return f->anonymous_id?w->shared_pages[f->anonymous_id-1].bytes:w->nodes[f->vnode].bytes+(size_t)f->offset;}
static int file_same(const RyzFilePage *a,const RyzFilePage *b)
{
    if(a->anonymous_id || b->anonymous_id)return a->anonymous_id && a->anonymous_id==b->anonymous_id;
    return a->vnode==b->vnode && a->offset==b->offset;
}
static void file_hold(RyzLinuxWorld *w,const RyzFilePage *f,int delta)
{
    if(f->anonymous_id){
        RyzSharedPage *page=&w->shared_pages[f->anonymous_id-1];
        if(delta>0)page->refs++;else if(page->refs && --page->refs==0){page->identity=0;w->shared_live--;}
    }else if(delta>0)w->mapped_nodes[f->vnode]++;else if(w->mapped_nodes[f->vnode])w->mapped_nodes[f->vnode]--;
}
void ryz_memory_commit(RyzLinuxMemory *m,int clear)
{
    unsigned int i,j;uint64_t now;RyzFilePage *f;RyzVnode *node;unsigned char *bytes,*base;int changed;
    if(!m->file_dirty || !m->world)return;
    for(i=0;i<m->file_count;i++)if(m->file_dirty & (UINT64_C(1)<<i)){
        f=&m->filepages[i];node=&m->world->nodes[f->vnode];changed=0;
        bytes=m->bytes+(size_t)(f->page-m->base);base=m->file_baseline+i*RYZ_PAGE;
        if(f->anonymous_id || f->offset<((node->size+RYZ_PAGE-1)&~(size_t)(RYZ_PAGE-1))){
            for(j=f->dirty_start;j<f->dirty_end;j++)if(bytes[j]!=base[j]){
                file_backing(m->world,f)[j]=bytes[j];if(!f->anonymous_id && f->offset+j<node->size)changed=1;
            }
        }
        if(changed){now=RYZ_TICK(m->world);node->mtime=node->ctime=now/1000000;node->mtime_ns=node->ctime_ns=(now%1000000)*1000;}
        memcpy(base+f->dirty_start,bytes+f->dirty_start,f->dirty_end-f->dirty_start);
        if(clear || !f->borrowed){m->file_dirty &= ~(UINT64_C(1)<<i);f->borrowed=0;}
    }
}
static int file_access(RyzLinuxMemory *m,uint64_t address,uint64_t size,unsigned int flags)
{
    unsigned int i,j,begin,finish;RyzFilePage *f,*other;RyzVnode *node;unsigned char *bytes;uint64_t end=address+size;
    if(!m->file_count)return 1;
    /* Validate the complete range before refreshing or marking any pages. */
    for(i=0;i<m->file_count;i++){
        f=&m->filepages[i];if(address>=f->page+RYZ_PAGE || end<=f->page)continue;
        node=&m->world->nodes[f->vnode];
        if(!f->anonymous_id && f->offset>=((node->size+RYZ_PAGE-1)&~(size_t)(RYZ_PAGE-1))){m->bus_valid=1;m->bus_address=address>f->page?address:f->page;return 0;}
        if(!f->private_map && (flags&RYZ_WRITE) && !(flags&256U))for(j=0;j<m->file_count;j++){
            other=&m->filepages[j];
            if(j!=i && !other->private_map && file_same(other,f) && (other->borrowed || (address<other->page+RYZ_PAGE && end>other->page)))return 0;
        }
    }
    ryz_memory_commit(m,0);
    for(i=0;i<m->file_count;i++){
        f=&m->filepages[i];if(address>=f->page+RYZ_PAGE || end<=f->page)continue;
        bytes=m->bytes+(size_t)(f->page-m->base);
        if(f->private_map){
            if(!f->detached){
                /* Detach the whole page before any write (including syscall
                 * output); later file changes cannot replace its untouched bytes. */
                memcpy(bytes,file_backing(m->world,f),RYZ_PAGE);
                if(flags&RYZ_WRITE)f->detached=1;
            }
            continue;
        }
        begin=address>f->page?(unsigned int)(address-f->page):0;finish=end<f->page+RYZ_PAGE?(unsigned int)(end-f->page):RYZ_PAGE;
        if((flags&RYZ_WRITE) && (m->file_dirty & (UINT64_C(1)<<i))){if(f->dirty_start<begin)begin=f->dirty_start;if(f->dirty_end>finish)finish=f->dirty_end;}
        memcpy(bytes+begin,file_backing(m->world,f)+begin,finish-begin);
        if((flags&RYZ_WRITE) || (m->file_dirty & (UINT64_C(1)<<i)))memcpy(m->file_baseline+i*RYZ_PAGE+begin,bytes+begin,finish-begin);
        if(flags&RYZ_WRITE){
            f->dirty_start=begin;f->dirty_end=finish;m->file_dirty |= UINT64_C(1)<<i;if(!(flags&256U))f->borrowed=1;
        }
    }
    return 1;
}
static void file_unbind(RyzLinuxMemory *m,uint64_t lo,uint64_t hi)
{
    unsigned int i=0;ryz_memory_commit(m,1);
    while(i<m->file_count){
        RyzFilePage *f=&m->filepages[i];
        if(f->page<lo || f->page>=hi){i++;continue;}
        file_hold(m->world,f,-1);
        m->filepages[i]=m->filepages[--m->file_count];
    }
}
void ryz_memory_drop(RyzLinuxMemory *m)
{
    unsigned int i;ryz_memory_commit(m,1);
    for(i=0;i<m->file_count;i++)file_hold(m->world,&m->filepages[i],-1);
    m->file_count=0;free(m->file_baseline);m->file_baseline=NULL;
}
int ryz_memory_fork(RyzLinuxMemory *next,RyzLinuxMemory *old,unsigned char *bytes)
{
    unsigned char *baseline=NULL;unsigned int i;
    if(old->file_baseline){baseline=malloc(RYZ_FILEMAP_PAGES*RYZ_PAGE);if(!baseline)return 0;}
    ryz_memory_commit(old,1);*next=*old;next->bytes=bytes;next->file_baseline=baseline;next->file_dirty=0;next->bus_valid=0;
    for(i=0;i<next->file_count;i++){next->filepages[i].borrowed=0;file_hold(next->world,&next->filepages[i],1);}
    return 1;
}

int ryz_memory_futex_key(RyzLinuxMemory *m,uint64_t address,int private_key,RyzFutexKey *key)
{
    unsigned int i;memset(key,0,sizeof(*key));
    if((address&3) || !ryz_memory_access(m,address,4,RYZ_READ))return (address&3)?-22:-14;
    key->memory=m;key->offset=address;
    if(private_key)return 0;
    for(i=0;i<m->file_count;i++){
        RyzFilePage *f=&m->filepages[i];if(address<f->page || address-f->page>=RYZ_PAGE || f->private_map)continue;
        key->memory=NULL;key->offset=address-f->page;
        if(f->anonymous_id){key->kind=1;key->index=f->anonymous_id-1;key->identity=m->world->shared_pages[key->index].identity;}
        else{key->kind=2;key->index=f->vnode;key->identity=m->world->nodes[f->vnode].inode;key->offset+=f->offset;}
        return 0;
    }
    return 0;
}
void ryz_memory_key_ref(RyzLinuxWorld *w,const RyzFutexKey *key,int delta)
{
    RyzFilePage f;memset(&f,0,sizeof f);if(!key->kind)return;
    if(key->kind==1)f.anonymous_id=key->index+1;else f.vnode=key->index;
    file_hold(w,&f,delta);
}
