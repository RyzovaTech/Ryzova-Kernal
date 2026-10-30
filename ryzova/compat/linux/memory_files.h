/* SPDX-License-Identifier: AGPL-3.0-only */
/* Internal coherent mirrors of bounded guest file pages; never host mappings. */
void ryz_memory_commit(RyzLinuxMemory *m,int clear)
{
    unsigned int i,j;uint64_t now;RyzFilePage *f;RyzVnode *node;unsigned char *bytes,*base;int changed;
    if(!m->file_dirty || !m->world)return;
    for(i=0;i<m->file_count;i++)if(m->file_dirty & (UINT64_C(1)<<i)){
        f=&m->filepages[i];node=&m->world->nodes[f->vnode];changed=0;
        bytes=m->bytes+(size_t)(f->page-m->base);base=m->file_baseline+i*RYZ_PAGE;
        if(f->offset<((node->size+RYZ_PAGE-1)&~(size_t)(RYZ_PAGE-1))){
            for(j=f->dirty_start;j<f->dirty_end;j++)if(bytes[j]!=base[j]){
                node->bytes[(size_t)f->offset+j]=bytes[j];if(f->offset+j<node->size)changed=1;
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
        if(f->offset>=((node->size+RYZ_PAGE-1)&~(size_t)(RYZ_PAGE-1))){m->bus_valid=1;m->bus_address=address>f->page?address:f->page;return 0;}
        if((flags&RYZ_WRITE) && !(flags&256U))for(j=0;j<m->file_count;j++){
            other=&m->filepages[j];
            if(j!=i && other->vnode==f->vnode && other->offset==f->offset && (other->borrowed || (address<other->page+RYZ_PAGE && end>other->page)))return 0;
        }
    }
    ryz_memory_commit(m,0);
    for(i=0;i<m->file_count;i++){
        f=&m->filepages[i];if(address>=f->page+RYZ_PAGE || end<=f->page)continue;
        node=&m->world->nodes[f->vnode];bytes=m->bytes+(size_t)(f->page-m->base);
        begin=address>f->page?(unsigned int)(address-f->page):0;finish=end<f->page+RYZ_PAGE?(unsigned int)(end-f->page):RYZ_PAGE;
        if((flags&RYZ_WRITE) && (m->file_dirty & (UINT64_C(1)<<i))){if(f->dirty_start<begin)begin=f->dirty_start;if(f->dirty_end>finish)finish=f->dirty_end;}
        memcpy(bytes+begin,node->bytes+(size_t)f->offset+begin,finish-begin);
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
        if(m->world->mapped_nodes[f->vnode])m->world->mapped_nodes[f->vnode]--;
        m->filepages[i]=m->filepages[--m->file_count];
    }
}
void ryz_memory_drop(RyzLinuxMemory *m)
{
    unsigned int i;ryz_memory_commit(m,1);
    for(i=0;i<m->file_count;i++)if(m->world->mapped_nodes[m->filepages[i].vnode])m->world->mapped_nodes[m->filepages[i].vnode]--;
    m->file_count=0;free(m->file_baseline);m->file_baseline=NULL;
}
int ryz_memory_fork(RyzLinuxMemory *next,RyzLinuxMemory *old,unsigned char *bytes)
{
    unsigned char *baseline=NULL;unsigned int i;
    if(old->file_count){baseline=malloc(RYZ_FILEMAP_PAGES*RYZ_PAGE);if(!baseline)return 0;}
    ryz_memory_commit(old,1);*next=*old;next->bytes=bytes;next->file_baseline=baseline;next->file_dirty=0;next->bus_valid=0;
    for(i=0;i<next->file_count;i++){next->filepages[i].borrowed=0;next->world->mapped_nodes[next->filepages[i].vnode]++;}
    return 1;
}
