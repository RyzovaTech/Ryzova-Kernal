/* SPDX-License-Identifier: AGPL-3.0-only */
#include "process.h"
#ifndef RYZ_PLAN9
#include <stdlib.h>
#endif
#include "memory_files.h"

int ryz_memory_access(RyzLinuxMemory *m, uint64_t address, uint64_t size, unsigned int flags)
{
    uint64_t start, end, i;unsigned int access=flags & 7U;
    if (address < m->base || address - m->base > m->size ||
        size > m->size - (address - m->base))
        return 0;
    if (size == 0)
        return 1;
    start = (address - m->base) / RYZ_PAGE;
    end = (address - m->base + size - 1) / RYZ_PAGE;
    for (i = start; i <= end; ++i)
        if ((m->pages[i] & (RYZ_MAP | access)) != (RYZ_MAP | access))
            return 0;
    return file_access(m,address,size,flags);
}
int ryz_memory_read(void *m, uint64_t address, uint64_t size)
{
    return ryz_memory_access(m,address,size,RYZ_READ);
}
int ryz_memory_write(void *m, uint64_t address, uint64_t size)
{
    return ryz_memory_access(m,address,size,RYZ_WRITE|128U);
}
static uint64_t alignpage(uint64_t x)
{
    return (x + RYZ_PAGE - 1) & ~(uint64_t)(RYZ_PAGE - 1);
}
static void mark(RyzLinuxMemory *m, uint64_t lo, uint64_t hi, unsigned int flags)
{
    uint64_t i;
    for (i = (lo - m->base) / RYZ_PAGE; i < (hi - m->base) / RYZ_PAGE; ++i)
        m->pages[i] = (unsigned char)flags;
}
static int freepages(RyzLinuxMemory *m, uint64_t lo, uint64_t hi)
{
    uint64_t i;
    for (i = (lo - m->base) / RYZ_PAGE; i < (hi - m->base) / RYZ_PAGE; ++i)
        if (m->pages[i] != 0)
            return 0;
    return 1;
}
static int64_t dynamic_memory(RyzLinuxMemory *m,const RyzLinuxRegs *r)
{
    uint64_t size,lo,hi,i,at,minimum,ceiling=m->stack-RYZ_PAGE,prot=r->rdx,offset=r->r9;
    unsigned int flags,kept;int fixed,anonymous,shared;const RyzLinuxExec *file=NULL;RyzVnode *node=NULL;unsigned int vnode=0;
    RyzLinuxProcess *p=m->process;
    if(r->rax==26){
        if((r->rdi & (RYZ_PAGE-1)) || (r->rdx & ~UINT64_C(7)) || (r->rdx & 5)==5)return -22;
        if(!r->rsi)return 0;
    }
    if(!r->rsi || r->rsi>m->size)return -22;
    size=alignpage(r->rsi);
    if(r->rax==9){
        if((r->r10 & ~(uint64_t)(3|16|32|0x800|0x1000)) || (r->r10&3)==0 || (r->r10&3)==3)return -22;
        if((prot & ~UINT64_C(7)) || (prot&6)==6)return -1;
        anonymous=(r->r10&32)!=0;fixed=(r->r10&16)!=0;shared=(r->r10&3)==1;
        if(anonymous){if(shared)return -22;if((prot&4) || r->r8!=UINT64_MAX || offset)return -1;}
        else{
            if(!p || !p->world || r->r8>=RYZ_LINUX_FD_MAX || !p->fds[r->r8].open)return -9;
            if(offset & (RYZ_PAGE-1) || offset>UINT64_MAX-size)return -22;
            if(p->fds[r->r8].mode==1)return -13;
            if(p->fds[r->r8].node==RYZ_NS_EXEC){if(shared)return -13;file=&p->world->execs[p->fds[r->r8].vnode];}
            else if(p->fds[r->r8].node==RYZ_NS_VFS){
                if(!shared)return -95;
                vnode=RYZ_VFS_INDEX(p->world,p->fds[r->r8].vnode);node=&p->world->nodes[vnode];
                if(node->directory)return -19;
                if(prot&4)return -1;
                if((prot&2) && p->fds[r->r8].mode!=2)return -13;
            }else return -19;
        }
        minimum=alignpage(m->brk);lo=r->rdi;
        if(fixed){
            if((lo & (RYZ_PAGE-1)) || lo<(anonymous?m->heap:minimum) || lo>=ceiling || size>ceiling-lo)return -22;
            for(i=(lo-m->base)/RYZ_PAGE;i<(lo+size-m->base)/RYZ_PAGE;i++)if(!(m->pages[i]&16) && !(anonymous && lo>=m->heap && lo+size<=alignpage(m->brk)))return -1;
        }else{
            if(lo<minimum || lo>=ceiling || (lo & (RYZ_PAGE-1)) || size>ceiling-lo || !freepages(m,lo,lo+size)){
                if(minimum>ceiling || size>ceiling-minimum)return -12;
                at=ceiling-size;
                for(;;){if(freepages(m,at,at+size))break;if(at==minimum)return -12;at-=RYZ_PAGE;}
                lo=at;
            }
        }
        hi=lo+size;
        if(node){
            kept=m->file_count;for(i=0;i<m->file_count;i++)if(m->filepages[i].page>=lo && m->filepages[i].page<hi)kept--;
            if(size/RYZ_PAGE>RYZ_FILEMAP_PAGES-kept)return -12;
            if(!m->file_baseline){m->file_baseline=malloc(RYZ_FILEMAP_PAGES*RYZ_PAGE);if(!m->file_baseline)return -12;}
        }
        file_unbind(m,lo,hi);
        flags=RYZ_MAP|16|((prot&1)?RYZ_READ:0)|((prot&2)?RYZ_WRITE:0)|((prot&4)?RYZ_EXEC:0);
        if(file && !(prot&2))flags|=64;
        memset(m->bytes+(size_t)(lo-m->base),0,(size_t)size);
        if(file && offset<file->size){uint64_t n=file->size-offset;if(n>size)n=size;memcpy(m->bytes+(size_t)(lo-m->base),file->image+(size_t)offset,(size_t)n);}
        mark(m,lo,hi,flags);
        if(node)for(i=0;i<size;i+=RYZ_PAGE){
            RyzFilePage *binding=&m->filepages[m->file_count++];memset(binding,0,sizeof(*binding));
            binding->page=lo+i;binding->offset=offset+i;binding->vnode=vnode;binding->maywrite=p->fds[r->r8].mode==2;m->world->mapped_nodes[vnode]++;
        }
        if(file){
            uint64_t valid=offset<file->size?alignpage(file->size-offset):0;
            if(valid<size)mark(m,lo+valid,hi,RYZ_MAP|16);
        }
        return (int64_t)lo;
    }
    lo=r->rdi;
    if((lo & (RYZ_PAGE-1)) || lo<m->base || lo>=m->base+m->size || size>m->base+m->size-lo)return -22;
    hi=lo+size;
    if(r->rax==26){
        for(i=(lo-m->base)/RYZ_PAGE;i<(hi-m->base)/RYZ_PAGE;i++)if(!(m->pages[i]&RYZ_MAP))return -12;
        ryz_memory_commit(m,1);return 0;
    }
    if(r->rax==11){file_unbind(m,lo,hi);mark(m,lo,hi,0);memset(m->bytes+(size_t)(lo-m->base),0,(size_t)size);return 0;}
    if((prot & ~UINT64_C(7)) || (prot&6)==6)return -1;
    for(i=(lo-m->base)/RYZ_PAGE;i<(hi-m->base)/RYZ_PAGE;i++){
        if(!(m->pages[i]&RYZ_MAP))return -12;
        if((prot&4) && !(m->pages[i]&64))return -1;
    }
    if(prot&2)for(i=0;i<m->file_count;i++)if(m->filepages[i].page>=lo && m->filepages[i].page<hi && !m->filepages[i].maywrite)return -13;
    for(i=(lo-m->base)/RYZ_PAGE;i<(hi-m->base)/RYZ_PAGE;i++){
        flags=m->pages[i] & (RYZ_MAP|16|64);if(prot&2)flags&=~64U;
        m->pages[i]=(unsigned char)(flags|((prot&1)?RYZ_READ:0)|((prot&2)?RYZ_WRITE:0)|((prot&4)?RYZ_EXEC:0));
    }
    return 0;
}
int64_t ryz_memory_call(void *context, const RyzLinuxRegs *r)
{
    RyzLinuxMemory *m = context;
    uint64_t lo, hi, size, old, at, i, ceiling;
    unsigned int flags;
    ceiling=m->stack-RYZ_PAGE; /* Unmapped guard below the initial stack. */
    if (r->rax == 12) {
        lo = r->rdi;
        if (lo == 0)
            return (int64_t)m->brk;
        if (lo < m->heap || lo > ceiling)
            return (int64_t)m->brk;
        old = alignpage(m->brk);
        hi = alignpage(lo);
        if (hi > old) {
            if (!freepages(m,old,hi))
                return (int64_t)m->brk;
            mark(m,old,hi,RYZ_MAP|RYZ_READ|RYZ_WRITE);
            memset(m->bytes + (size_t)(old-m->base),0,(size_t)(hi-old));
        } else if (hi < old) {
            mark(m,hi,old,0);
            memset(m->bytes + (size_t)(hi-m->base),0,(size_t)(old-hi));
        }
        m->brk = lo;
        return (int64_t)lo;
    }
    if(m->dynamic || (m->process && m->process->world))return dynamic_memory(m,r);
    size = r->rsi;
    if (size == 0 || size > m->size)
        return -22;
    size = alignpage(size);
    if (r->rax == 9) {
        if (r->rdi != 0 || r->r10 != 34 || r->r8 != UINT64_MAX || r->r9 != 0)
            return -22;
        if ((r->rdx & ~UINT64_C(3)) != 0)
            return -1; /* Anonymous executable memory is outside this profile. */
        flags = RYZ_MAP | ((r->rdx & 1) ? RYZ_READ : 0) | ((r->rdx & 2) ? RYZ_WRITE : 0);
        lo = alignpage(m->brk);
        if (lo > ceiling || size > ceiling - lo)
            return -12;
        at = ceiling - size;
        for (;;) {
            if (freepages(m,at,at+size)) {
                mark(m,at,at+size,flags);
                memset(m->bytes+(size_t)(at-m->base),0,(size_t)size);
                return (int64_t)at;
            }
            if (at == lo)
                break;
            at -= RYZ_PAGE;
        }
        return -12;
    }
    lo = r->rdi;
    if ((lo & (RYZ_PAGE-1)) != 0 || lo < alignpage(m->brk) ||
        lo >= ceiling || size > ceiling-lo)
        return -22;
    hi = lo + size;
    if (r->rax == 11) {
        mark(m,lo,hi,0);
        memset(m->bytes+(size_t)(lo-m->base),0,(size_t)size);
        return 0;
    }
    if (r->rax == 10) {
        if ((r->rdx & ~UINT64_C(3)) != 0)
            return -1;
        for (i=(lo-m->base)/RYZ_PAGE;i<(hi-m->base)/RYZ_PAGE;++i)
            if ((m->pages[i] & RYZ_MAP) == 0)
                return -12; /* Validate whole range before changing any page. */
        flags = RYZ_MAP | ((r->rdx&1) ? RYZ_READ:0) | ((r->rdx&2) ? RYZ_WRITE:0);
        mark(m,lo,hi,flags);
        return 0;
    }
    return -38;
}
