/* SPDX-License-Identifier: AGPL-3.0-only */
/* Virtual syscalls; only caller-supplied buffers and output callback are used. */
#include "syscall.h"

/* Linux AMD64 syscall and errno numbers (ABI constants). */
#define L_READ 0U
#define L_WRITE 1U
#define L_CLOSE 3U
#define L_GETPID 39U
#define L_EXIT 60U
#define L_GETUID 102U
#define L_GETGID 104U
#define L_GETTID 186U
#define L_EXIT_GROUP 231U
#define L_OPENAT 257U
#define L_AT_FDCWD ((uint64_t)-100)
#define L_O_WRONLY 1U
#define L_O_RDWR 2U
#define L_O_ACCMODE 3U
#define L_O_TRUNC 01000U
#define L_ENOSPC 28
#define L_EACCES 13
#define L_ENOENT 2
#define L_O_CLOEXEC 02000000U
#define L_EPERM 1
#define L_EIO 5
#define L_EBADF 9
#define L_EFAULT 14
#define L_EINVAL 22
#define L_EMFILE 24
#define L_ENOSYS 38

static int guest_range(const RyzLinuxProcess *p, uint64_t address,
                       uint64_t count, unsigned char **pointer)
{
    uint64_t delta;
    if (p->guest_bytes == NULL || address < p->guest_base)
        return 0;
    delta = address - p->guest_base;
    if (delta > (uint64_t)p->guest_size ||
        count > (uint64_t)p->guest_size - delta)
        return 0;
    *pointer = p->guest_bytes + (size_t)delta;
    return 1;
}
int ryz_linux_process_init(RyzLinuxProcess *p, uint32_t namespace_id,
    uint32_t pid, uint32_t uid, uint32_t gid, uint64_t guest_base,
    unsigned char *guest_bytes, size_t guest_size,
    RyzLinuxWrite write_output, void *write_context)
{
    if (p == NULL || guest_bytes == NULL || guest_size == 0 ||
        guest_size > 64U * 1024U * 1024U || pid == 0 || namespace_id == 0 ||
        guest_base > UINT64_MAX - (uint64_t)guest_size)
        return -L_EINVAL;
    memset(p, 0, sizeof(*p));
    p->ns.pid = pid;
    p->ns.uid = uid;
    p->ns.gid = gid;
    p->ns.namespace_id = namespace_id;
    p->guest_base = guest_base;
    p->guest_bytes = guest_bytes;
    p->guest_size = guest_size;
    p->write_output = write_output;
    p->write_context = write_context;
    p->next_description=4;
    p->fds[0].description=1;p->fds[1].description=2;p->fds[2].description=3;
    p->fds[0].node=RYZ_NS_STDIN;p->fds[1].node=RYZ_NS_STDOUT;p->fds[2].node=RYZ_NS_STDERR;
    p->fds[1].mode=p->fds[2].mode=1;
    p->fds[0].open = 1;
    p->fds[1].open = 1;
    p->fds[2].open = 1;
    return 0;
}
/* A description ID survives closing/reusing the descriptor originally duplicated. */
static void set_offset(RyzLinuxProcess *p, uint64_t fd, size_t offset)
{
    unsigned int i,description=p->fds[fd].description;
    for(i=0;i<RYZ_LINUX_FD_MAX;i++)
        if(p->fds[i].open && p->fds[i].description==description)p->fds[i].offset=offset;
}
static int64_t duplicate(RyzLinuxProcess *p, uint64_t old, uint64_t target, int cloexec)
{
    if(old>=RYZ_LINUX_FD_MAX || !p->fds[old].open || target>=RYZ_LINUX_FD_MAX)return -L_EBADF;
    p->fds[target]=p->fds[old];p->fds[target].cloexec=cloexec;return (int64_t)target;
}
static int64_t duplicate_min(RyzLinuxProcess *p, uint64_t old, uint64_t minimum, int cloexec)
{
    unsigned int i;
    if(old>=RYZ_LINUX_FD_MAX || !p->fds[old].open)return -L_EBADF;
    if(minimum>=RYZ_LINUX_FD_MAX)return -L_EINVAL;
    for(i=(unsigned int)minimum;i<RYZ_LINUX_FD_MAX;i++)
        if(!p->fds[i].open)return duplicate(p,old,i,cloexec);
    return -L_EMFILE;
}
static int64_t do_write(RyzLinuxProcess *p, uint64_t fd,
                        uint64_t address, uint64_t count)
{
    unsigned char *buf;
    int64_t result;
    if (fd >= RYZ_LINUX_FD_MAX || !p->fds[fd].open)
        return -L_EBADF;
    if (count > RYZ_LINUX_IO_MAX)
        return -L_EINVAL;
    if (!guest_range(p, address, count, &buf))
        return -L_EFAULT;
    if (count != 0 && p->memory_read != NULL &&
        !p->memory_read(p->memory_context, address, count))
        return -L_EFAULT;
    if (p->fds[fd].node == RYZ_NS_STDIN)
        return -L_EBADF;
    if (p->fds[fd].node == RYZ_NS_STDOUT || p->fds[fd].node == RYZ_NS_STDERR) {
        if (p->write_output == NULL)
            return -L_EIO;
        if (count > RYZ_LINUX_FILE_MAX - p->output_bytes)
            return -L_ENOSPC;
        result = p->write_output(p->write_context, p->fds[fd].node==RYZ_NS_STDOUT?1:2, buf, (size_t)count);
        if (result < 0 || (uint64_t)result > count)
            return -L_EIO;
        p->output_bytes += (uint64_t)result;
        return result;
    }
    if (p->fds[fd].mode == 0)
        return -L_EBADF;
    if (p->fds[fd].node == RYZ_NS_OUTPUT && p->files != NULL) {
        RyzLinuxFiles *f = p->files;
        size_t offset = p->fds[fd].append?f->output_size:p->fds[fd].offset;
        if (offset > f->output_capacity || count > f->output_capacity - offset)
            return -L_ENOSPC;
        memcpy(f->output + offset, buf, (size_t)count);
        set_offset(p,fd,offset+(size_t)count);
        if (p->fds[fd].offset > f->output_size)
            f->output_size = p->fds[fd].offset;
        return (int64_t)count;
    }
    if (p->fds[fd].node == RYZ_NS_DEV_NULL ||
        p->fds[fd].node == RYZ_NS_DEV_ZERO)
        return (int64_t)count;
    return -L_EBADF;
}
static int64_t do_read(RyzLinuxProcess *p, uint64_t fd,
                       uint64_t address, uint64_t count)
{
    unsigned char *buf;
    if (fd >= RYZ_LINUX_FD_MAX || !p->fds[fd].open)
        return -L_EBADF;
    if (count > RYZ_LINUX_IO_MAX)
        return -L_EINVAL;
    if (!guest_range(p, address, count, &buf))
        return -L_EFAULT;
    if (count != 0 && p->memory_write != NULL &&
        !p->memory_write(p->memory_context, address, count))
        return -L_EFAULT;
    if (p->fds[fd].node == RYZ_NS_STDIN)
        return 0; /* Host-independent EOF for unconnected stdin. */
    if (p->fds[fd].mode == 1)
        return -L_EBADF;
    if (p->fds[fd].node == RYZ_NS_INPUT && p->files != NULL) {
        RyzLinuxFiles *f = p->files;
        size_t offset = p->fds[fd].offset;
        if (offset >= f->input_size)
            return 0;
        if (count > f->input_size - offset)
            count = f->input_size - offset;
        memcpy(buf, f->input + offset, (size_t)count);
        set_offset(p,fd,p->fds[fd].offset+(size_t)count);
        return (int64_t)count;
    }
    if (p->fds[fd].node == RYZ_NS_DEV_ZERO) {
        memset(buf, 0, (size_t)count);
        return (int64_t)count;
    }
    if (p->fds[fd].node == RYZ_NS_DEV_NULL)
        return 0;
    return -L_EBADF;
}
static int guest_path(RyzLinuxProcess *p, uint64_t address, const char **path, size_t *length)
{
    unsigned char *buf=NULL;
    size_t i;
    for(i=0;i<RYZ_NS_PATH_MAX;i++){
        if(!guest_range(p,address,i+1,&buf) ||
           (p->memory_read && !p->memory_read(p->memory_context,address,i+1)))return -L_EFAULT;
        if(buf[i]==0){*path=(const char *)buf;*length=i+1;return 0;}
    }
    return -36;
}
static int resolve(RyzLinuxProcess *p, const char *path, size_t length, enum RyzLinuxNode *kind)
{
    int code;
    char absolute[RYZ_NS_PATH_MAX];
    const char *prefix;
    size_t n;
    if(path[0]!='/'){
        prefix=p->cwd==RYZ_NS_TMP?"/tmp/":(p->cwd==RYZ_NS_PROC_SELF?"/proc/self/":"/");
        n=strlen(prefix);
        if(n+length>sizeof absolute)return -36;
        memcpy(absolute,prefix,n);memcpy(absolute+n,path,length);path=absolute;length+=n;
    }
    if(strcmp(path,"/")==0){*kind=RYZ_NS_ROOT;return 0;}
    code=ryz_linux_ns_resolve(&p->ns,path,length,kind);
    if(!code && (*kind==RYZ_NS_INPUT || *kind==RYZ_NS_OUTPUT) && !p->files)return -L_ENOENT;
    return code;
}
static void encode(unsigned char *b, uint64_t v, unsigned int n)
{
    unsigned int i;
    for(i=0;i<n;i++)b[i]=(unsigned char)(v>>(8*i));
}
/* AMD64 Linux UAPI stat layout: exactly 144 bytes, zero padding/timestamps. */
static int64_t do_stat(RyzLinuxProcess *p, uint64_t key, uint64_t destination, int by_fd)
{
    const char *path;
    size_t length;
    enum RyzLinuxNode kind=RYZ_NS_NONE;
    unsigned char data[144], *out;
    uint64_t bytes=0, mode=0, device=0, inode;
    int code;
    if(by_fd){
        if(key>=RYZ_LINUX_FD_MAX || !p->fds[key].open)return -L_EBADF;
        kind=p->fds[key].node;
        if(kind==RYZ_NS_STDIN || kind==RYZ_NS_STDOUT || kind==RYZ_NS_STDERR){mode=0010000|0600;inode=100+(uint64_t)kind;}
        else inode=(uint64_t)kind+1;
    }else{
        code=guest_path(p,key,&path,&length);if(code)return code;
        code=resolve(p,path,length,&kind);if(code)return code;
        inode=(uint64_t)kind+1;
    }
    if(kind==RYZ_NS_INPUT){mode=0100000|0444;bytes=p->files->input_size;}
    if(kind==RYZ_NS_OUTPUT){mode=0100000|0222;bytes=p->files->output_size;}
    if(kind==RYZ_NS_DEV_NULL || kind==RYZ_NS_DEV_ZERO){mode=0020000|0666;device=kind==RYZ_NS_DEV_NULL?259:261;}
    if(kind==RYZ_NS_ROOT || kind==RYZ_NS_TMP || kind==RYZ_NS_PROC_SELF)mode=0040000|0700;
    if(!mode)return -L_ENOENT;
    if(!guest_range(p,destination,sizeof data,&out) ||
       (p->memory_write && !p->memory_write(p->memory_context,destination,sizeof data)))return -L_EFAULT;
    memset(data,0,sizeof data);
    encode(data,p->ns.namespace_id,8);encode(data+8,inode,8);encode(data+16,1,8);
    encode(data+24,mode,4);encode(data+28,p->ns.uid,4);encode(data+32,p->ns.gid,4);
    encode(data+40,device,8);encode(data+48,bytes,8);encode(data+56,4096,8);encode(data+64,(bytes+511)/512,8);
    memcpy(out,data,sizeof data);return 0;
}
static int64_t do_openat(RyzLinuxProcess *p, uint64_t dirfd,
                         uint64_t pathaddr, uint64_t flags)
{
    const char *path;
    enum RyzLinuxNode kind;
    unsigned int access;
    int fd, code;
    size_t length;
    if (dirfd != L_AT_FDCWD ||
        (flags & ~(uint64_t)(L_O_ACCMODE | L_O_CLOEXEC | L_O_TRUNC | (p->memory_call?0100U|0200U|02000U:0))) != 0)
        return -L_EINVAL;
    code=guest_path(p,pathaddr,&path,&length);if(code)return code;
    code=resolve(p,path,length,&kind);if(code)return code;
    if((flags & 0300U)==0300U)return -17;
    if((flags & (0100U|02000U)) && kind!=RYZ_NS_OUTPUT)return -L_EACCES;
    if (kind == RYZ_NS_INPUT || kind == RYZ_NS_OUTPUT) {
        if (p->files == NULL)
            return -L_ENOENT;
        if ((kind == RYZ_NS_INPUT && ((flags & L_O_ACCMODE) != 0 ||
                                      (flags & L_O_TRUNC) != 0)) ||
            (kind == RYZ_NS_OUTPUT && (flags & L_O_ACCMODE) != L_O_WRONLY))
            return -L_EACCES;
    } else {
        if (kind != RYZ_NS_DEV_NULL && kind != RYZ_NS_DEV_ZERO)
            return -L_EPERM;
        if ((flags & L_O_TRUNC) != 0)
            return -L_EINVAL;
    }
    access = (unsigned int)(flags & L_O_ACCMODE);
    if (access == L_O_RDWR || access > L_O_RDWR)
        return -L_EINVAL;
    for (fd = 3; fd < (int)RYZ_LINUX_FD_MAX; ++fd)
        if (!p->fds[fd].open) {
            if (kind == RYZ_NS_OUTPUT && (flags & L_O_TRUNC) != 0) {
                memset(p->files->output, 0, p->files->output_capacity);
                p->files->output_size = 0;
            }
            p->fds[fd].append=(flags & 02000U)!=0;
            p->fds[fd].description=p->next_description++;
            p->fds[fd].cloexec = (flags & L_O_CLOEXEC) != 0;
            p->fds[fd].offset = 0;
            p->fds[fd].open = 1;
            p->fds[fd].node = kind;
            p->fds[fd].mode = access == L_O_WRONLY ? 1 : 0;
            return fd;
        }
    return -L_EMFILE;
}
static uint64_t word64(const unsigned char *b)
{
    uint64_t v=0;unsigned int i;
    for(i=0;i<8;i++)v|=(uint64_t)b[i]<<(i*8);
    return v;
}
static int64_t do_writev(RyzLinuxProcess *p, uint64_t fd, uint64_t address, uint64_t count)
{
    unsigned char *table, *bytes;
    uint64_t bases[16], lengths[16], i,total=0,done=0;
    int64_t n;
    if(count>16)return -L_EINVAL;
    if(fd>=RYZ_LINUX_FD_MAX || !p->fds[fd].open)return -L_EBADF;
    if(count==0)return 0;
    if(!guest_range(p,address,count*16,&table) ||
       (p->memory_read && !p->memory_read(p->memory_context,address,count*16)))return -L_EFAULT;
    for(i=0;i<count;i++){
        bases[i]=word64(table+i*16);lengths[i]=word64(table+i*16+8);
        if(lengths[i]>RYZ_LINUX_IO_MAX-total)return -L_EINVAL;
        total+=lengths[i];
        if(lengths[i] && (!guest_range(p,bases[i],lengths[i],&bytes) ||
           (p->memory_read && !p->memory_read(p->memory_context,bases[i],lengths[i]))))return -L_EFAULT;
    }
    for(i=0;i<count;i++){
        if(lengths[i]==0)continue;
        n=do_write(p,fd,bases[i],lengths[i]);
        if(n<0)return done?(int64_t)done:n;
        done+=(uint64_t)n;
        if((uint64_t)n<lengths[i])break;
    }
    return (int64_t)done;
}
static int buffer(RyzLinuxProcess *p, uint64_t at, size_t size, int write, unsigned char **out)
{
    RyzLinuxMemoryWrite check=write?p->memory_write:p->memory_read;
    return guest_range(p,at,size,out) && (!check || check(p->memory_context,at,size));
}
static int64_t signal_state(RyzLinuxProcess *p, const RyzLinuxRegs *r)
{
    unsigned char *in=NULL,*out=NULL, data[32];
    uint64_t bits=0,old=p->signal_mask;
    if(r->r10!=8)return -L_EINVAL;
    if(r->rax==14){
        if(r->rsi){
            if(r->rdi>2)return -L_EINVAL;
            if(!buffer(p,r->rsi,8,0,&in))return -L_EFAULT;
            bits=word64(in);bits &= ~((UINT64_C(1)<<8)|(UINT64_C(1)<<18));
        }
        if(r->rdx && !buffer(p,r->rdx,8,1,&out))return -L_EFAULT;
        if(in){
            if(r->rdi==0)p->signal_mask|=bits;
            else if(r->rdi==1)p->signal_mask&=~bits;
            else p->signal_mask=bits;
        }
        if(out)encode(out,old,8);
    }else{
        if(r->rdi==0 || r->rdi>64 || r->rdi==9 || r->rdi==19)return -L_EINVAL;
        if(r->rsi){
            if(!buffer(p,r->rsi,32,0,&in))return -L_EFAULT;
            memcpy(data,in,32);
            bits=word64(data+24)&~((UINT64_C(1)<<8)|(UINT64_C(1)<<18));encode(data+24,bits,8);
        }
        if(r->rdx && !buffer(p,r->rdx,32,1,&out))return -L_EFAULT;
        if(out)memcpy(out,p->signal_actions[r->rdi-1],32);
        if(in)memcpy(p->signal_actions[r->rdi-1],data,32);
    }
    return 0;
}
int64_t ryz_linux_syscall(RyzLinuxProcess *p, const RyzLinuxRegs *regs)
{
    uint64_t nr;
    if (p == NULL || regs == NULL)
        return -L_EINVAL;
    if (p->exited)
        return -L_EPERM;
    nr = regs->rax;
    switch (nr) {
    case 9: case 10: case 11: case 12:
        return p->memory_call == NULL ? -L_ENOSYS :
               p->memory_call(p->memory_context, regs);
    case 13: case 14:return signal_state(p,regs);
    case 105: case 106:
        return (uint32_t)regs->rdi==(nr==105?p->ns.uid:p->ns.gid)?0:-L_EPERM;
    case 117: case 119:{
        uint32_t id=nr==117?p->ns.uid:p->ns.gid;
        return ((uint32_t)regs->rdi==id || (uint32_t)regs->rdi==(uint32_t)-1) &&
               ((uint32_t)regs->rsi==id || (uint32_t)regs->rsi==(uint32_t)-1) &&
               ((uint32_t)regs->rdx==id || (uint32_t)regs->rdx==(uint32_t)-1)?0:-L_EPERM;
    }
    case 63:{
        unsigned char *out;
        if(!buffer(p,regs->rdi,390,1,&out))return -L_EFAULT;
        memset(out,0,390);
        memcpy(out,"Linux",6);memcpy(out+65,"compact",8);memcpy(out+130,"flex-abi-0.1",13);
        memcpy(out+195,"Ryzova interpreted environment",30);memcpy(out+260,"x86_64",7);memcpy(out+325,"(none)",7);
        return 0;
    }
    case 79:{
        unsigned char *out;
        const char *cwd=p->cwd==RYZ_NS_TMP?"/tmp":(p->cwd==RYZ_NS_PROC_SELF?"/proc/self":"/");
        size_t n=strlen(cwd)+1;
        if(regs->rsi==0)return -L_EINVAL;
        if(regs->rsi<n)return -34;
        if(!buffer(p,regs->rdi,n,1,&out))return -L_EFAULT;
        memcpy(out,cwd,n);return (int64_t)n;
    }
    case 80:{
        const char *path;size_t n;enum RyzLinuxNode kind;int code;
        code=guest_path(p,regs->rdi,&path,&n);if(code)return code;
        if(strcmp(path,".")==0)return 0;
        if(strcmp(path,"..")==0){p->cwd=RYZ_NS_ROOT;return 0;}
        code=resolve(p,path,n,&kind);if(code)return code;
        if(kind!=RYZ_NS_ROOT && kind!=RYZ_NS_TMP)return -20;
        p->cwd=kind;return 0;
    }
    case 2:return do_openat(p,L_AT_FDCWD,regs->rdi,regs->rsi);
    case 8:{
        RyzLinuxFD *fd;
        uint64_t end,base,position,delta=regs->rsi;
        if(regs->rdi>=RYZ_LINUX_FD_MAX || !p->fds[regs->rdi].open)return -L_EBADF;
        fd=&p->fds[regs->rdi];
        if(fd->node!=RYZ_NS_INPUT && fd->node!=RYZ_NS_OUTPUT)return -29;
        end=fd->node==RYZ_NS_INPUT?p->files->input_size:p->files->output_size;
        if(regs->rdx>2)return -L_EINVAL;
        base=regs->rdx==0?0:(regs->rdx==1?fd->offset:end);
        if(delta>>63){delta=-delta;if(delta>base)return -L_EINVAL;position=base-delta;}
        else{if(delta>RYZ_LINUX_FILE_MAX || base>RYZ_LINUX_FILE_MAX-delta)return -L_EINVAL;position=base+delta;}
        set_offset(p,regs->rdi,(size_t)position);return (int64_t)position;
    }
    case 110:return 1;
    case 111:return (int64_t)p->ns.pid;
    case 4: case 6:return do_stat(p,regs->rdi,regs->rsi,0);
    case 5:return do_stat(p,regs->rdi,regs->rsi,1);
    case 262:
        if(regs->rdi!=L_AT_FDCWD || (regs->r10 & ~UINT64_C(256)))return -L_EINVAL;
        return do_stat(p,regs->rsi,regs->rdx,0);
    case 107:return (int64_t)p->ns.uid;
    case 108:return (int64_t)p->ns.gid;
    case 20:return do_writev(p,regs->rdi,regs->rsi,regs->rdx);
    case 16:
        return regs->rdi>=RYZ_LINUX_FD_MAX || !p->fds[regs->rdi].open?-L_EBADF:-25;
    case 7:{
        unsigned char *table,data[RYZ_LINUX_FD_MAX*8];
        uint64_t i,fd,events,revents;int ready=0;
        if(regs->rsi>RYZ_LINUX_FD_MAX)return -L_EINVAL;
        if(regs->rsi && (!buffer(p,regs->rdi,(size_t)regs->rsi*8,0,&table) ||
           !buffer(p,regs->rdi,(size_t)regs->rsi*8,1,&table)))return -L_EFAULT;
        if(regs->rsi)memcpy(data,table,(size_t)regs->rsi*8);
        for(i=0;i<regs->rsi;i++){
            fd=word64(data+i*8)&UINT64_C(0xffffffff);events=(uint64_t)data[i*8+4]|((uint64_t)data[i*8+5]<<8);revents=0;
            if(!(fd & UINT64_C(0x80000000))){
                if(fd>=RYZ_LINUX_FD_MAX || !p->fds[fd].open)revents=32;
                else revents=events & (p->fds[fd].mode==0?1U:4U);
            }
            if(revents)ready++;
            encode(data+i*8+6,revents,2);
        }
        if(!ready && (uint32_t)regs->rdx!=0)return -L_ENOSYS;
        if(regs->rsi)memcpy(table,data,(size_t)regs->rsi*8);
        return ready;
    }
    case 40:return -L_ENOSYS; /* sendfile: callers can fall back to read/write. */
    case 32:return duplicate_min(p,regs->rdi,0,0);
    case 33:
        if(regs->rdi==regs->rsi)return regs->rdi<RYZ_LINUX_FD_MAX && p->fds[regs->rdi].open?(int64_t)regs->rdi:-L_EBADF;
        return duplicate(p,regs->rdi,regs->rsi,0);
    case 292:
        if(regs->rdi==regs->rsi || (regs->rdx & ~(uint64_t)L_O_CLOEXEC))return -L_EINVAL;
        return duplicate(p,regs->rdi,regs->rsi,regs->rdx!=0);
    case 72:
        if(regs->rdi>=RYZ_LINUX_FD_MAX || !p->fds[regs->rdi].open)return -L_EBADF;
        if(regs->rsi==0 || regs->rsi==1030)return duplicate_min(p,regs->rdi,regs->rdx,regs->rsi==1030);
        if(regs->rsi==1)return p->fds[regs->rdi].cloexec;
        if(regs->rsi==2){
            if((regs->rdx&~UINT64_C(1))!=0)return -L_EINVAL;
            p->fds[regs->rdi].cloexec=(int)regs->rdx;return 0;
        }
        if(regs->rsi==3)return p->fds[regs->rdi].mode|(p->fds[regs->rdi].append?02000:0);
        if(regs->rsi==4){
            unsigned int i;
            if(regs->rdx & ~(uint64_t)(02000U|L_O_ACCMODE))return -L_EINVAL;
            for(i=0;i<RYZ_LINUX_FD_MAX;i++)if(p->fds[i].open && p->fds[i].description==p->fds[regs->rdi].description)
                p->fds[i].append=(regs->rdx & 02000U)!=0;
            return 0;
        }
        return -L_EINVAL;
    case L_READ: return do_read(p, regs->rdi, regs->rsi, regs->rdx);
    case L_WRITE: return do_write(p, regs->rdi, regs->rsi, regs->rdx);
    case L_OPENAT: return do_openat(p, regs->rdi, regs->rsi, regs->rdx);
    case L_CLOSE:
        if (regs->rdi >= RYZ_LINUX_FD_MAX || !p->fds[regs->rdi].open)
            return -L_EBADF;
        p->fds[regs->rdi].open = 0;
        p->fds[regs->rdi].node = RYZ_NS_NONE;
        return 0;
    case L_GETPID: return (int64_t)p->ns.pid;
    case L_GETUID: return (int64_t)p->ns.uid;
    case L_GETGID: return (int64_t)p->ns.gid;
    case L_GETTID: return (int64_t)p->ns.pid;
    case L_EXIT:
    case L_EXIT_GROUP:
        p->exited = 1;
        p->exit_status = (uint8_t)regs->rdi;
        return 0;
    default: return -L_ENOSYS;
    }
}
