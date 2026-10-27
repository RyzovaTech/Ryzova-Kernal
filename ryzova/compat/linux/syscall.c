/* SPDX-License-Identifier: AGPL-3.0-only */
/* All operations are emulated, with no host syscalls or native kernel hooks. */
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
    p->fds[0].open = 1;
    p->fds[1].open = 1;
    p->fds[2].open = 1;
    return 0;
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
    if (fd == 0)
        return -L_EBADF;
    if (fd == 1 || fd == 2) {
        if (p->write_output == NULL)
            return -L_EIO;
        result = p->write_output(p->write_context, (int)fd, buf, (size_t)count);
        if (result < 0 || (uint64_t)result > count)
            return -L_EIO;
        return result;
    }
    if (p->fds[fd].mode == 0)
        return -L_EBADF;
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
    if (fd == 0)
        return 0; /* Host-independent EOF for unconnected stdin. */
    if (fd <= 2 || p->fds[fd].mode == 1)
        return -L_EBADF;
    if (p->fds[fd].node == RYZ_NS_DEV_ZERO) {
        memset(buf, 0, (size_t)count);
        return (int64_t)count;
    }
    if (p->fds[fd].node == RYZ_NS_DEV_NULL)
        return 0;
    return -L_EBADF;
}
static int64_t do_openat(RyzLinuxProcess *p, uint64_t dirfd,
                         uint64_t pathaddr, uint64_t flags)
{
    unsigned char *buf = NULL;
    enum RyzLinuxNode kind;
    unsigned int access;
    int fd, code;
    size_t i;
    if (dirfd != L_AT_FDCWD ||
        (flags & ~(uint64_t)(L_O_ACCMODE | L_O_CLOEXEC)) != 0)
        return -L_EINVAL;
    for (i = 0; i < RYZ_NS_PATH_MAX; ++i) {
        if (!guest_range(p, pathaddr, (uint64_t)i + 1U, &buf))
            return -L_EFAULT;
        if (buf[i] == 0)
            break;
    }
    if (i == RYZ_NS_PATH_MAX)
        return -L_EINVAL;
    code = ryz_linux_ns_resolve(&p->ns, (const char *)buf, i+1, &kind);
    if (code)
        return code;
    if (kind != RYZ_NS_DEV_NULL && kind != RYZ_NS_DEV_ZERO)
        return -L_EPERM;
    access = (unsigned int)(flags & L_O_ACCMODE);
    if (access == L_O_RDWR || access > L_O_RDWR)
        return -L_EINVAL;
    for (fd = 3; fd < (int)RYZ_LINUX_FD_MAX; ++fd)
        if (!p->fds[fd].open) {
            p->fds[fd].open = 1;
            p->fds[fd].node = kind;
            p->fds[fd].mode = access == L_O_WRONLY ? 1 : 0;
            return fd;
        }
    return -L_EMFILE;
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
