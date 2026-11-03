/* SPDX-License-Identifier: AGPL-3.0-only */
/* Linux-host reference adapter. Native production uses network_plan9.h. */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include "network_cli.h"
typedef struct NetworkHost {struct sockaddr_in address;} NetworkHost;
static uint64_t network_now(void *context)
{
    struct timespec ts;(void)context;
    if(clock_gettime(CLOCK_MONOTONIC,&ts))return UINT64_MAX;
    return (uint64_t)ts.tv_sec*1000000000+(uint64_t)ts.tv_nsec;
}
static void network_wait(void *context){struct timespec ts={0,1000000};(void)context;nanosleep(&ts,NULL);}
static int64_t network_open(void *context)
{
    NetworkHost *host=context;struct pollfd p;int fd,error;socklen_t size=sizeof error;
    fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);if(fd<0)return -errno;
    if(fd<3){int copy=fcntl(fd,F_DUPFD_CLOEXEC,3);error=errno;close(fd);if(copy<0)return -error;fd=copy;}
    if(connect(fd,(struct sockaddr *)&host->address,sizeof host->address)){
        if(errno!=EINPROGRESS){error=errno;close(fd);return -error;}
        p.fd=fd;p.events=POLLOUT;p.revents=0;
        if(poll(&p,1,1000)<=0){close(fd);return -110;}
        if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size)){error=errno;close(fd);return -error;}
        if(error){close(fd);return -error;}
    }
    return fd;
}
static int network_ready(void *context,int64_t handle)
{
    struct pollfd p;int n;(void)context;p.fd=(int)handle;p.events=POLLIN|POLLOUT|POLLRDHUP;p.revents=0;
    n=poll(&p,1,0);return n<0?-errno:p.revents;
}
static int64_t network_read(void *context,int64_t handle,unsigned char *bytes,size_t size)
{
    ssize_t n;(void)context;n=recv((int)handle,bytes,size,MSG_DONTWAIT);return n<0?-errno:(int64_t)n;
}
static int64_t network_write(void *context,int64_t handle,const unsigned char *bytes,size_t size)
{
    ssize_t n;(void)context;n=send((int)handle,bytes,size,MSG_DONTWAIT|MSG_NOSIGNAL);return n<0?-errno:(int64_t)n;
}
static void network_close(void *context,int64_t handle){(void)context;close((int)handle);}
static const RyzNetworkOps network_ops={network_open,network_ready,network_read,network_write,network_close};
static int network_parse(char *text,RyzNetworkGrant *grant,NetworkHost *host)
{
    const char *target;char ip[16],*end;size_t n;unsigned long port;
    if(!network_guest(text,grant,&target))return 0;
    n=0;while(target[n] && target[n]!=':'){if(n>=15)return 0;ip[n]=target[n];n++;}ip[n]=0;
    if(target[n]!=':' || !target[n+1])return 0;
    port=strtoul(target+n+1,&end,10);if(*end || !port || port>65535)return 0;
    memset(host,0,sizeof *host);host->address.sin_family=AF_INET;host->address.sin_port=htons((unsigned short)port);
    if(inet_pton(AF_INET,ip,&host->address.sin_addr)!=1)return 0;
    grant->ops=&network_ops;grant->context=host;return 1;
}
