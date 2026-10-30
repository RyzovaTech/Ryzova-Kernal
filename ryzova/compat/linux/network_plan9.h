/* SPDX-License-Identifier: AGPL-3.0-only */
/* Explicit TCP resources implemented through the native Plan 9 namespace. */
#include "network_cli.h"
typedef struct NetworkHost {const char *target;char directory[NETPATHLEN];} NetworkHost;
static volatile unsigned int network_alarms;
static int network_alarm(void *context,char *note)
{
    USED(context);if(strcmp(note,"alarm"))return 0;network_alarms++;return 1;
}
static int network_clock_fd=-1;
static int network_stdio[3]={1,1,1};
static void network_prepare(void)
{
    int i,copy;
    for(i=0;i<3;i++){
        copy=dup(i,-1);
        if(copy>=0){close(copy);continue;}
        network_stdio[i]=0;copy=open("/dev/null",ORDWR);
        if(copy<0)sysfatal("reserve standard descriptors: %r");
        if(copy!=i){if(dup(copy,i)<0)sysfatal("reserve standard descriptor: %r");close(copy);}
    }
    if(!atnotify(network_alarm,1))sysfatal("network deadline handler unavailable");
}
static uint64_t network_now(void *context)
{
    unsigned char bytes[32];uint64_t value=0;unsigned int i;USED(context);
    if(network_clock_fd<0)network_clock_fd=open("/dev/bintime",OREAD|OCEXEC);
    if(network_clock_fd<0 || pread(network_clock_fd,bytes,sizeof bytes,0)!=(long)sizeof bytes)return UINT64_MAX;
    /* The fourth big-endian word is kernel monotonic uptime in nanoseconds.
     * Reading the device avoids requiring newer libc time helper symbols. */
    for(i=24;i<32;i++)value=(value<<8)|bytes[i];
    return value;
}
static void network_finish(void)
{
    if(network_clock_fd>=0){close(network_clock_fd);network_clock_fd=-1;}
}
static void network_wait(void *context){USED(context);sleep(1);}
static int64_t network_open(void *context)
{
    NetworkHost *host=context;int fd;unsigned int seen=network_alarms;
    alarm(1000);fd=dial((char *)host->target,nil,host->directory,nil);alarm(0);
    return fd<0?(network_alarms!=seen?-110:-111):fd;
}
static int network_status(NetworkHost *host,int *incoming,int *outgoing,int *ended)
{
    char path[NETPATHLEN+16],text[512],*fields[8],*end;int fd,n,count;long qin,qout;unsigned int seen=network_alarms;
    snprint(path,sizeof path,"%s/status",host->directory);alarm(100);
    fd=open(path,OREAD);if(fd<0){alarm(0);return network_alarms!=seen?-11:-5;}
    n=read(fd,text,sizeof text-1);close(fd);alarm(0);if(n<=0)return network_alarms!=seen?-11:-5;
    text[n]=0;count=tokenize(text,fields,nelem(fields));if(count<5 || strcmp(fields[1],"qin") || strcmp(fields[3],"qout"))return -5;
    qin=strtol(fields[2],&end,10);if(*end || qin<0 || qin>1073741824)return -5;
    qout=strtol(fields[4],&end,10);if(*end || qout<0 || qout>1073741824)return -5;
    *incoming=(int)qin;*outgoing=(int)qout;
    *ended=!strcmp(fields[0],"Closed")?2:(!strcmp(fields[0],"Close_wait")?1:0);
    return 0;
}
static int network_ready(void *context,int64_t handle)
{
    int in,out,ended,result;USED(handle);result=network_status(context,&in,&out,&ended);
    if(result==-11)return 0;
    if(result<0)return result;
    return (in || ended?1:0)|(!out && ended!=2?4:0)|(ended?8192:0)|(ended==2?16:0);
}
static int64_t network_read(void *context,int64_t handle,unsigned char *bytes,size_t size)
{
    int in,out,ended,result;long n;unsigned int seen;
    result=network_status(context,&in,&out,&ended);if(result<0)return result;
    if(!in)return ended?0:-11;
    if(size>(size_t)in)size=(size_t)in;
    seen=network_alarms;alarm(100);n=read((int)handle,bytes,size);alarm(0);
    return n<0?(network_alarms!=seen?-11:-5):n;
}
static int64_t network_write(void *context,int64_t handle,const unsigned char *bytes,size_t size)
{
    int in,out,ended,result;long n;unsigned int seen;
    result=network_status(context,&in,&out,&ended);if(result<0)return result;
    if(ended==2)return -32;
    if(out)return -11;
    if(size>4096)size=4096;
    seen=network_alarms;alarm(100);n=write((int)handle,bytes,size);alarm(0);
    return n<0?(network_alarms!=seen?-11:-32):n;
}
static void network_close(void *context,int64_t handle){USED(context);alarm(100);close((int)handle);alarm(0);}
static const RyzNetworkOps network_ops={network_open,network_ready,network_read,network_write,network_close};
static int network_parse(char *text,RyzNetworkGrant *grant,NetworkHost *host)
{
    const char *target,*separator;
    if(!network_guest(text,grant,&target) || strncmp(target,"tcp!",4) || strlen(target)>=128)return 0;
    separator=strchr(target+4,'!');
    if(!separator || separator==target+4 || !separator[1] || strchr(separator+1,'!') || strpbrk(target," \t\r\n"))return 0;
    memset(host,0,sizeof *host);host->target=target;grant->ops=&network_ops;grant->context=host;return 1;
}
