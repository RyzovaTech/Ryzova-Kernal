/* SPDX-License-Identifier: AGPL-3.0-only */
/* Provider-independent resource ownership, budget and contract regression. */
#include "../ryzova/compat/linux/jobs.h"
#include <stdio.h>
#include <stdlib.h>
typedef struct Fake {uint64_t now;int opened,closed,written,read,mode;} Fake;
static int64_t op_open(void *ctx){Fake *f=ctx;if(f->mode==4)return -4096;f->opened++;return 88;}
static int op_ready(void *ctx,int64_t handle){Fake *f=ctx;(void)handle;if(f->mode==2)return 0x40000000;if(f->mode==11)return 17;if(f->mode==12)return -5;if(f->mode==13)return -4096;if((f->mode==6 || f->mode==10))return 0;return 4|(f->written?1:0);}
static int64_t op_read(void *ctx,int64_t handle,unsigned char *bytes,size_t size)
{
 Fake *f=ctx;(void)handle;if(f->mode==1)return (int64_t)size+1;if(f->mode==14)return -4096;if(f->mode==7)return 0;if(f->mode==8)return -104;
 if(f->read)return 0;
 if(size>4)size=4;
 memcpy(bytes,"pong",size);f->read++;return (int64_t)size;
}
static int64_t op_write(void *ctx,int64_t handle,const unsigned char *bytes,size_t size)
{
 Fake *f=ctx;(void)handle;if(f->mode==3)return (int64_t)size+1;if(f->mode==15)return -4096;if(f->mode==9)return 0;
 if(size!=4 || memcmp(bytes,"ping",4))return -5;
 f->written++;return (int64_t)size;
}
static void op_close(void *ctx,int64_t handle){Fake *f=ctx;if(handle!=88)abort();f->closed++;}
static uint64_t now_ns(void *ctx){Fake *f=ctx;if(f->mode==5 && f->now){f->now--;return f->now;}return f->now;}
static void idle(void *ctx){Fake *f=ctx;if(f->mode!=10)f->now+=1000000;}
static int64_t sink(void *ctx,int fd,const unsigned char *b,size_t n){(void)ctx;(void)fd;(void)b;return (int64_t)n;}
static const RyzNetworkOps ops={op_open,op_ready,op_read,op_write,op_close};
int main(int argc,char **argv)
{
 FILE *file;long length;unsigned char *image,*arena;RyzProcessArgs args;RyzJobConfig config;RyzVmResult result;RyzNetworkResources network;RyzNetworkGrant grant[2];Fake fake;
 const char *av[]={"raw","roundtrip"};int mode,status;unsigned int i;
 if(argc!=2)return 64;
 file=fopen(argv[1],"rb");if(!file || fseek(file,0,SEEK_END))return 65;
 length=ftell(file);if(length<=0 || fseek(file,0,SEEK_SET))return 65;
 image=malloc((size_t)length);arena=malloc(RYZ_PROCESS_MAX_SPAN);if(!image || !arena || fread(image,1,(size_t)length,file)!=(size_t)length)return 65;fclose(file);
 for(mode=0;mode<=15;mode++){
  memset(&config,0,sizeof config);memset(&network,0,sizeof network);memset(grant,0,sizeof grant);memset(&fake,0,sizeof fake);memset(&args,0,sizeof args);
  fake.mode=mode;fake.now=1000000;grant[0].address[0]=10;grant[0].address[1]=20;grant[0].address[2]=30;grant[0].address[3]=40;grant[0].port=8080;grant[0].ops=&ops;grant[0].context=&fake;
  network.grants=grant;network.count=1;network.now_ns=now_ns;network.wait=idle;network.context=&fake;network.wall_milliseconds=20;config.network=&network;
  av[1]=mode==7?"eof":(mode==8?"read-error":(mode==11?"write-closed":(mode==9 || mode==12?"write-error":"roundtrip")));args.argv=av;args.argc=2;
  status=ryz_vm_run_jobs_elf(image,(size_t)length,arena,RYZ_PROCESS_MAX_SPAN,NULL,&args,&config,sink,NULL,&result);
  if(mode==1 || mode==2 || mode==3 || mode==4 || mode==5 || mode==6 || mode==10 || mode>=13){if(status!=RYZ_JOB_NETWORK_LIMIT){fprintf(stderr,"mode %d status %d\n",mode,status);return 1;}}
  else if(status || !result.exited || result.exit_status){fprintf(stderr,"mode %d status %d exit %d\n",mode,status,result.exit_status);return 1;}
  if(fake.opened!=fake.closed){fprintf(stderr,"mode %d leaked handle %d/%d\n",mode,fake.opened,fake.closed);return 1;}
 }
 fake.mode=0;
 for(i=0;i<4;i++){
  const char *modes[]={"fdshare","policy","no-grant","options-before"};memset(&fake,0,sizeof fake);network.wall_milliseconds=100;grant[0].port=i==2?8081:8080;av[1]=modes[i];
  status=ryz_vm_run_jobs_elf(image,(size_t)length,arena,RYZ_PROCESS_MAX_SPAN,NULL,&args,&config,sink,NULL,&result);
  if(status || !result.exited || result.exit_status || fake.opened!=fake.closed || fake.opened!=(i<2?1:0)){fprintf(stderr,"policy %s status %d exit %d handles %d/%d\n",modes[i],status,result.exit_status,fake.opened,fake.closed);return 1;}
 }
 grant[0].port=8080;grant[1]=grant[0];network.count=2;
 if(ryz_vm_run_jobs_elf(image,(size_t)length,arena,RYZ_PROCESS_MAX_SPAN,NULL,&args,&config,sink,NULL,&result)!=RYZ_VM_BAD_INPUT)return 1;
 free(image);free(arena);puts("FLEX_EXTERNAL_RESOURCES_OK");return 0;
}
