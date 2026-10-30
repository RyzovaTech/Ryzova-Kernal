/* SPDX-License-Identifier: AGPL-3.0-only */
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"MAP_MUSL_FAILED line=%d\n",__LINE__);return 90;}}while(0)
static unsigned char *mapped;
static void *worker(void *arg)
{unsigned int i;for(i=0;i<100;i++)__sync_fetch_and_add((uint32_t *)(mapped+128),1);mapped[32+(long)arg]=(unsigned char)('a'+(long)arg);return arg;}
int main(int argc,char **argv)
{
 int fd,status;pid_t pid;pthread_t a,b;void *value;unsigned char *alias;char bytes[17];CHECK(argc==3);
 CHECK(!mkdir(argv[1],0700) && !chdir(argv[1]));fd=open("file",O_CREAT|O_TRUNC|O_RDWR,0600);CHECK(fd>=0 && !ftruncate(fd,8192));
 mapped=mmap(0,8192,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);CHECK(mapped!=MAP_FAILED);
 alias=mmap(0,8192,PROT_READ,MAP_SHARED,fd,0);CHECK(alias!=MAP_FAILED && !close(fd));
 memcpy(mapped,"FLEX_MAPPED_FILE\n",17);CHECK(!pthread_create(&a,0,worker,(void *)0) && !pthread_create(&b,0,worker,(void *)1));
 CHECK(!pthread_join(a,&value) && value==0 && !pthread_join(b,&value) && value==(void *)1);
 CHECK(*(volatile uint32_t *)(alias+128)==200 && alias[32]=='a' && alias[33]=='b');
 pid=fork();CHECK(pid>=0);if(!pid){mapped[4096]='C';_exit(0);}CHECK(waitpid(pid,&status,0)==pid && status==0 && alias[4096]=='C');
 CHECK(!msync(mapped,8192,MS_SYNC) && !munmap(mapped,8192) && !munmap(alias,8192));
 fd=open("file",O_RDONLY);CHECK(fd>=0 && read(fd,bytes,sizeof bytes)==sizeof bytes && !memcmp(bytes,"FLEX_MAPPED_FILE\n",sizeof bytes) && !close(fd));
 puts("FLEX_MAP_MUSL_OK");puts(argv[2]);return 0;
}
