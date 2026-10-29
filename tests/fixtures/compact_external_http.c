/* SPDX-License-Identifier: AGPL-3.0-only */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
static int fail(int line){fprintf(stderr,"EXTERNAL_HTTP_FAILED line=%d errno=%d\n",line,errno);return line%200+1;}
#define CHECK(x) do{if(!(x))return fail(__LINE__);}while(0)
static int connect_to(int fd,struct sockaddr_in *address,int nonblock)
{
    struct pollfd p;int error=0;int result=connect(fd,(void *)address,sizeof *address);socklen_t length=sizeof error;
    if(result && (!nonblock || errno!=EINPROGRESS))return -1;
    p.fd=fd;p.events=POLLOUT;p.revents=0;
    if(nonblock && (poll(&p,1,2000)!=1 || !(p.revents&POLLOUT) || getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&length) || error))return -1;
    return 0;
}
int main(int argc,char **argv)
{
    static const char normal_request[]="GET /external-probe.txt HTTP/1.0\r\nHost: flex-resource\r\nConnection: close\r\n\r\n";
    static const char stall_request[]="GET /external-stall.txt HTTP/1.0\r\nHost: flex-resource\r\nConnection: close\r\n\r\n";
    const char *request;size_t request_size;
    struct sockaddr_in address;struct pollfd p;char response[8192],peek[8];size_t used=0;ssize_t n;int fd,other,status,nonblock;const char *mode,*native;pid_t child;
    CHECK(argc==4);mode=argv[1];request=!strcmp(mode,"timeout")?stall_request:normal_request;request_size=strlen(request);native=getenv("FLEX_EXTERNAL_NATIVE_ADDR");nonblock=!strcmp(mode,"nonblock");
    memset(&address,0,sizeof address);address.sin_family=AF_INET;address.sin_port=htons(8080);CHECK(inet_pton(AF_INET,"10.20.30.40",&address.sin_addr)==1);
    if(native){char ip[32];const char *colon=strchr(native,':');CHECK(colon && (size_t)(colon-native)<sizeof ip);memcpy(ip,native,(size_t)(colon-native));ip[colon-native]=0;CHECK(inet_pton(AF_INET,ip,&address.sin_addr)==1);address.sin_port=htons((unsigned short)atoi(colon+1));}
    fd=socket(AF_INET,SOCK_STREAM|(nonblock?SOCK_NONBLOCK:0),0);CHECK(fd>=0);
    if(!strcmp(mode,"denied")){
        address.sin_port=htons(8081);CHECK(connect(fd,(void *)&address,sizeof address)==-1 && errno==ENETUNREACH);CHECK(!close(fd));goto done;
    }
    CHECK(!connect_to(fd,&address,nonblock));
    if(!strcmp(mode,"duplicate")){
        other=socket(AF_INET,SOCK_STREAM,0);CHECK(other>=0 && connect(other,(void *)&address,sizeof address)==-1 && errno==EADDRINUSE);CHECK(!close(fd));fd=other;CHECK(!connect_to(fd,&address,0));
    }
    if(!strcmp(mode,"fork")){
        child=fork();CHECK(child>=0);if(!child){if(write(fd,request,request_size)!=(ssize_t)(request_size))_exit(90);_exit(0);}
        CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    }else CHECK(write(fd,request,request_size)==(ssize_t)(request_size));
    if(!strcmp(mode,"poll") || nonblock){p.fd=fd;p.events=POLLIN;p.revents=0;CHECK(poll(&p,1,2000)==1 && (p.revents&POLLIN));}
    if(!strcmp(mode,"peek")){do{n=recv(fd,peek,sizeof peek,MSG_PEEK);CHECK(n>0);if(n<8)usleep(1000);}while(n<8);CHECK(!memcmp(peek,"HTTP/1.0",8));}
    if(!strcmp(mode,"msg-peek")){
        struct iovec vectors[2]={{peek,3},{peek+3,5}};struct msghdr message={0};message.msg_iov=vectors;message.msg_iovlen=2;
        do{n=recvmsg(fd,&message,MSG_PEEK);CHECK(n>0);if(n<8)usleep(1000);}while(n<8);
        CHECK(!memcmp(peek,"HTTP/1.0",8));
    }
    for(;;){
        n=read(fd,response+used,sizeof response-1-used);
        if(n<0 && nonblock && errno==EAGAIN){p.fd=fd;p.events=POLLIN;p.revents=0;CHECK(poll(&p,1,2000)==1);continue;}
        CHECK(n>=0);if(!n)break;used+=(size_t)n;CHECK(used<sizeof response-1);
    }
    response[used]=0;CHECK(strstr(response," 200 OK\r\n") && strstr(response,argv[2]));CHECK(!close(fd));
 done:
    printf("FLEX_EXTERNAL_OK %s\n",mode);puts(argv[3]);return 0;
}
