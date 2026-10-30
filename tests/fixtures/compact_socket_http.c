/* SPDX-License-Identifier: AGPL-3.0-only */
#define _GNU_SOURCE
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int listener,problem;
static const char *challenge;
static void *serve(void *unused)
{
    int fd;ssize_t n;char request[256],response[512];struct pollfd pollfd;
    (void)unused;fd=accept(listener,0,0);if(fd<0){problem=1;return 0;}
    pollfd.fd=fd;pollfd.events=POLLIN;pollfd.revents=0;
    if(poll(&pollfd,1,5000)!=1){problem=2;return 0;}
    n=read(fd,request,sizeof request-1);if(n<16 || memcmp(request,"GET /hello HTTP/1",16)){problem=3;return 0;}
    n=snprintf(response,sizeof response,"HTTP/1.1 200 OK\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",strlen(challenge),challenge);
    if(write(fd,response,(size_t)n)!=n || shutdown(fd,SHUT_WR) || close(fd))problem=4;
    return 0;
}
int main(int argc,char **argv)
{
    pthread_t thread;struct sockaddr_in address;char response[512];socklen_t length=sizeof address;
    int client;size_t used=0;ssize_t n;
    if(argc!=2)return 64;challenge=argv[1];memset(&address,0,sizeof address);
    address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    listener=socket(AF_INET,SOCK_STREAM,0);if(listener<0 || bind(listener,(void *)&address,sizeof address) || listen(listener,4) || getsockname(listener,(void *)&address,&length))return 65;
    if(pthread_create(&thread,0,serve,0))return 66;
    client=socket(AF_INET,SOCK_STREAM,0);if(client<0 || connect(client,(void *)&address,sizeof address))return 67;
    if(write(client,"GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n",40)!=40)return 68;
    while((n=read(client,response+used,sizeof response-1-used))>0){used+=(size_t)n;if(used==sizeof response-1)return 69;}
    response[used]=0;
    if(n<0 || close(client) || pthread_join(thread,0) || close(listener) || problem)return 70;
    if(!strstr(response,"HTTP/1.1 200 OK\r\n") || !strstr(response,challenge))return 71;
    puts("FLEX_SOCKET_HTTP_OK");puts(challenge);return 0;
}
