/* SPDX-License-Identifier: AGPL-3.0-only */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition=PTHREAD_COND_INITIALIZER;
static pthread_barrier_t barrier;
static volatile int count,ready,hit,problem;
static int fd;
static const char *mode,*directory,*program,*challenge;
static pid_t main_pid,main_ppid;
static __thread int local=10;
static void caught(int sig){if(sig==SIGUSR1)hit++;}
static void *work(void *arg)
{
    long value=(long)arg;int i;
    if(getpid()!=main_pid || getppid()!=main_ppid || syscall(SYS_gettid)==main_pid)problem=1;
    local+=value;
    if(!strcmp(mode,"exec")){
        char pid[32],tid[32],keep[32],drop[32];const char *loader=getenv("FLEX_TEST_NATIVE_INTERP");
        snprintf(pid,sizeof pid,"%d",main_pid);snprintf(tid,sizeof tid,"%ld",syscall(SYS_gettid));
        snprintf(keep,sizeof keep,"%d",fd);snprintf(drop,sizeof drop,"%d",count);
        if(loader)execl(loader,loader,program,"exec-child",pid,tid,keep,drop,challenge,(char *)0);
        else execl(program,program,"exec-child",pid,tid,keep,drop,challenge,(char *)0);
        _exit(91);
    }else if(!strcmp(mode,"exec-failed")){
        char *args[]={"missing",0};
        if(execv("/missing",args)!=-1 || errno!=ENOENT)problem=6;
    }else if(!strcmp(mode,"fds")){if(write(fd,"worker",6)!=6 || close(fd))problem=2;}
    else if(!strcmp(mode,"fs")){if(chdir(directory))problem=3;umask(0077);signal(SIGUSR1,caught);}
    else if(!strcmp(mode,"cond")){
        pthread_mutex_lock(&mutex);ready=1;pthread_cond_signal(&condition);pthread_mutex_unlock(&mutex);
    }else if(!strcmp(mode,"capacity")){
        pthread_mutex_lock(&mutex);while(!ready)pthread_cond_wait(&condition,&mutex);pthread_mutex_unlock(&mutex);
    }else if(!strcmp(mode,"robust")){
        if(pthread_mutex_lock(&mutex))problem=4;return (void *)local;
    }else if(!strcmp(mode,"detach")){
        pthread_mutex_lock(&mutex);count++;pthread_cond_signal(&condition);pthread_mutex_unlock(&mutex);
    }else if(!strcmp(mode,"cancel")){
        pthread_mutex_lock(&mutex);ready=1;pthread_cond_signal(&condition);pthread_mutex_unlock(&mutex);
        for(;;){pthread_testcancel();sched_yield();}
    }else if(!strcmp(mode,"kill")){
        pthread_barrier_wait(&barrier);while(!hit)sched_yield();
    }else if(!strcmp(mode,"fork")){
        int status=0;pid_t child=fork();if(child==0)_exit(7);
        if(child<0 || waitpid(child,&status,0)!=child || !WIFEXITED(status) || WEXITSTATUS(status)!=7)problem=5;
    }else{
        for(i=0;i<20;i++){pthread_mutex_lock(&mutex);count++;pthread_mutex_unlock(&mutex);}
    }
    return (void *)(long)local;
}
static int fail(int line){fprintf(stderr,"THREAD_FIXTURE_FAILED line=%d errno=%d problem=%d\n",line,errno,problem);return line%200+1;}
#define CHECK(x) do{if(!(x))return fail(__LINE__);}while(0)
int main(int argc,char **argv)
{
    pthread_t a,b;void *ra,*rb;char buffer[256],path[256];int status;pthread_mutexattr_t attr;struct stat st;
    CHECK(argc>=2);
    if(!strcmp(argv[1],"exec-child")){
        sigset_t mask;struct sigaction action;
        CHECK(argc==7 && getpid()==atoi(argv[2]) && syscall(SYS_gettid)==getpid());
        CHECK(syscall(SYS_tgkill,getpid(),atoi(argv[3]),0)==-1 && errno==ESRCH);
        CHECK(fcntl(atoi(argv[4]),F_GETFD)>=0);
        CHECK(fcntl(atoi(argv[5]),F_GETFD)==-1 && errno==EBADF);
        CHECK(!pthread_sigmask(SIG_SETMASK,0,&mask) && sigismember(&mask,SIGUSR2));
        CHECK(!sigaction(SIGUSR1,0,&action) && action.sa_handler==SIG_IGN);
        puts("FLEX_THREADS_OK exec");puts(argv[6]);return 0;
    }
    program=argv[0];challenge=argc>3?argv[3]:"";mode=argv[1];directory=argc>2?argv[2]:"/tmp";main_pid=getpid();main_ppid=getppid();
    if(!strcmp(mode,"fds")){
        snprintf(path,sizeof path,"%s/threads-file",directory);fd=open(path,O_CREAT|O_RDWR|O_TRUNC,0600);CHECK(fd>=0);
    }
    if(!strcmp(mode,"robust")){
        CHECK(!pthread_mutexattr_init(&attr) && !pthread_mutexattr_setrobust(&attr,PTHREAD_MUTEX_ROBUST));
        CHECK(!pthread_mutex_init(&mutex,&attr) && !pthread_mutexattr_destroy(&attr));
    }
    if(!strcmp(mode,"kill")){CHECK(signal(SIGUSR1,caught)!=SIG_ERR && !pthread_barrier_init(&barrier,0,2));}
    if(!strcmp(mode,"capacity")){
        pthread_t threads[8];long i;
        for(i=0;i<7;i++)CHECK(!pthread_create(&threads[i],0,work,(void *)(i+1)));
        CHECK(pthread_create(&threads[7],0,work,(void *)8)==EAGAIN);
        CHECK(!pthread_mutex_lock(&mutex));ready=1;CHECK(!pthread_cond_broadcast(&condition));CHECK(!pthread_mutex_unlock(&mutex));
        for(i=0;i<7;i++)CHECK(!pthread_join(threads[i],&ra) && (long)ra==i+11);
        CHECK(!problem);puts("FLEX_THREADS_OK capacity");if(argc>3)puts(argv[3]);return 0;
    }
    if(!strcmp(mode,"quota")){
        long i;for(i=0;i<32;i++)CHECK(!pthread_create(&a,0,work,(void *)1) && !pthread_join(a,&ra));
        CHECK(pthread_create(&a,0,work,(void *)1)==EAGAIN && !problem);puts("FLEX_THREADS_OK quota");if(argc>3)puts(argv[3]);return 0;
    }
    if(!strcmp(mode,"exec")){
        sigset_t mask;sigemptyset(&mask);sigaddset(&mask,SIGUSR2);
        CHECK(!pthread_sigmask(SIG_BLOCK,&mask,0) && signal(SIGUSR1,SIG_IGN)!=SIG_ERR);
        fd=open("/dev/null",O_RDWR);count=open("/dev/null",O_RDWR|O_CLOEXEC);CHECK(fd>=0 && count>=0);
    }
    CHECK(!pthread_create(&a,0,work,(void *)1));
    if(!strcmp(mode,"basic")){
        CHECK(!pthread_create(&b,0,work,(void *)2));CHECK(!pthread_join(b,&rb) && (long)rb==12);
    }
    if(!strcmp(mode,"cond") || !strcmp(mode,"cancel")){
        CHECK(!pthread_mutex_lock(&mutex));while(!ready)CHECK(!pthread_cond_wait(&condition,&mutex));CHECK(!pthread_mutex_unlock(&mutex));
        if(!strcmp(mode,"cancel"))CHECK(!pthread_cancel(a));
    }
    if(!strcmp(mode,"kill")){pthread_barrier_wait(&barrier);CHECK(!pthread_kill(a,SIGUSR1));}
    if(!strcmp(mode,"detach")){
        CHECK(!pthread_detach(a));CHECK(!pthread_mutex_lock(&mutex));while(!count)CHECK(!pthread_cond_wait(&condition,&mutex));CHECK(!pthread_mutex_unlock(&mutex));
        for(status=0;status<100;status++)sched_yield();
    }else{
        CHECK(!pthread_join(a,&ra));CHECK(!strcmp(mode,"cancel")?ra==PTHREAD_CANCELED:(long)ra==11);
    }
    CHECK(!problem && local==10);
    if(!strcmp(mode,"basic"))CHECK(count==40);
    if(!strcmp(mode,"fds"))CHECK(write(fd,"x",1)==-1 && errno==EBADF);
    if(!strcmp(mode,"fs")){
        CHECK(getcwd(buffer,sizeof buffer) && !strcmp(buffer,directory));
        fd=open("umask-file",O_CREAT|O_RDWR,0666);CHECK(fd>=0 && !fstat(fd,&st) && (st.st_mode&0777)==0600);
        CHECK(!kill(main_pid,SIGUSR1) && hit==1);
    }
    if(!strcmp(mode,"robust")){CHECK(pthread_mutex_lock(&mutex)==EOWNERDEAD);CHECK(!pthread_mutex_consistent(&mutex) && !pthread_mutex_unlock(&mutex));}
    if(!strcmp(mode,"kill"))CHECK(hit==1);
    printf("FLEX_THREADS_OK %s\n",mode);if(argc>3)puts(argv[3]);return 0;
}
