/* SPDX-License-Identifier: AGPL-3.0-only */
typedef unsigned long U;
static volatile long value=7;
static unsigned char block[8192],readbuf[32768];
static __attribute__((always_inline)) inline long call(long nr,long a,long b,long c,long d,long e,long f)
{
    register long r10 __asm__("r10")=d;register long r8 __asm__("r8")=e;register long r9 __asm__("r9")=f;long out;
    __asm__ volatile("syscall":"=a"(out):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;
}
static int equal(const char *a,const char *b){while(*a && *a==*b){a++;b++;}return *a==*b;}
static U len(const char *s){U n=0;while(s[n])n++;return n;}
static __attribute__((noreturn)) void bye(long code){call(60,code,0,0,0,0,0);__asm__ volatile("ud2");__builtin_unreachable();}
static long wait_for(long pid,long expected)
{
    int status=0;long n=call(61,pid,(long)&status,0,0,0,0);
    return n==pid && status==(expected<<8);
}
long app_main(long argc,char **argv,char **env)
{
    long parent,pid,n,i,total,fd,alias,count;int pipefd[2],status;char ch;
    char *av[18],*ev[]={"TOKEN=guest",0};
    if(argc<2)return 80;
    if(equal(argv[1],"exec-child")){
        if(argc!=3 || !env[0] || !equal(env[0],"TOKEN=guest") || env[1])return 81;
        if(call(1,4,(long)"X",1,0,0,0)!=-9 || call(1,5,(long)"E",1,0,0,0)!=1)return 82;
        return 6;
    }
    if(argc!=3)return 83;
    if(equal(argv[1],"private") || equal(argv[1],"vfork")){
        parent=call(39,0,0,0,0,0,0);
        pid=call(equal(argv[1],"vfork")?58:57,0,0,0,0,0,0);
        if(pid<0)return 84;
        if(pid==0){value=19;if(call(110,0,0,0,0,0,0)!=parent)bye(99);bye(3);}
        if(!wait_for(pid,3))return 85;
        if(value!=(equal(argv[1],"vfork")?19:7))return 86;
        if(call(61,pid,(long)&status,1,0,0,0)!=-10)return 87;
    }else if(equal(argv[1],"pipe") || equal(argv[1],"io-quota")){
        for(i=0;i<8192;i++)block[i]=(unsigned char)(i&255);
        if(call(293,(long)pipefd,0,0,0,0,0))return 88;
        pid=call(57,0,0,0,0,0,0);if(pid<0)return 89;
        if(pid==0){
            call(3,pipefd[0],0,0,0,0,0);
            for(i=0;i<(equal(argv[1],"io-quota")?513:10);i++){
                n=call(1,pipefd[1],(long)block,8192,0,0,0);
                if(i==512){if(n!=-28)bye(90);}else if(n!=8192)bye(90);
            }
            bye(0);
        }
        call(3,pipefd[1],0,0,0,0,0);total=0;
        while((n=call(0,pipefd[0],(long)readbuf,32768,0,0,0))>0){
            if(readbuf[0]!=(unsigned char)(total&255) || readbuf[n-1]!=(unsigned char)((total+n-1)&255))return 91;
            total+=n;
        }
        if(n!=0 || total!=(equal(argv[1],"io-quota")?4194304:81920) || !wait_for(pid,0))return 92;
    }else if(equal(argv[1],"offset")){
        fd=call(2,(long)"/input",0,0,0,0,0);if(fd<0)return 93;
        alias=call(32,fd,0,0,0,0,0);if(alias<0)return 94;
        pid=call(57,0,0,0,0,0,0);if(pid<0)return 95;
        if(pid==0){call(3,fd,0,0,0,0,0);if(call(0,alias,(long)readbuf,3,0,0,0)!=3)bye(96);bye(0);}
        if(!wait_for(pid,0))return 97;
        call(3,fd,0,0,0,0,0);
        if(call(2,(long)"/input",0,0,0,0,0)!=fd)return 98;
        if(call(0,alias,(long)&ch,1,0,0,0)!=1 || ch!='d')return 99;
        if(call(0,fd,(long)&ch,1,0,0,0)!=1 || ch!='a')return 100;
    }else if(equal(argv[1],"exec") || equal(argv[1],"vfork-exec")){
        if(call(22,(long)pipefd,0,0,0,0,0) || pipefd[0]!=3 || pipefd[1]!=4)return 101;
        if(call(33,4,5,0,0,0,0)!=5 || call(72,4,2,1,0,0,0))return 102;
        pid=call(equal(argv[1],"vfork-exec")?58:57,0,0,0,0,0,0);if(pid<0)return 103;
        if(pid==0){
            call(3,3,0,0,0,0,0);av[0]=argv[0];av[1]="exec-child";av[2]=argv[2];av[3]=0;
            call(59,(long)argv[0],(long)av,(long)ev,0,0,0);bye(104);
        }
        call(3,4,0,0,0,0,0);call(3,5,0,0,0,0,0);
        if(call(0,3,(long)&ch,1,0,0,0)!=1 || ch!='E')return 105;
        if(call(0,3,(long)&ch,1,0,0,0)!=0 || !wait_for(pid,6))return 106;
    }else if(equal(argv[1],"denied")){
        av[0]=argv[0];av[1]="exec-child";av[2]=argv[2];av[3]=0;
        if(call(59,(long)"/etc/passwd",(long)av,(long)ev,0,0,0)!=-2)return 107;
        if(call(59,(long)argv[0],-1,(long)ev,0,0,0)!=-14)return 108;
        for(i=0;i<18;i++)av[i]="x";
        if(call(59,(long)argv[0],(long)av,(long)ev,0,0,0)!=-7 || value!=7)return 109;
    }else if(equal(argv[1],"capacity")){
        count=0;
        for(i=0;i<8;i++){
            pid=call(57,0,0,0,0,0,0);if(pid==0)bye(0);
            if(pid==-11)break;if(pid<0)return 110;count++;
        }
        if(count!=7)return 111;
        for(i=0;i<count;i++)if(call(61,-1,(long)&status,0,0,0,0)<=0 || status)return 112;
    }else if(equal(argv[1],"descriptions")){
        int ready[2],control[2];unsigned char stat[144];
        if(call(22,(long)ready,0,0,0,0,0) || call(22,(long)control,0,0,0,0,0))return 119;
        fd=call(2,(long)"/output",577,0,0,0,0);if(fd!=7 || call(1,fd,(long)"keep\n",5,0,0,0)!=5)return 120;
        for(i=0;i<7;i++){
            pid=call(57,0,0,0,0,0,0);if(pid<0)return 121;
            if(pid==0){
                call(3,ready[0],0,0,0,0,0);call(3,control[1],0,0,0,0,0);
                while(call(2,(long)"/input",0,0,0,0,0)>=0);
                if(call(1,ready[1],(long)"R",1,0,0,0)!=1)bye(122);
                if(call(0,control[0],(long)&ch,1,0,0,0)!=0)bye(123);
                bye(0);
            }
        }
        call(3,ready[1],0,0,0,0,0);call(3,control[0],0,0,0,0,0);
        for(i=0;i<7;i++)if(call(0,ready[0],(long)&ch,1,0,0,0)!=1 || ch!='R')return 124;
        if(call(2,(long)"/output",577,0,0,0,0)!=-24)return 125;
        if(call(5,fd,(long)stat,0,0,0,0) || *(U *)(stat+48)!=5)return 126;
        call(3,control[1],0,0,0,0,0);
        for(i=0;i<7;i++)if(call(61,-1,(long)&status,0,0,0,0)<=0 || status)return 127;
    }else if(equal(argv[1],"quota")){
        for(i=0;i<32;i++){
            pid=call(57,0,0,0,0,0,0);if(pid==0)bye(0);
            if(pid<=0 || !wait_for(pid,0))return 113;
        }
        if(call(57,0,0,0,0,0,0)!=-11)return 114;
    }else if(equal(argv[1],"exec-quota")){
        av[0]=argv[0];av[1]="exec-quota";av[2]=argv[2];av[3]=0;
        if(call(59,(long)argv[0],(long)av,(long)ev,0,0,0)!=-11)return 128;
    }else if(equal(argv[1],"wait-errors")){
        pid=call(57,0,0,0,0,0,0);if(pid==0)bye(5);if(pid<0)return 129;
        if(call(61,pid,-1,0,0,0,0)!=-14)return 130;
        if(call(61,pid,(long)&status,0,-1,0,0)!=-14)return 131;
        if(!wait_for(pid,5))return 132;
        if(call(61,(long)((U)1<<63),(long)&status,0,0,0,0)!=-10)return 133;
    }else if(equal(argv[1],"nonblock")){
        U action[4]={1,0,0,0};int pairs[4][2];
        if(call(293,-1,0,0,0,0,0)!=-14 || call(293,(long)pipefd,04000|02000000,0,0,0,0))return 134;
        if(call(0,pipefd[0],(long)&ch,1,0,0,0)!=-11)return 135;
        if(call(0,pipefd[0],0,0,0,0,0)!=0 || call(1,pipefd[1],0,0,0,0,0)!=0)return 136;
        if(call(72,pipefd[0],1,0,0,0,0)!=1 || call(72,pipefd[0],3,0,0,0,0)!=04000)return 137;
        call(3,pipefd[1],0,0,0,0,0);if(call(0,pipefd[0],(long)&ch,1,0,0,0)!=0)return 138;
        call(3,pipefd[0],0,0,0,0,0);
        fd=call(2,(long)"/dev/null",0,0,0,0,0);
        if(fd<0 || call(72,fd,3,0,0,0,0)!=0)return 152;
        call(3,fd,0,0,0,0,0);
        if(call(22,(long)pipefd,0,0,0,0,0) || call(13,13,(long)action,0,8,0,0))return 139;
        call(3,pipefd[0],0,0,0,0,0);if(call(1,pipefd[1],(long)"X",1,0,0,0)!=-32)return 140;
        call(3,pipefd[1],0,0,0,0,0);
        for(i=0;i<4;i++)if(call(22,(long)pairs[i],0,0,0,0,0))return 141;
        if(call(22,(long)pipefd,0,0,0,0,0)!=-24)return 142;
        for(i=0;i<4;i++){call(3,pairs[i][0],0,0,0,0,0);call(3,pairs[i][1],0,0,0,0,0);}
        if(call(22,(long)pipefd,0,0,0,0,0))return 143;
    }else if(equal(argv[1],"console")){
        for(i=0;i<4096;i++)block[i]='z';
        pid=call(57,0,0,0,0,0,0);if(pid<0)return 144;
        if(pid==0){for(i=0;i<8;i++)if(call(1,1,(long)block,4096,0,0,0)!=4096)bye(145);bye(0);}
        if(!wait_for(pid,0))return 146;
        for(i=0;i<8;i++)if(call(1,1,(long)block,4096,0,0,0)!=4096)return 147;
        if(call(1,1,(long)"X",1,0,0,0)!=-28)return 148;
        return 0;
    }else if(equal(argv[1],"fault-child")){
        pid=call(57,0,0,0,0,0,0);if(pid<0)return 149;
        if(pid==0){__asm__ volatile("ud2");bye(150);}
        call(61,pid,(long)&status,0,0,0,0);return 151;
    }else if(equal(argv[1],"deadlock")){
        if(call(22,(long)pipefd,0,0,0,0,0))return 115;
        call(0,pipefd[0],(long)&ch,1,0,0,0);return 116;
    }else return 117;
    if(call(1,1,(long)"FLEX_JOBS_FIXTURE_OK\n",21,0,0,0)!=21)return 118;
    call(1,1,(long)argv[2],(long)len(argv[2]),0,0,0);call(1,1,(long)"\n",1,0,0,0);return 0;
}
