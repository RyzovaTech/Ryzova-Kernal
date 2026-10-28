/* SPDX-License-Identifier: AGPL-3.0-only */
typedef unsigned long U;
static unsigned char data[65536],scratch[65536];
static __attribute__((always_inline)) inline long call(long nr,long a,long b,long c,long d,long e,long f)
{
    register long r10 __asm__("r10")=d;register long r8 __asm__("r8")=e;register long r9 __asm__("r9")=f;long out;
    __asm__ volatile("syscall":"=a"(out):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;
}
static int eq(const char *a,const char *b){while(*a && *a==*b){a++;b++;}return *a==*b;}
static U len(const char *s){U n=0;while(s[n])n++;return n;}
static U word(const unsigned char *b,U n){U v=0,i;for(i=0;i<n;i++)v|=(U)b[i]<<(8*i);return v;}
#define C(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
#define CHECK(x) do{if(!(x))return __LINE__;}while(0)
long app_main(long argc,char **argv,char **env)
{
    long fd,other,directory,n,i,pid,status;U ino;char *av[4],*ev[]={0};
    (void)env;
    if(argc==2 && eq(argv[1],"exec")){
        CHECK(C(0,3,scratch,1)==1 && scratch[0]=='b');
        CHECK(C(2,"item",0,0)>=0);return 7;
    }
    CHECK(argc==4);
    CHECK(C(83,argv[1],0700,0)==0);CHECK(C(80,argv[1],0,0)==0);
    if(eq(argv[2],"basic")){
        CHECK(C(95,0027,0,0)==0022);
        fd=C(2,"item",0100|0200|2,0666);CHECK(fd==3);
        CHECK(C(5,fd,scratch,0)==0 && (word(scratch+24,4)&0777)==0640);ino=word(scratch+8,8);
        CHECK(C(1,fd,"abc",3)==3);CHECK(C(8,fd,5,0)==5);CHECK(C(1,fd,"Z",1)==1);
        CHECK(C(8,fd,0,0)==0 && C(0,fd,scratch,9)==6);
        CHECK(scratch[0]=='a' && scratch[3]==0 && scratch[4]==0 && scratch[5]=='Z');
        CHECK(C(77,fd,9,0)==0 && C(8,fd,6,0)==6 && C(0,fd,scratch,3)==3 && !scratch[0] && !scratch[2]);
        CHECK(C(77,fd,2,0)==0 && C(8,fd,0,2)==2);
        CHECK(C(74,fd,0,0)==0 && C(75,fd,0,0)==0);
        CHECK(C(91,fd,0600,0)==0 && C(4,"item",scratch,0)==0 && word(scratch+8,8)==ino);
        CHECK(C(3,fd,0,0)==0);fd=C(2,"item",1|02000,0);CHECK(fd==3);
        CHECK(C(8,fd,0,0)==0 && C(1,fd,"x",1)==1 && C(3,fd,0,0)==0);
        CHECK(C(76,"item",2,0)==0);fd=C(2,"item",0,0);CHECK(C(0,fd,scratch,10)==2 && scratch[0]=='a' && scratch[1]=='b');
    }else if(eq(argv[2],"directory")){
        CHECK(C(83,"sub",0700,0)==0);directory=C(2,"sub",0200000,0);CHECK(directory==3);
        fd=call(257,directory,(long)"f",0100|2,0600,0,0);CHECK(fd==4);
        CHECK(call(262,directory,(long)"f",(long)scratch,0,0,0)==0 && (word(scratch+24,4)&0170000)==0100000);
        CHECK(C(217,directory,scratch,24)==24 && eq((char *)scratch+19,"."));
        CHECK(C(217,directory,scratch,24)==24 && eq((char *)scratch+19,".."));
        CHECK(C(217,directory,scratch,24)==24 && eq((char *)scratch+19,"f"));
        CHECK(C(217,directory,scratch,24)==0 && C(8,directory,0,0)==0);
        CHECK(C(217,directory,scratch,24)==24);
        CHECK(C(81,directory,0,0)==0 && C(2,"./../sub/f",0,0)>=0);
        CHECK(C(80,"..",0,0)==0);CHECK(C(82,"sub","renamed",0)==0);
        CHECK(C(81,directory,0,0)==0 && C(79,scratch,256,0)>0);
        n=len((char *)scratch);CHECK(n>=8 && eq((char *)scratch+n-8,"/renamed"));
        CHECK(call(263,directory,(long)"f",0,0,0,0)==0);CHECK(C(80,"..",0,0)==0);
        CHECK(C(84,"renamed",0,0)==0);
    }else if(eq(argv[2],"unlink")){
        fd=C(2,"item",0100|2,0600);CHECK(fd==3 && C(1,fd,"old",3)==3);
        CHECK(C(87,"item",0,0)==0 && C(4,"item",scratch,0)==-2);
        other=C(2,"item",0100|2,0600);CHECK(other==4 && C(1,other,"new",3)==3);
        CHECK(C(8,fd,0,0)==0 && C(0,fd,scratch,3)==3 && scratch[0]=='o');
        CHECK(C(82,"item","other",0)==0 && C(4,"item",scratch,0)==-2);
        CHECK(C(82,"other","other",0)==0 && C(5,fd,scratch,0)==0 && word(scratch+16,8)==0);
        for(i=0;i<50;i++){
            n=C(2,"recycle",0100|2,0600);CHECK(n>=0);CHECK(C(87,"recycle",0,0)==0 && C(3,n,0,0)==0);
        }
    }else if(eq(argv[2],"errors")){
        CHECK(C(2,"missing/../item",0100|2,0600)==-2);
        CHECK(C(83,"sub",0700,0)==0 && C(83,"sub",0700,0)==-17);
        CHECK(C(2,"item",0100|2,0600)==3);
        CHECK(C(2,"item/../b",0100|2,0600)==-20 && C(2,"item/",0,0)==-20);
        CHECK(C(2,"item",0100|0200|2,0600)==-17);
        CHECK(C(2,"item",0200000,0)==-20 && C(0,3,-1,1)==-14);
        CHECK(C(1,3,-1,1)==-14 && C(217,3,scratch,100)==-20);
        CHECK(C(2,"sub",1,0)==-21 && C(87,"sub",0,0)==-21 && C(84,"item",0,0)==-20);
        CHECK(C(82,"sub","sub/inside",0)==-22);
        CHECK(C(83,"sub/inside",0700,0)==0 && C(84,"sub",0,0)==-39);
        CHECK(C(8,3,-1,0)==-22 && C(77,3,65537,0)==-27);
        CHECK(C(90,"item",0,0)==0 && C(2,"item",0,0)==-13);
        /* Existing open descriptions remain valid after chmod. */
        CHECK(C(1,3,"x",1)==1 && C(90,"sub",0000,0)==0 && C(2,"sub/inside",0,0)==-13);
    }else if(eq(argv[2],"shared")){
        fd=C(2,"item",0100|2,0600);CHECK(fd==3 && C(1,fd,"abc",3)==3 && C(8,fd,0,0)==0);
        pid=C(57,0,0,0);CHECK(pid>=0);
        if(!pid){
            CHECK(C(0,fd,scratch,1)==1 && scratch[0]=='a');
            av[0]=argv[0];av[1]="exec";av[2]=0;
            C(59,argv[0],av,ev);return 99;
        }
        CHECK(C(61,pid,&status,0)==pid && status==(7<<8));
        CHECK(C(0,fd,scratch,1)==1 && scratch[0]=='c');
    }else if(eq(argv[2],"atomic")){
        fd=C(2,"item",0100|2,0600);CHECK(fd==3 && C(1,fd,"keep",4)==4);
        for(i=4;i<16;i++)CHECK(C(2,"item",0,0)==i);
        CHECK(C(2,"item",1|01000,0)==-24 && C(3,15,0,0)==0);
        CHECK(C(8,fd,0,0)==0 && C(0,fd,scratch,4)==4 && scratch[0]=='k');
        CHECK(C(2,"missing",0100|0200|2,0600)==15 && C(3,15,0,0)==0);
        for(i=0;i<40;i++){
            char name[4]={'n',(char)('0'+i/10),(char)('0'+i%10),0};
            n=C(2,name,0100|2,0600);
            if(n==-28)break;
            CHECK(n==15 && C(3,n,0,0)==0);
        }
        CHECK(i==28 && C(2,"item",1|01000,0)==15);
    }else if(eq(argv[2],"grants")){
        fd=C(2,"item",0100|2,0600);CHECK(fd==3 && C(1,fd,"safe",4)==4);
        CHECK(C(82,"item","/tmp/bound",0)==-13);
        CHECK(C(2,"/tmp/bound",0100|1|01000,0600)==-13);
        CHECK(C(4,"item",scratch,0)==0 && word(scratch+48,8)==4);
        CHECK(C(4,"/tmp/bound",scratch,0)==0 && (word(scratch+24,4)&0170000)==0100000);
    }else if(eq(argv[2],"times")){
        U times[4]={11,123,22,456};
        fd=C(2,"item",0100|2,0600);CHECK(fd==3);
        CHECK(call(280,-100,(long)"item",(long)times,0,0,0)==0);
        CHECK(C(5,fd,scratch,0)==0 && word(scratch+72,8)==11 && word(scratch+80,8)==123 && word(scratch+88,8)==22 && word(scratch+96,8)==456);
        times[1]=1000000000;
        CHECK(call(280,-100,(long)"item",(long)times,0,0,0)==-22);
        CHECK(C(5,fd,scratch,0)==0 && word(scratch+80,8)==123);
        times[1]=times[3]=1073741822;
        CHECK(call(280,-100,(long)"item",(long)times,0,0,0)==0);
        CHECK(C(5,fd,scratch,0)==0 && word(scratch+96,8)==456);
    }else if(eq(argv[2],"quota")){
        fd=C(2,"item",0100|2,0600);CHECK(fd==3);
        data[65535]=255;
        CHECK(C(1,fd,data,65536)==65536 && C(1,fd,"x",1)==-28);
        CHECK(C(8,fd,0,0)==0 && C(0,fd,scratch,65536)==65536);
        CHECK(scratch[0]==0 && scratch[65535]==255);
    }else return 98;
    CHECK(C(1,1,"FLEX_VFS_OK\n",12)==12);
    CHECK(C(1,1,argv[3],len(argv[3]))==(long)len(argv[3]));CHECK(C(1,1,"\n",1)==1);return 0;
}
