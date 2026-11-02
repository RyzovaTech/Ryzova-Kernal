/* SPDX-License-Identifier: AGPL-3.0-only */
/* CLX-06: same source-built, unmodified Linux AMD64 executable on host
 * and bounded Ryzova user-space interpreter. No host PTY is passed to VM. */
typedef unsigned long U;
static long call(long nr,long a,long b,long c,long d,long e,long f)
{
 register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;
 long out;
 __asm__ volatile("syscall":"=a"(out):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");
 return out;
}
#define C(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
#define CHECK(expr) do{if(!(expr))return __LINE__;}while(0)
static int eq(const char *a,const char *b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
long app_main(long argc,char **argv,char **env)
{
 long master,slave,index=99,lock=0,r;unsigned char readback[8],tc[36],size[8];
 unsigned int i;char path[]="/dev/pts/0";
 (void)env;CHECK(argc==3);
 master=C(257,-100,"/dev/ptmx",2);CHECK(master>=0);
 if(eq(argv[1],"deny")){
  CHECK(C(257,-100,path,2)<0);
  lock=2;CHECK(C(16,master,0x40045431,&lock)==-22);
  lock=0;CHECK(!C(16,master,0x40045431,&lock));
  CHECK(C(16,master,0x5402,1)==-14);
  CHECK(C(16,master,0x7777,&lock)==-25);
  CHECK(!C(3,master,0,0));return 0;
 }
 CHECK(eq(argv[1],"raw"));
 CHECK(!C(16,master,0x80045430,&index) && index<2);
 path[9]=(char)('0'+index);
 CHECK(!C(16,master,0x40045431,&lock));
 slave=C(257,-100,path,2);CHECK(slave>=0);
 CHECK(!C(16,slave,0x5401,tc));
 for(i=0;i<36;i++)tc[i]=0;
 tc[8]=0xb0;tc[23]=1;
 CHECK(!C(16,slave,0x5402,tc));
 size[0]=40;size[1]=0;size[2]=120;size[3]=0;
 for(i=4;i<8;i++)size[i]=0;
 CHECK(!C(16,master,0x5414,size));
 for(i=0;i<8;i++)size[i]=0;
 CHECK(!C(16,slave,0x5413,size));
 CHECK(size[0]==40 && size[2]==120);
 CHECK(C(1,master,"to",2)==2);
 CHECK(C(0,slave,readback,2)==2 && readback[0]=='t' && readback[1]=='o');
 CHECK(C(1,slave,"ok",2)==2);
 CHECK(C(0,master,readback,2)==2 && readback[0]=='o' && readback[1]=='k');
 CHECK(!C(3,slave,0,0));CHECK(!C(3,master,0,0));
 r=C(1,1,"FLEX_PTY_RAW_OK\n",16);CHECK(r==16);
 return 0;
}
