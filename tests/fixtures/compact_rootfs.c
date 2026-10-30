/* SPDX-License-Identifier: AGPL-3.0-only */
typedef unsigned long U;
static __attribute__((always_inline)) inline long call(long nr,long a,long b,long c,long d,long e,long f)
{register long r10 __asm__("r10")=d;register long r8 __asm__("r8")=e;register long r9 __asm__("r9")=f;long out;__asm__ volatile("syscall":"=a"(out):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;}
#define C(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
#define CHECK(x) do{if(!(x))return __LINE__;}while(0)
static int eq(const char *a,const char *b){while(*a && *a==*b){a++;b++;}return *a==*b;}
static U len(const char *s){U n=0;while(s[n])n++;return n;}
static void print(const char *s){C(1,1,s,len(s));}
static long make(const char *path,const char *text){long fd=C(2,path,0102,0600);if(fd>=0 && C(1,fd,text,len(text))!=(long)len(text))return -100;return fd;}
static int content(const char *path,const char *text){char b[256];long fd=C(2,path,0,0),n;if(fd<0)return 0;n=C(0,fd,b,255);C(3,fd,0,0);if(n<0)return 0;b[n]=0;return eq(b,text);}
long app_main(long argc,char **argv,char **env)
{
 const char *roots[]={"/etc","/home","/usr","/var","/tmp"};
 const char *files[]={"/etc/settings","/home/project/main.c","/usr/local/tool","/var/log","/tmp/scratch"};
 char b[256];U st[18],second[18];long fd,dir,i,pid,status;(void)env;CHECK(argc==3);
 if(eq(argv[1],"create")){
  for(i=0;i<5;i++)CHECK(!C(4,roots[i],st,0) && (((unsigned int *)st)[6]&0170000)==0040000);
  CHECK(!C(83,"/home/project",0700,0) && !C(83,"/usr/local",0700,0));
  for(i=0;i<5;i++){fd=make(files[i],argv[2]);CHECK(fd>=0 && !C(3,fd,0,0));}
  CHECK(!C(86,"/home/project/main.c","/var/main-link",0));
  CHECK(!C(88,"../../var/main-link","/home/project/source",0));
  CHECK(content("/home/project/source",argv[2]));
  CHECK(!C(90,"/etc/settings",0640,0));
 }else if(eq(argv[1],"reload")){
  for(i=0;i<5;i++)CHECK(content(files[i],argv[2]));
  CHECK(content("/home/project/source",argv[2]));
  CHECK(!C(4,files[1],st,0) && !C(4,"/var/main-link",second,0) && st[1]==second[1] && st[2]==2);
  CHECK(!C(4,files[0],st,0) && (((unsigned int *)st)[6]&0777)==0640);
 }else if(eq(argv[1],"fresh")){
  CHECK(C(4,"/etc/settings",st,0)==-2 && C(4,"/home/project",st,0)==-2);
 }else if(eq(argv[1],"cwd")){
  CHECK(!C(80,"/",0,0) && C(79,b,256,0)==2 && eq(b,"/"));
  CHECK(!C(83,"/home/project",0700,0) && !C(80,"/home/project",0,0));
  CHECK(C(79,b,256,0)==14 && eq(b,"/home/project"));
  CHECK(!C(80,"../../usr",0,0) && C(79,b,256,0)==5 && eq(b,"/usr"));
  dir=C(2,"/home",0200000,0);CHECK(dir>=0);
  fd=call(257,dir,(long)"project/file",0102,0600,0,0);CHECK(fd>=0 && C(1,fd,argv[2],len(argv[2]))==(long)len(argv[2]) && !C(3,fd,0,0));
  CHECK(!C(81,dir,0,0) && C(79,b,256,0)==6 && eq(b,"/home") && content("project/file",argv[2]));
  dir=C(2,"/",0200000,0);CHECK(dir>=0 && C(217,dir,b,256)>0 && !C(81,dir,0,0));
  CHECK(C(79,b,256,0)==2 && eq(b,"/"));
  CHECK(!C(83,"/work",0700,0) && !C(82,"/work","/renamed",0) && !C(84,"/renamed",0,0));
  CHECK(C(84,"/",0,0)==-16 && C(82,"/","/other",0)==-16);
 }else if(eq(argv[1],"deny")){
  CHECK(C(2,"/dev/host-secret",0102,0600)<0 && C(83,"/proc/escape",0700,0)<0 && C(83,"/compat/escape",0700,0)<0);
  CHECK(!C(88,"/proc/self/mem","/home/escape",0) && C(2,"/home/escape",0,0)<0);
  CHECK(!C(88,"/dev/host-secret","/tmp/host",0) && C(2,"/tmp/host",0102,0600)<0);
  CHECK(!C(90,"/home",0500,0) && C(2,"/home/denied",0102,0600)==-13);
  CHECK(!C(90,"/home",0700,0));
  fd=make("/etc/settings","guest-only");CHECK(fd>=0 && !C(3,fd,0,0));
  CHECK(C(2,"/etc/../../proc/host",0,0)<0);
 }else if(eq(argv[1],"fork")){
  pid=C(57,0,0,0);CHECK(pid>=0);
  if(!pid){fd=make("/home/child",argv[2]);CHECK(fd>=0 && !C(3,fd,0,0));return 0;}
  CHECK(C(61,pid,&status,0)==pid && status==0 && content("/home/child",argv[2]));
 }else if(eq(argv[1],"legacy")){
  CHECK(C(4,"/home",st,0)<0 && C(2,"/etc/denied",0102,0600)<0);
  fd=make("/tmp/legacy",argv[2]);CHECK(fd>=0 && !C(3,fd,0,0));
 }else return 99;
 print("FLEX_ROOTFS_OK ");print(argv[1]);print("\n");print(argv[2]);print("\n");return 0;
}
