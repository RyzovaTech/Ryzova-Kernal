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
 long fd,other,dir,n,i,pid,status;U st[18],second[18];char b[256];(void)env;CHECK(argc==4);
 if(!eq(argv[2],"reload") && !eq(argv[2],"reload-mutated") && !eq(argv[2],"reload-single") && !eq(argv[2],"reload-symlinks"))CHECK(!C(83,argv[1],0700,0));
 CHECK(!C(80,argv[1],0,0));
 if(eq(argv[2],"basic") || eq(argv[2],"create")){
  fd=make("first",argv[3]);CHECK(fd>=0 && !C(86,"first","second",0) && !C(86,"second","third",0));
  CHECK(!C(5,fd,st,0) && !C(4,"third",second,0) && st[1]==second[1] && st[2]==3 && second[2]==3);
  CHECK(!C(87,"first",0,0) && !C(5,fd,st,0) && st[2]==2 && content("second",argv[3]));
  CHECK(!C(90,"third",0640,0) && !C(4,"second",st,0) && (((unsigned int *)st)[6]&0777)==0640);
  CHECK(!C(3,fd,0,0));
 }else if(eq(argv[2],"reload")){
  CHECK(C(4,"first",st,0)==-2 && !C(4,"second",st,0) && !C(4,"third",second,0));
  CHECK(st[1]==second[1] && st[2]==2 && second[2]==2 && content("third",argv[3]));
  fd=C(2,"third",02001,0);CHECK(fd>=0 && C(1,fd,"!",1)==1 && !C(3,fd,0,0));
  CHECK(!C(4,"second",st,0) && st[6]==len(argv[3])+1);
 }else if(eq(argv[2],"reload-mutated")){
  CHECK(!C(4,"second",st,0) && !C(4,"third",second,0) && st[1]==second[1] && st[2]==2);
  fd=C(2,"second",0,0);CHECK(fd>=0);n=C(0,fd,b,255);CHECK(n==(long)len(argv[3])+1 && b[n-1]=='!');b[n-1]=0;CHECK(eq(b,argv[3]));
 }else if(eq(argv[2],"single")){
  fd=make("first",argv[3]);CHECK(fd>=0 && !C(86,"first","second",0) && !C(87,"first",0,0) && !C(3,fd,0,0));
 }else if(eq(argv[2],"reload-single")){
  CHECK(!C(4,"second",st,0) && st[2]==1 && content("second",argv[3]) && C(4,"first",st,0)==-2);
 }else if(eq(argv[2],"offsets")){
  fd=make("first","abc");CHECK(fd>=0 && !C(86,"first","second",0));other=C(2,"second",2,0);CHECK(other>=0);
  CHECK(C(0,other,b,1)==1 && b[0]=='a' && C(8,fd,0,1)==3 && C(8,other,0,1)==1);
  CHECK(C(1,other,"Z",1)==1 && content("first","aZc"));CHECK(!C(77,fd,1,0) && content("second","a"));
 }else if(eq(argv[2],"unlink-open")){
  fd=make("first","old");CHECK(fd>=0 && !C(86,"first","second",0));other=C(2,"second",0,0);CHECK(other>=0);
  CHECK(!C(87,"first",0,0) && !C(87,"second",0,0) && !C(5,fd,st,0) && st[2]==0);
  for(i=0;i<40;i++){n=make("recycle","new");CHECK(n>=0 && !C(87,"recycle",0,0) && !C(3,n,0,0));}
  CHECK(C(0,other,b,3)==3 && b[0]=='o' && !C(3,fd,0,0) && !C(3,other,0,0));
 }else if(eq(argv[2],"rename")){
  fd=make("first","one");CHECK(fd>=0 && !C(3,fd,0,0) && !C(86,"first","second",0));
  CHECK(!C(82,"first","second",0) && !C(4,"first",st,0) && st[2]==2);
  fd=make("other","two");CHECK(fd>=0 && !C(86,"other","other-link",0));
  CHECK(!C(82,"second","other",0) && content("other","one") && content("other-link","two"));
  CHECK(!C(5,fd,st,0) && st[2]==1 && !C(4,"first",st,0) && st[2]==2);
 }else if(eq(argv[2],"symlinks")){
  CHECK(!C(83,"a",0700,0) && !C(83,"b",0700,0));fd=make("a/target","A");CHECK(fd>=0 && !C(3,fd,0,0));fd=make("b/target","B");CHECK(fd>=0 && !C(3,fd,0,0));
  CHECK(!C(88,"target","a/link",0) && !C(86,"a/link","b/link",0));
  CHECK(!C(6,"a/link",st,0) && !C(6,"b/link",second,0) && st[1]==second[1] && st[2]==2);
  CHECK(content("a/link","A") && content("b/link","B") && C(89,"b/link",b,100)==6);
  CHECK(!call(265,-100,(long)"a/link",-100,(long)"followed",1024,0));CHECK(content("followed","A"));
  CHECK(!C(4,"a/target",st,0) && st[2]==2 && !C(87,"a/link",0,0) && !C(6,"b/link",st,0) && st[2]==1);
 }else if(eq(argv[2],"reload-symlinks")){
  CHECK(C(6,"a/link",st,0)==-2 && !C(6,"b/link",st,0) && st[2]==1 && content("b/link","B") && content("followed","A"));
  CHECK(!C(4,"a/target",st,0) && !C(4,"followed",second,0) && st[1]==second[1] && st[2]==2);
 }else if(eq(argv[2],"times")){
  U times[4]={11,123,22,456};fd=make("first","time");CHECK(fd>=0 && !C(3,fd,0,0) && !C(86,"first","second",0));
  CHECK(!call(280,-100,(long)"second",(long)times,0,0,0) && !C(4,"first",st,0) && st[9]==11 && st[10]==123 && st[11]==22 && st[12]==456);
  CHECK(!C(88,"first","symlink",0) && !C(86,"symlink","symlink-copy",0));
  CHECK(!call(280,-100,(long)"symlink-copy",(long)times,256,0,0) && !C(6,"symlink",st,0) && st[9]==11 && st[10]==123 && st[11]==22 && st[12]==456);
 }else if(eq(argv[2],"churn")){
  fd=make("first","keep");CHECK(fd>=0 && !C(5,fd,st,0) && !C(86,"first","second",0) && !C(87,"first",0,0) && !C(3,fd,0,0));
  for(i=0;i<50;i++){fd=make("temp","new");CHECK(fd>=0 && !C(86,"temp","temp-link",0) && !C(87,"temp",0,0) && !C(87,"temp-link",0,0) && !C(3,fd,0,0));}
  CHECK(!C(4,"second",second,0) && st[1]==second[1] && second[2]==1 && content("second","keep"));
 }else if(eq(argv[2],"grants")){
  CHECK(C(86,argv[0],"image",0)==-13 && C(86,"/dev/null","null",0)==-18);
  fd=make("first","safe");CHECK(fd>=0 && C(86,"first",argv[0],0)==-13 && !C(5,fd,st,0) && st[2]==1);
 }else if(eq(argv[2],"at")){
  CHECK(!C(83,"a",0700,0) && !C(83,"b",0700,0));fd=make("a/file","at");CHECK(fd>=0 && !C(3,fd,0,0));dir=C(2,"a",0,0);other=C(2,"b",0,0);CHECK(dir>=0 && other>=0);
  CHECK(!call(265,dir,(long)"file",other,(long)"alias",0,0) && content("b/alias","at"));
  CHECK(call(265,dir,(long)"file",other,(long)"bad",2,0)==-22 && call(265,999,(long)"file",other,(long)"bad",0,0)==-9);
 }else if(eq(argv[2],"errors")){
  fd=make("first","safe");CHECK(fd>=0);
  CHECK(C(86,".","dirlink",0)==-1 && C(86,"missing","bad",0)==-2 && C(86,"first","first",0)==-17);
  CHECK(!C(83,"sub",0700,0) && !C(90,"sub",0500,0) && C(86,"first","sub/alias",0)==-13);
  CHECK(C(86,"first","missing/../alias",0)==-2 && C(86,"first","alias/",0)==-2 && C(86,"first/","alias",0)==-20);
  CHECK(!C(88,"missing","dangling",0) && !C(86,"dangling","dangling-copy",0));CHECK(C(4,"dangling-copy",st,0)==-2 && !C(6,"dangling-copy",st,0) && st[2]==2);
 }else if(eq(argv[2],"shared")){
  fd=make("first","parent");CHECK(fd>=0 && !C(86,"first","second",0));pid=C(57,0,0,0);CHECK(pid>=0);
  if(!pid){if(C(76,"second",0,0) || C(8,fd,0,0) || C(1,fd,"child",5)!=5 || C(87,"first",0,0))return 91;return 0;}
  CHECK(C(61,pid,&status,0)==pid && status==0 && content("second","child") && !C(5,fd,st,0) && st[2]==1);
 }else if(eq(argv[2],"quota")){
  fd=make("first","one");CHECK(fd>=0);
  for(i=0;i<29;i++){char name[4]={'n',(char)('0'+i/10),(char)('0'+i%10),0};CHECK(!C(86,"first",name,0));}
  CHECK(C(86,"first","full",0)==-28 && !C(5,fd,st,0) && st[2]==30);
  CHECK(!C(87,"n00",0,0) && !C(86,"first","again",0) && !C(5,fd,st,0) && st[2]==30);
 }else return 99;
 print("FLEX_HARDLINK_OK ");print(argv[2]);print("\n");print(argv[3]);print("\n");return 0;
}
