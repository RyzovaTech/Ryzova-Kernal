/* SPDX-License-Identifier: AGPL-3.0-only */
typedef unsigned long U;
static __attribute__((always_inline)) inline long call(long nr,long a,long b,long c,long d,long e,long f)
{register long r10 __asm__("r10")=d;register long r8 __asm__("r8")=e;register long r9 __asm__("r9")=f;long out;__asm__ volatile("syscall":"=a"(out):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;}
#define C(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
#define CHECK(x) do{if(!(x))return __LINE__;}while(0)
static int equal(const char *a,const char *b){while(*a && *a==*b){a++;b++;}return *a==*b;}
static U length(const char *s){U n=0;while(s[n])n++;return n;}
static void print(const char *s){C(1,1,s,length(s));}
static int content(const char *path,const char *text)
{char bytes[256];long fd=C(2,path,0,0),n;if(fd<0)return 0;n=C(0,fd,bytes,255);C(3,fd,0,0);if(n<0)return 0;bytes[n]=0;return equal(bytes,text);}
static unsigned char thread_stack[16384] __attribute__((aligned(16)));
static volatile int thread_ready;static char *thread_args[5],*thread_env[1];
__attribute__((naked)) static long spawn(void *fn,void *top,U flags)
{
 (void)fn;(void)top;(void)flags;
 __asm__ volatile("mov %rdi,%r9; mov %rdx,%rdi; xor %edx,%edx; xor %r10d,%r10d; xor %r8d,%r8d; and $-16,%rsi; mov $56,%eax; syscall; test %eax,%eax; jnz 1f; xor %ebp,%ebp; call *%r9; mov %eax,%edi; mov $60,%eax; syscall; ud2; 1: ret");
}
static long exec_worker(void)
{
 while(!thread_ready)C(24,0,0,0);
 C(59,"application",thread_args,thread_env);C(231,91,0,0);return 91;
}
long app_main(long argc,char **argv,char **env)
{
 long fd,dir,n,status,pid;char bytes[256];U st[18],other[18];(void)env;CHECK(argc==4);
 if(equal(argv[2],"thread-executed")){print("FLEX_SYMLINK_OK thread-exec\n");print(argv[3]);print("\n");return 0;}
 if(equal(argv[2],"executed")){CHECK(argc==4);return 7;}
 if(!equal(argv[2],"reload") && !equal(argv[2],"legacy") && !equal(argv[2],"shadow")){CHECK(!C(83,argv[1],0700,0));}
 CHECK(!C(80,argv[1],0,0));
 if(equal(argv[2],"basic") || equal(argv[2],"create")){
  fd=C(2,"file",0101,0600);CHECK(fd>=0 && C(1,fd,argv[3],length(argv[3]))==(long)length(argv[3]) && !C(3,fd,0,0));
  CHECK(!C(88,"file","link",0));CHECK(!C(88,"link","chain",0));CHECK(content("chain",argv[3]));
  CHECK(!C(6,"link",st,0) && (((unsigned int *)st)[6]&0170000)==0120000 && st[6]==4);
  CHECK(!C(4,"link",st,0) && !C(4,"file",other,0) && st[1]==other[1]);
  bytes[0]='?';bytes[2]='!';CHECK(C(89,"link",bytes,2)==2 && bytes[0]=='f' && bytes[1]=='i' && bytes[2]=='!');
  CHECK(!C(83,"sub",0700,0) && !C(88,"../chain","sub/relative",0));CHECK(content("sub/relative",argv[3]));
  CHECK(!C(88,"sub","directory",0) && !C(80,"directory",0,0));CHECK(content("../link",argv[3]));CHECK(!C(80,"..",0,0));
 }else if(equal(argv[2],"reload")){
  CHECK(content("chain",argv[3]) && content("sub/relative",argv[3]));
  CHECK(C(89,"link",bytes,sizeof bytes)==4 && bytes[0]=='f' && bytes[3]=='e');
  CHECK(!C(6,"directory",st,0) && (((unsigned int *)st)[6]&0170000)==0120000);
 }else if(equal(argv[2],"shadow")){
  fd=C(2,"link",0,0);CHECK(fd>=0 && C(0,fd,bytes,4)==4 && bytes[0]==127 && !C(3,fd,0,0));
  CHECK(C(2,"link",01001,0)==-13 && C(89,"link",bytes,10)==-22);
  CHECK(!C(6,"link",st,0) && (((unsigned int *)st)[6]&0170000)==0100000);
 }else if(equal(argv[2],"legacy")){
  CHECK(content("absent","ok") && C(6,"dangling",st,0)==-2);
 }else if(equal(argv[2],"nofollow")){
  CHECK(!C(88,"absent","dangling",0));CHECK(C(2,"dangling",0400000,0)==-40);
  CHECK(C(2,"dangling",0301,0600)==-17 && C(4,"dangling",st,0)==-2);
  fd=C(2,"dangling",0101,0600);CHECK(fd>=0 && C(1,fd,"ok",2)==2 && !C(3,fd,0,0));CHECK(content("absent","ok"));
  CHECK(C(89,"absent",bytes,10)==-22 && C(89,"dangling",bytes,0)==-22 && C(89,"dangling",-1,10)==-14);
  CHECK(!call(262,-100,(long)"dangling",(long)st,256,0,0) && (((unsigned int *)st)[6]&0170000)==0120000);
  CHECK(!C(87,"dangling",0,0) && content("absent","ok"));
 }else if(equal(argv[2],"loops")){
  CHECK(!C(88,"a","a",0) && C(2,"a",0,0)==-40 && C(4,"a",st,0)==-40);
  CHECK(!C(6,"a",st,0) && C(89,"a",bytes,10)==1);
  CHECK(!C(88,"c","b",0) && !C(88,"b","c",0) && C(2,"b",0,0)==-40);
  CHECK(C(88,"","empty",0)==-2 && C(88,-1,"bad",0)==-14);
  CHECK(!C(88,"missing/../file","missing-parent",0) && C(2,"missing-parent",0101,0600)==-2);
 }else if(equal(argv[2],"at")){
  CHECK(!C(83,"sub",0700,0));dir=C(2,"sub",0,0);CHECK(dir>=0);
  CHECK(!call(266,(long)"file",dir,(long)"link",0,0,0));
  fd=call(257,dir,(long)"link",0101,0600,0,0);CHECK(fd>=0 && C(1,fd,"at",2)==2 && !C(3,fd,0,0));
  CHECK(content("sub/file","at"));CHECK(call(267,dir,(long)"link",(long)bytes,3,0,0)==3 && bytes[2]=='l');
  CHECK(!call(262,dir,(long)"link",(long)st,256,0,0) && (((unsigned int *)st)[6]&0170000)==0120000);
  CHECK(!call(263,dir,(long)"link",0,0,0,0) && content("sub/file","at"));
 }else if(equal(argv[2],"rename")){
  CHECK(!C(88,"absent","old",0) && !C(88,"other","new",0));
  CHECK(!C(82,"old","new",0) && C(6,"old",st,0)==-2 && C(89,"new",bytes,100)==6);
  CHECK(!C(83,"dir",0700,0) && !C(88,"dir","alias",0));
  CHECK(C(84,"alias",0,0)==-20 && !C(87,"alias",0,0) && !C(84,"dir",0,0));
 }else if(equal(argv[2],"times")){
  U times[4]={11,123,22,456};fd=C(2,"file",0101,0600);CHECK(fd>=0 && !C(3,fd,0,0) && !C(88,"file","link",0));
  CHECK(!call(280,-100,(long)"link",(long)times,256,0,0));
  CHECK(!C(6,"link",st,0) && st[9]==11 && st[11]==22 && !C(4,"file",other,0) && other[9]!=11);
  CHECK(!call(280,-100,(long)"link",(long)times,0,0,0) && !C(4,"file",other,0) && other[9]==11);
 }else if(equal(argv[2],"boundary")){
  U i,at;CHECK(!C(83,"sub",0700,0) && !C(88,"sub","d",0));
  fd=C(2,"file",0101,0600);CHECK(fd>=0 && C(1,fd,"ok",2)==2 && !C(3,fd,0,0));
  for(n=39;n<=41;n++){
   at=0;for(i=0;i<(U)n;i++){bytes[at++]='d';bytes[at++]='/';bytes[at++]='.';bytes[at++]='.';bytes[at++]='/';}
   bytes[at++]='f';bytes[at++]='i';bytes[at++]='l';bytes[at++]='e';bytes[at]=0;
   if(n<=40)CHECK(content(bytes,"ok"));else CHECK(C(2,bytes,0,0)==-40);
  }
 }else if(equal(argv[2],"permissions")){
  CHECK(!C(83,"sub",0700,0) && !C(88,"sub/hidden","link",0) && !C(90,"sub",0,0));
  CHECK(C(2,"link",0101,0600)==-13 && !C(6,"link",st,0));
  CHECK(!C(90,"sub",0700,0) && C(95,077,0,0)>=0 && !C(88,"missing","masked",0));
  CHECK(!C(6,"masked",st,0) && (((unsigned int *)st)[6]&0777)==0777);
 }else if(equal(argv[2],"thread-exec")){
  CHECK(!C(83,"sub",0700,0) && !C(88,argv[0],"sub/application",0));
  thread_args[0]=argv[0];thread_args[1]=argv[1];thread_args[2]="thread-executed";thread_args[3]=argv[3];
  CHECK(spawn(exec_worker,thread_stack+sizeof thread_stack,0x10f00)>0);
  CHECK(!C(80,"sub",0,0));thread_ready=1;for(;;)C(24,0,0,0);
 }else if(equal(argv[2],"grants")){
  char *av[5]={argv[0],argv[1],"executed",argv[3],0},*ev[1]={0};
  CHECK(!C(88,"/dev/null","null",0));fd=C(2,"null",1,0);CHECK(fd>=0 && C(1,fd,"x",1)==1 && !C(3,fd,0,0));
  CHECK(!C(88,argv[0],"application",0));fd=C(2,"application",0,0);CHECK(fd>=0 && C(0,fd,bytes,4)==4 && bytes[0]==127 && !C(3,fd,0,0));
  fd=C(2,"application",01001,0);CHECK(fd==-13 || fd==-26);
  pid=C(57,0,0,0);CHECK(pid>=0);if(!pid){C(59,"application",av,ev);return 99;}
  CHECK(C(61,pid,&status,0)==pid && status==(7<<8));
  dir=C(2,".",0,0);CHECK(dir>=0);
  fd=call(257,dir,(long)"application",0,0,0,0);CHECK(fd>=0 && C(0,fd,bytes,4)==4 && bytes[0]==127 && !C(3,fd,0,0));
  CHECK(!call(262,dir,(long)"application",(long)st,0,0,0) && (((unsigned int *)st)[6]&0170000)==0100000);
 }else if(equal(argv[2],"trailing-mutations")){
  CHECK(!C(83,"dir",0700,0) && !C(88,"dir","link",0) && !C(88,"missing","dangling",0));
  CHECK(C(84,"link/",0,0)==-20 && C(87,"link/",0,0)==-20 && C(82,"link/","renamed",0)==-20);
  CHECK(C(82,"dir","link/",0)==-20 && !C(4,"dir",st,0));
  CHECK(C(83,"dangling/",0700,0)==-17 && C(88,"x","link/",0)==-17 && C(4,"missing",st,0)==-2);
 }else if(equal(argv[2],"trailing")){
  fd=C(2,"file",0101,0600);CHECK(fd>=0 && !C(3,fd,0,0));CHECK(!C(88,"file/","link",0));
  CHECK(C(2,"link",0,0)==-20 && C(4,"link",st,0)==-20 && !C(6,"link",st,0));
  CHECK(!C(88,"file","plain",0) && C(4,"plain/",st,0)==-20);
 }else return 99;
 print("FLEX_SYMLINK_OK ");print(argv[2]);print("\n");print(argv[3]);print("\n");return 0;
}
