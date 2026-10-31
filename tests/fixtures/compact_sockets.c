/* SPDX-License-Identifier: AGPL-3.0-only */
typedef unsigned long U;
static unsigned char big[4096];
static __attribute__((always_inline)) inline long call(long nr,long a,long b,long c,long d,long e,long f)
{
 register long r10 __asm__("r10")=d;register long r8 __asm__("r8")=e;register long r9 __asm__("r9")=f;long out;
 __asm__ volatile("syscall":"=a"(out):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;
}
#define C(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
#define CHECK(x) do{if(!(x))return __LINE__;}while(0)
static int equal(const char *a,const char *b){while(*a && *a==*b){a++;b++;}return *a==*b;}
static void print(const char *s){U n=0;while(s[n])n++;C(1,1,s,n);}
static int pair(int *fds,int flags){return (int)call(53,1,1|flags,0,(long)fds,0,0);}
static int waitchild(long pid){int status;return C(61,pid,&status,0)==pid && status==0;}
long app_main(long argc,char **argv,char **env)
{
 int fds[2],status=0;long n,fd,child,server,client,accepted;unsigned int length;char data[32];
 unsigned char address[32]={2,0},peer[128]={0};U statbuf[18];
 struct {int fd;unsigned short events,revents;} pollfd;
 (void)env;CHECK(argc==3);
 if(equal(argv[1],"pair")){
  CHECK(!pair(fds,0));CHECK(C(1,fds[0],"hello",5)==5 && C(0,fds[1],data,5)==5);
  CHECK(data[0]=='h' && data[4]=='o' && C(1,fds[1],"ok",2)==2 && C(0,fds[0],data,2)==2 && data[1]=='k');
  CHECK(!C(5,fds[0],statbuf,0) && (((unsigned int *)statbuf)[6]&0170000)==0140000);
 }else if(equal(argv[1],"unix") || equal(argv[1],"inet") || equal(argv[1],"inet6") || equal(argv[1],"accept-fault")){
  int domain=equal(argv[1],"unix")?1:(equal(argv[1],"inet6")?10:2);
  unsigned int addrsize=domain==10?28:16;
  U unique=(U)C(39,0,0,0);
  address[0]=(unsigned char)domain;
  if(domain==1){unsigned int i;for(i=3;i<16;i++){address[i]=(unsigned char)(unique%26+'a');unique=unique/26+3;}}
  else if(domain==10){address[23]=1;}
  else{address[4]=127;address[7]=1;}
  server=C(41,domain,1,0);CHECK(server>=0 && !C(49,server,address,addrsize) && !C(50,server,4,0));
  length=addrsize;CHECK(!C(51,server,address,&length) && length==addrsize);
  child=C(57,0,0,0);CHECK(child>=0);
  if(!child){
   client=C(41,domain,1,0);CHECK(client>=0 && !C(42,client,address,addrsize));CHECK(C(1,client,"request",7)==7);
   CHECK(C(0,client,data,32)==5 && data[0]=='r' && data[4]=='y');CHECK(!C(48,client,1,0));CHECK(C(0,client,data,32)==0);return 0;
  }
  if(equal(argv[1],"accept-fault"))CHECK(C(43,server,1,&length)==-14);
  length=sizeof peer;accepted=C(43,server,peer,&length);CHECK(accepted>=0 && peer[0]==domain);
  CHECK(C(0,accepted,data,32)==7 && data[0]=='r' && data[6]=='t');CHECK(C(1,accepted,"reply",5)==5);
  length=sizeof peer;CHECK(!C(52,accepted,peer,&length) && peer[0]==domain);
  CHECK(!C(48,accepted,1,0) && C(0,accepted,data,32)==0 && !C(3,accepted,0,0) && waitchild(child));
 }else if(equal(argv[1],"peek")){
  CHECK(!pair(fds,0) && C(1,fds[0],"abc",3)==3);
  CHECK(call(45,fds[1],(long)data,2,2,0,0)==2 && data[1]=='b');
  CHECK(C(0,fds[1],data,3)==3 && data[0]=='a' && data[2]=='c');
 }else if(equal(argv[1],"poll")){
  CHECK(!pair(fds,0));pollfd.fd=fds[1];pollfd.events=5;
  CHECK(C(7,&pollfd,1,0)==1 && pollfd.revents==4);
  CHECK(C(1,fds[0],"a",1)==1);pollfd.events=1;CHECK(C(7,&pollfd,1,0)==1 && (pollfd.revents&1));
  CHECK(!C(48,fds[0],1,0));pollfd.events=8193;CHECK(C(7,&pollfd,1,0)==1 && (pollfd.revents&8193)==8193);
 }else if(equal(argv[1],"shutdown")){
  CHECK(!pair(fds,0) && C(1,fds[0],"abc",3)==3 && !C(48,fds[0],1,0));
  CHECK(C(0,fds[1],data,32)==3 && C(0,fds[1],data,32)==0);
  CHECK(C(1,fds[1],"x",1)==1 && C(0,fds[0],data,1)==1);
  CHECK(!C(48,fds[0],0,0) && C(0,fds[0],data,1)==0);
  CHECK(call(44,fds[1],(long)"x",1,16384,0,0)==-32);
 }else if(equal(argv[1],"sigpipe")){
  CHECK(!pair(fds,0));child=C(57,0,0,0);CHECK(child>=0);
  if(!child){C(3,fds[1],0,0);C(48,fds[0],1,0);C(1,fds[0],"x",1);return 99;}
  CHECK(C(61,child,&status,0)==child && status==13);
 }else if(equal(argv[1],"nonblock")){
  CHECK(!pair(fds,04000|02000000));CHECK(C(0,fds[0],data,1)==-11 && (C(72,fds[0],3,0)&04000));
  CHECK(C(72,fds[0],1,0)==1 && call(45,fds[0],(long)data,1,64,0,0)==-11);
  fd=C(41,2,1|04000,0);CHECK(fd>=0 && C(43,fd,0,0)==-22);
 }else if(equal(argv[1],"alias")){
  CHECK(!pair(fds,0));fd=C(32,fds[0],0,0);CHECK(fd>=0 && !C(3,fds[0],0,0));
  CHECK(C(1,fd,"a",1)==1 && C(0,fds[1],data,1)==1);
  CHECK(!C(3,fd,0,0) && C(0,fds[1],data,1)==0);
 }else if(equal(argv[1],"reclaim")){
  int i;for(i=0;i<100;i++){CHECK(!pair(fds,0));CHECK(!C(3,fds[0],0,0) && !C(3,fds[1],0,0));}
 }else if(equal(argv[1],"backpressure")){
  CHECK(!pair(fds,04000));CHECK(C(1,fds[0],big,sizeof big)==sizeof big);
  CHECK(C(1,fds[0],big,sizeof big)==-11 && C(0,fds[1],big,sizeof big)==sizeof big);
  CHECK(C(1,fds[0],"a",1)==1 && C(0,fds[1],data,1)==1);
 }else if(equal(argv[1],"bound")){
  address[4]=127;address[7]=1;fd=C(41,2,1,0);CHECK(fd>=0 && !C(49,fd,address,16));length=16;CHECK(!C(51,fd,address,&length));
  client=C(41,2,1,0);CHECK(client>=0 && C(49,client,address,16)==-98);
  CHECK(!C(50,fd,1,0) && !C(3,fd,0,0) && !C(49,client,address,16));
 }else if(equal(argv[1],"errors")){
  CHECK(C(41,999,1,0)==-97 && C(41,10,3,0)==-94 && C(41,1,2,0)==-94 && C(41,2,1,17)==-93);
  fd=C(41,2,1,0);CHECK(fd>=0);address[4]=127;address[7]=1;CHECK(C(42,fd,address,16)==-111);
  CHECK(C(48,fd,1,0)==-107 && C(49,fd,1,16)==-14 && C(43,1,0,0)==-88);
 }else if(equal(argv[1],"udp4") || equal(argv[1],"udp6")){
  int domain=equal(argv[1],"udp6")?10:2;
  int addrsize=domain==10?28:16;
  unsigned int src_length;
  address[0]=(unsigned char)domain;
  if(domain==10)address[23]=1;
  else{address[4]=127;address[7]=1;}
  server=C(41,domain,2|04000,0);
  CHECK(server>=0 && !C(49,server,address,addrsize));
  length=addrsize;CHECK(!C(51,server,address,&length) && length==addrsize);
  client=C(41,domain,2,0);CHECK(client>=0);
  CHECK(call(44,client,(long)"packet",6,0,(long)address,addrsize)==6);
  src_length=sizeof peer;
  CHECK(call(45,server,(long)data,3,2,(long)peer,(long)&src_length)==3);
  CHECK(data[0]=='p' && data[2]=='c' && src_length==addrsize && peer[0]==domain);
  src_length=sizeof peer;
  CHECK(call(45,server,(long)data,32,0,(long)peer,(long)&src_length)==6);
  CHECK(data[0]=='p' && data[5]=='t' && src_length==addrsize);
  CHECK(call(45,server,(long)data,32,0,0,0)==-11);
  CHECK(!C(42,client,address,addrsize) && C(1,client,"last",4)==4);
  CHECK(C(0,server,data,2)==2 && data[0]=='l' && data[1]=='a');
  CHECK(C(0,server,data,32)==-11);
  CHECK(C(50,server,1,0)==-95 && C(43,server,0,0)==-95);
 }else if(equal(argv[1],"udp-quota")){
  int i;
  address[0]=2;address[4]=127;address[7]=1;
  server=C(41,2,2|04000,0);
  CHECK(server>=0 && !C(49,server,address,16));
  length=16;CHECK(!C(51,server,address,&length) && length==16);
  client=C(41,2,2|04000,0);CHECK(client>=0);
  CHECK(call(44,client,1,1,0,(long)address,16)==-14);
  for(i=0;i<4;i++)CHECK(call(44,client,(long)"x",1,0,(long)address,16)==1);
  CHECK(call(44,client,(long)"y",1,0,(long)address,16)==-11);
  CHECK(C(0,server,data,1)==1 && data[0]=='x');
  CHECK(call(44,client,(long)"z",1,0,(long)address,16)==1);
  for(i=0;i<3;i++)CHECK(C(0,server,data,1)==1 && data[0]=='x');
  CHECK(C(0,server,data,1)==1 && data[0]=='z');
  CHECK(C(0,server,data,1)==-11);
  CHECK(call(44,client,(long)big,sizeof big+1,0,(long)address,16)==-90);
 }else if(equal(argv[1],"udp-deny")){
  unsigned char offlink[28]={2,0};
  fd=C(41,2,2,0);CHECK(fd>=0);
  offlink[4]=10;offlink[7]=2;
  CHECK(call(44,fd,(long)"x",1,0,(long)offlink,16)==-101);
  CHECK(C(42,fd,offlink,16)==-101);
  CHECK(!C(3,fd,0,0));
 }else if(equal(argv[1],"ipv6-deny")){
  unsigned char offlink[28]={10,0};
  fd=C(41,10,1,0);CHECK(fd>=0);
  offlink[8]=0x20;offlink[23]=1;
  CHECK(C(42,fd,offlink,28)==-101 && C(49,fd,offlink,28)==-101);
  CHECK(!C(3,fd,0,0));
 }else if(equal(argv[1],"fd-limit")){
  int i,opened[16];for(i=0;i<13;i++){opened[i]=(int)C(41,1,1,0);CHECK(opened[i]>=0);}
  CHECK(C(41,1,1,0)==-24 && pair(fds,0)==-24);
  CHECK(!C(3,opened[0],0,0) && pair(fds,0)==-24);
  CHECK(!C(3,opened[1],0,0) && !pair(fds,0));
 }else if(equal(argv[1],"poll-timeout")){
  U before[2],after[2];CHECK(!pair(fds,0));pollfd.fd=fds[0];pollfd.events=1;
  CHECK(!C(228,1,before,0) && C(7,&pollfd,1,5)==0 && !pollfd.revents && !C(228,1,after,0));
  CHECK(after[0]>before[0] || after[1]-before[1]>=5000000);
 }else if(equal(argv[1],"poll-wake")){
  CHECK(!pair(fds,0));child=C(57,0,0,0);CHECK(child>=0);
  if(!child){U delay[2]={0,1000000};CHECK(!C(35,delay,0,0) && C(1,fds[1],"a",1)==1);return 0;}
  pollfd.fd=fds[0];pollfd.events=1;CHECK(C(7,&pollfd,1,-1)==1 && (pollfd.revents&1));
  CHECK(C(0,fds[0],data,1)==1 && waitchild(child));
 }else if(equal(argv[1],"message")){
  struct Iov {U at,length;} vectors[2];
  struct Msg {U name;unsigned int namelen,pad;U iov,iovlen,control,controllen;unsigned int flags,pad2;} msg={0};
  CHECK(!pair(fds,0));vectors[0].at=(U)"abc";vectors[0].length=3;vectors[1].at=(U)"def";vectors[1].length=3;
  msg.iov=(U)vectors;msg.iovlen=2;CHECK(C(46,fds[0],&msg,0)==6);
  vectors[0].at=(U)data;vectors[0].length=2;vectors[1].at=(U)(data+2);vectors[1].length=4;
  CHECK(C(47,fds[1],&msg,2)==6 && data[0]=='a' && data[5]=='f' && !msg.flags && !msg.controllen);
  CHECK(C(47,fds[1],&msg,0)==6 && data[2]=='c' && data[5]=='f');
 }else if(equal(argv[1],"options")){
  int value=1,result=0;fd=C(41,2,1,0);CHECK(fd>=0);
  CHECK(!call(54,fd,1,2,(long)&value,4,0));length=4;CHECK(!call(55,fd,1,2,(long)&result,(long)&length,0) && result==1 && length==4);
  CHECK(!call(54,fd,6,1,(long)&value,4,0));length=4;CHECK(!call(55,fd,6,1,(long)&result,(long)&length,0) && result==1);
  length=4;CHECK(!call(55,fd,1,3,(long)&result,(long)&length,0) && result==1);
  result=0;length=2;CHECK(!call(55,fd,1,3,(long)&result,(long)&length,0) && result==1 && length==2);
  CHECK(call(54,fd,1,65535,(long)&value,4,0)==-92);
 }else if(equal(argv[1],"accept4")){
  address[4]=127;address[7]=1;server=C(41,2,1|04000,0);CHECK(server>=0 && !C(49,server,address,16) && !C(50,server,4,0));
  CHECK(C(43,server,0,0)==-11);length=16;CHECK(!C(51,server,address,&length));
  client=C(41,2,1,0);CHECK(client>=0 && !C(42,client,address,16));
  fd=call(288,server,0,0,04000|02000000,0,0);CHECK(fd>=0 && C(72,fd,1,0)==1 && (C(72,fd,3,0)&04000));
  CHECK(C(0,fd,data,1)==-11);
 }else if(equal(argv[1],"bad-message")){
  struct {U at,length;} vectors[2];
  struct {U name;unsigned int namelen,pad;U iov,iovlen,control,controllen;unsigned int flags,pad2;} msg={0};
  CHECK(!pair(fds,04000));vectors[0].at=(U)data;vectors[0].length=4;vectors[1].at=1;vectors[1].length=4;msg.iov=(U)vectors;msg.iovlen=2;
  CHECK(C(46,fds[0],&msg,0)==-14 && C(0,fds[1],data,1)==-11);
  CHECK(C(1,fds[0],"abcd",4)==4 && C(47,fds[1],&msg,0)==4 && C(0,fds[1],data,1)==-11 && data[3]=='d');
 }else if(equal(argv[1],"wrap")){
  int i;CHECK(!pair(fds,04000));for(i=0;i<100;i++){CHECK(C(1,fds[0],big,3000)==3000);CHECK(C(0,fds[1],big,2000)==2000 && C(0,fds[1],big,1000)==1000);}
 }else if(equal(argv[1],"traffic-quota")){
  int i;CHECK(!pair(fds,0));for(i=0;i<1024;i++)CHECK(C(1,fds[0],big,sizeof big)==sizeof big && C(0,fds[1],big,sizeof big)==sizeof big);
  CHECK(C(1,fds[0],"x",1)==-28);
 }else if(equal(argv[1],"queue-close")){
  address[4]=127;address[7]=1;server=C(41,2,1,0);CHECK(server>=0 && !C(49,server,address,16) && !C(50,server,4,0));length=16;CHECK(!C(51,server,address,&length));
  client=C(41,2,1,0);CHECK(client>=0 && !C(42,client,address,16) && !C(3,server,0,0));
  CHECK(C(0,client,data,1)==0 && call(44,client,(long)"x",1,16384,0,0)==-32);
 }else if(equal(argv[1],"byte-order")){
  U bits=0x1122334455667788UL,flags;unsigned short half=0x1234;unsigned char byte=0x81;
  __asm__ volatile("bswapq %0":"+r"(bits));CHECK(bits==0x8877665544332211UL);
  bits=0xffffffff11223344UL;__asm__ volatile("bswapl %k0":"+r"(bits));CHECK(bits==0x44332211UL);
  __asm__ volatile("rolw $8,%0":"+r"(half)::"cc");CHECK(half==0x3412);
  __asm__ volatile("cmp %2,%2; rolb $1,%0; pushfq; popq %1":"+q"(byte),"=r"(flags):"r"(bits):"cc");
  CHECK(byte==3 && (flags&0x8c5)==0x845);
  byte=1;__asm__ volatile("rorb $1,%0; pushfq; popq %1":"+q"(byte),"=r"(flags)::"cc");CHECK(byte==128 && (flags&0x801)==0x801);
 }else if(equal(argv[1],"namespace")){
  fd=C(41,2,1,0);CHECK(fd>=0);address[4]=10;address[7]=2;CHECK(C(42,fd,address,16)==-101 && C(49,fd,address,16)==-101);
 }else return 99;
 print("FLEX_SOCKETS_OK ");print(argv[1]);print("\n");print(argv[2]);print("\n");return 0;
}
