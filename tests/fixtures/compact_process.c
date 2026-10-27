/* SPDX-License-Identifier: AGPL-3.0-only */
typedef unsigned long U;
extern void _start(void);
static long call6(long nr,long a,long b,long c,long d,long e,long f)
{
    register long r10 __asm__("r10")=d;
    register long r8 __asm__("r8")=e;
    register long r9 __asm__("r9")=f;
    long result;
    __asm__ volatile("syscall":"=a"(result):"a"(nr),"D"(a),"S"(b),"d"(c),
        "r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");
    return result;
}
static __attribute__((noinline)) U length(const char *s)
{
    U i=0;
    while(s[i])i++;
    return i;
}
static int equal(const char *a,const char *b)
{
    while(*a && *a==*b){a++;b++;}
    return *a==*b;
}
long app_main(long argc,char **argv,char **envp)
{
    unsigned char *p,*q,*heap;
    U *aux, pages=0, phdr=0, phnum=0, phent=0, entry=0, i, total=0;
    long base;
    if(argc!=2 || !argv[1] || argv[argc]!=0 || envp[0]==0 || envp[1]!=0 || !equal(envp[0],"FLEX_MODE=test"))return 81;
    while(*envp)envp++;
    aux=(U *)(envp+1);
    for(;aux[0];aux+=2){
        if(aux[0]==6)pages=aux[1];
        if(aux[0]==3)phdr=aux[1];
        if(aux[0]==4)phent=aux[1];
        if(aux[0]==5)phnum=aux[1];
        if(aux[0]==9)entry=aux[1];
    }
    if(pages!=4096 || phdr==0 || phnum==0 || phent!=56 || entry!=(U)&_start || *(unsigned int *)phdr==0)return 82;
    p=(unsigned char *)call6(9,0,4096,3,34,-1,0);
    if((long)p<0)return 83;
    for(i=0;i<256;i++)p[i]=(unsigned char)i;
    for(i=0;i<256;i++)total+=p[i];
    if(total!=32640 || call6(10,(long)p,4096,1,0,0,0)!=0)return 84;
    if(p[255]!=255 || call6(10,(long)p,4096,3,0,0,0)!=0)return 85;
    p[0]=111;
    if(call6(11,(long)p,4096,0,0,0,0)!=0)return 86;
    q=(unsigned char *)call6(9,0,4096,3,34,-1,0);
    if((long)q<0 || q[0]!=0 || call6(11,(long)q,4096,0,0,0,0)!=0)return 87;
    base=call6(12,0,0,0,0,0,0);
    if(base<=0 || call6(12,base+4096,0,0,0,0,0)!=base+4096)return 88;
    heap=(unsigned char *)base; heap[0]=17; heap[4095]=29;
    if(heap[0]+heap[4095]!=46 || call6(12,base,0,0,0,0,0)!=base)return 89;
    if(call6(1,1,(long)"FLEX_COMPILED_C_OK\n",19,0,0,0)!=19)return 90;
    if(call6(1,1,(long)argv[1],(long)length(argv[1]),0,0,0)<0)return 91;
    if(call6(1,1,(long)"\n",1,0,0,0)!=1)return 92;
    return 0;
}
