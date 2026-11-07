/* SPDX-License-Identifier: AGPL-3.0-only */
/* Selected CRT contracts, implemented inside the guest boundary, never forwarded. */
#include "api.h"
#include "files.h"
#ifndef CW_PLAN9
#include <string.h>
#endif
#define CRT_LIMIT 65536U
int cw_crt_export(unsigned int id) { return (id>=CW_MEMCPY && id<=CW_ERRNO) || (id>=CW_CRT_INVALID_HANDLER && id<=CW_CRT_QUICK_EXIT) || id==CW_CRT_RAND_S || id==CW_CRT_SETLOCALE || (id>=CW_CRT_IOB && id<=CW_CRT_WRITE) || (id>=CW_CRT_ISALPHA && id<=CW_CRT_STRNCPY) || id==CW_CRT_GETENV || id==CW_CRT_LOCALE_CODEPAGE || id==CW_CRT_FULLPATH || (id>=CW_CRT_STRERROR && id<=CW_CRT_UNLOCK_FILE); }
const char *cw_crt_alias(unsigned int id) {
    if(id==CW_CRT_FULLPATH || id==CW_CRT_LOCK_FILE || id==CW_CRT_UNLOCK_FILE)return "api-ms-win-crt-filesystem-l1-1-0.dll";
    if(id>=CW_CRT_STRCHR && id<=CW_CRT_MEMCHR)return "api-ms-win-crt-private-l1-1-0.dll";
    if(id>=CW_CRT_ISALPHA && id<=CW_CRT_STRNCPY)return "api-ms-win-crt-string-l1-1-0.dll";
    if(id>=CW_CRT_IOB && id<=CW_CRT_WRITE)return "api-ms-win-crt-stdio-l1-1-0.dll";
    if(id==CW_CRT_SETLOCALE || id==CW_CRT_LOCALE_CODEPAGE)return "api-ms-win-crt-locale-l1-1-0.dll";
    if(id==CW_CRT_RAND_S)return "api-ms-win-crt-utility-l1-1-0.dll";
    if(id==CW_CRT_NEW_MODE)return "api-ms-win-crt-heap-l1-1-0.dll";
    if(id>=CW_MALLOC && id<=CW_FREE)return "api-ms-win-crt-heap-l1-1-0.dll";
    if(id==CW_MEMCPY || id==CW_MEMMOVE || id==CW_MEMCMP)return "api-ms-win-crt-private-l1-1-0.dll";
    if(id==CW_MEMSET || (id>=CW_STRLEN && id<=CW_WCSLEN))return "api-ms-win-crt-string-l1-1-0.dll";
    if(id==CW_CRT_WENV || id==CW_CRT_GETENV)return "api-ms-win-crt-environment-l1-1-0.dll";
    if(id==CW_CRT_FMODE || id==CW_CRT_COMMODE)return "api-ms-win-crt-stdio-l1-1-0.dll";
    if(id==CW_ERRNO || id==CW_CRT_STRERROR || (id>=CW_CRT_INVALID_HANDLER && id<=CW_CRT_APP_TYPE) || id==CW_CRT_INITTERM || (id>=CW_CRT_INITTERM_E && id<=CW_CRT_WARGV) || (id>=CW_CRT_ATEXIT && id<=CW_CRT_QUICK_EXIT))return "api-ms-win-crt-runtime-l1-1-0.dll";
    return NULL;
}
static void error_number(CwServices *s,uint32_t value) { unsigned int i;for(i=0;i<4;i++)s->errno_bytes[i]=(unsigned char)(value>>(8*i)); }
/* A single page allocation backs the diagnostic CRT suballocator. Block
 * metadata stays outside guest memory. Older profiles keep page-per-block
 * behavior so their limits and fault semantics do not change. */
static unsigned int trace_block_index(const CwServices *s,uint64_t at) {
    unsigned int lo=0,hi=s->trace_crt_count;
    while(lo<hi){
        unsigned int mid=lo+(hi-lo)/2;
        if(s->trace_crt_blocks[mid].base<=at)lo=mid+1;
        else hi=mid;
    }
    return lo;
}

int cw_crt_trace_span(const CwServices *s,uint64_t at,size_t n) {
    unsigned int i=trace_block_index(s,at);
    const CwCrtBlock *block;
    if(!i)return 0;
    block=&s->trace_crt_blocks[i-1];
    return at-block->base<=block->capacity && n<=block->capacity-(at-block->base);
}

static uint64_t trace_allocate(CwMachine *m,uint64_t size) {
    CwServices *s=m->services;
    uint64_t bytes=((size?size:1)+15)&~UINT64_C(15);
    uint64_t at,end;
    unsigned int i;
    if(s->trace_crt_count==CW_CRT_TRACE_BLOCKS)return 0;
    if(!s->trace_crt_base){
        /* Leave at least a quarter of the launch heap for virtual allocations. */
        uint64_t arena=(s->heap_bytes/4096)*3/4*4096;
        if(bytes>arena)return 0;
        s->trace_crt_base=cw_heap_allocate(m,arena);
        if(!s->trace_crt_base)return 0;
        s->trace_crt_size=arena;
    }
    at=s->trace_crt_base;
    end=at+s->trace_crt_size;
    for(i=0;i<s->trace_crt_count;i++){
        CwCrtBlock *next=&s->trace_crt_blocks[i];
        if(bytes<=next->base-at)break;
        at=next->base+next->capacity;
    }
    if(bytes>end-at)return 0;
    memmove(&s->trace_crt_blocks[i+1],&s->trace_crt_blocks[i],
            (s->trace_crt_count-i)*sizeof(s->trace_crt_blocks[0]));
    s->trace_crt_blocks[i].base=at;
    s->trace_crt_blocks[i].size=size;
    s->trace_crt_blocks[i].capacity=bytes;
    s->trace_crt_count++;
    return at;
}

int cw_crt_owned(CwMachine *m,uint64_t at) {
    unsigned int i;CwServices *s=m->services;
    if(s->trace_crt_base && at>=s->trace_crt_base && at-s->trace_crt_base<s->trace_crt_size)return 1;
    for(i=0;i<16;i++)if(s->crt_blocks[i].base && at>=s->crt_blocks[i].base && at-s->crt_blocks[i].base<s->crt_blocks[i].capacity)return 1;
    return 0;
}
static CwCrtBlock *block(CwServices *s,uint64_t at) {
    unsigned int i;
    if(s->trace_crt_base){
        i=trace_block_index(s,at);
        return i && s->trace_crt_blocks[i-1].base==at?&s->trace_crt_blocks[i-1]:NULL;
    }
    for(i=0;i<16;i++)if(s->crt_blocks[i].base==at && at)return &s->crt_blocks[i];
    return NULL;
}
static uint64_t allocate(CwMachine *m,uint64_t size) {
    CwServices *s=m->services;unsigned int i;uint64_t at,bytes=size?size:1;
    if(bytes>s->heap_bytes){error_number(s,12);return 0;}
    if(m->plan.profile_flags==CW_PROFILE_TRACE){
        at=trace_allocate(m,size);
        if(!at)error_number(s,12);
        return at;
    }
    for(i=0;i<16;i++)if(!s->crt_blocks[i].base)break;
    if(i==16 || !(at=cw_heap_allocate(m,bytes))){error_number(s,12);return 0;}
    s->crt_blocks[i].base=at;s->crt_blocks[i].size=size;s->crt_blocks[i].capacity=(bytes+4095)&~UINT64_C(4095);return at;
}
static int release(CwMachine *m,uint64_t at) {
    CwCrtBlock *b;if(!at)return CW_OK;
    b=block(m->services,at);if(!b)return CW_CRT;
    if(m->services->trace_crt_base){
        CwServices *s=m->services;
        unsigned int i=(unsigned int)(b-s->trace_crt_blocks);
        unsigned char *p=cw_memory(m,at,(size_t)b->capacity,CW_W);
        if(!p)return CW_CRT;
        memset(p,0,(size_t)b->capacity);
        memmove(b,b+1,(s->trace_crt_count-i-1)*sizeof(*b));
        s->trace_crt_count--;
        return CW_OK;
    }
    if(!cw_heap_release(m,at))return CW_CRT;
    memset(b,0,sizeof(*b));return CW_OK;
}
static int unit(CwMachine *m,uint64_t at,unsigned int width,uint64_t index,uint32_t *out) {
    unsigned char *p;if(index>(UINT64_MAX-at)/width)return CW_CRT;
    p=cw_memory(m,at+index*width,width,CW_R);if(!p)return CW_CRT;
    *out=p[0]|(width==2?(uint32_t)p[1]<<8:0);return CW_OK;
}
/* Initializer callbacks execute through the same CPU and budget as the image.
   Only trusted frames hold the continuation; no guest address is a host function. */
static uint64_t word64(const unsigned char *p) {
    uint64_t v=0;unsigned int i;for(i=0;i<8;i++)v|=(uint64_t)p[i]<<(8*i);return v;
}
static int init_next(CwMachine *m,int returned) {
    CwServices *s=m->services;CwCrtInit *f=&s->crt_initializers[s->crt_init_depth-1];
    unsigned char *p;uint64_t target,value=returned && f->checked==1?(uint32_t)m->r[0]:0;
    if(!value)for(;;) {
        if(f->checked>=2) {
            if(!s->crt_exit_count)break;
            target=s->crt_exit_callbacks[--s->crt_exit_count];
        }else {
            if(f->cursor==f->end)break;
            p=cw_memory(m,f->cursor,8,CW_R);if(!p)return CW_CRT;
            target=word64(p);f->cursor+=8;if(!target)continue;
        }
        if(!cw_memory(m,target,1,CW_X) || f->stack<m->stack_base+48)return CW_CRT;
        p=cw_memory(m,f->stack-48,40,CW_W);if(!p)return CW_CRT;
        memset(p,0,40);{unsigned int i;for(i=0;i<8;i++)p[i]=(unsigned char)(CW_CRT_RETURN>>(i*8));}
        m->r[4]=f->stack-48;m->ip=target;return CW_CRT_PENDING;
    }
    if(f->checked==3) {
        cw_files_close_all(m);m->exit_code=f->code;m->exited=1;m->exit_kind=1;
        s->crt_init_depth--;return CW_CRT_PENDING;
    }
    m->r[0]=value;m->r[4]=f->stack+8;m->ip=f->ret;s->crt_init_depth--;
    if(m->ip>=CW_TLS_RETURN){int status=cw_bootstrap_return(m,m->ip,m->r[4]-8);if(status)return status;}
    return CW_CRT_PENDING;
}
int cw_crt_continue(CwMachine *m) {
    CwServices *s=m->services;int status;
    if(!s || s->bound_machine!=m || !s->crt_init_depth || s->crt_init_depth>CW_CRT_INIT_DEPTH ||
       m->r[4]!=s->crt_initializers[s->crt_init_depth-1].stack-40)return CW_API;
    status=init_next(m,1);return status==CW_CRT_PENDING?CW_OK:status;
}
static int initializers(CwMachine *m,const uint64_t *a,int checked) {
    CwServices *s=m->services;CwCrtInit *f;unsigned char *p;
    if((a[0]&7) || (a[1]&7) || a[1]<a[0] || a[1]-a[0]>2048 ||
       (a[1]!=a[0] && !cw_memory(m,a[0],(size_t)(a[1]-a[0]),CW_R)) || s->crt_init_depth>=CW_CRT_INIT_DEPTH)return CW_CRT;
    p=cw_memory(m,m->r[4],8,CW_R);if(!p)return CW_CRT;
    f=&s->crt_initializers[s->crt_init_depth++];f->cursor=a[0];f->end=a[1];
    f->stack=m->r[4];f->ret=word64(p);f->checked=(uint32_t)checked;f->code=0;
    return init_next(m,0);
}
static int terminate(CwMachine *m,uint32_t code,int callbacks,int returning) {
    CwServices *s=m->services;CwCrtInit *f;unsigned char *p;
    if(!callbacks){cw_files_close_all(m);m->exit_code=code;m->exited=1;m->exit_kind=1;return CW_CRT_PENDING;}
    if(s->crt_init_depth>=CW_CRT_INIT_DEPTH)return CW_CRT;
    p=cw_memory(m,m->r[4],8,CW_R);if(!p)return CW_CRT;
    f=&s->crt_initializers[s->crt_init_depth++];memset(f,0,sizeof(*f));
    f->stack=m->r[4];f->ret=word64(p);f->checked=returning?2:3;f->code=code;
    return init_next(m,0);
}
static void store(unsigned char *p,uint64_t v,unsigned int n) {
    unsigned int i;for(i=0;i<n;i++)p[i]=(unsigned char)(v>>(8*i));
}
static int wide_environment(CwServices *s) {
    unsigned int i,j,at=136;uint64_t base=s->command_base+16384;
    if(s->crt_environment_ready)return CW_OK;
    memset(s->crt_environment,0,sizeof(s->crt_environment));
    for(i=0;i<s->launch.environment_count;i++) {
        store(s->crt_environment+i*8,base+at,8);
        for(j=0;s->launch.environment[i].name[j];j++,at+=2)store(s->crt_environment+at,s->launch.environment[i].name[j],2);
        store(s->crt_environment+at,'=',2);at+=2;
        for(j=0;s->launch.environment[i].value[j];j++,at+=2)store(s->crt_environment+at,s->launch.environment[i].value[j],2);
        at+=2;
    }
    store(s->crt_globals+24,base,8);s->crt_environment_ready=1;return CW_OK;
}
static int wide_arguments(CwServices *s,unsigned int mode) {
    const uint16_t *c=s->launch.command_line;unsigned int i=0,argc=0,at=1032,quoted,n,k;uint16_t ch;
    unsigned char out[4096];uint64_t base=s->command_base+8192;
    if(mode>1)return CW_CRT; /* Wildcard expansion needs a separate filesystem contract. */
    if(s->crt_argv_ready)return s->crt_argv_ready==mode+1?CW_OK:CW_CRT;
    memset(out,0,sizeof(out));
    while(mode && c[i]) {
        while(c[i]==' ' || c[i]=='\t')i++;
        if(!c[i])break;
        if(argc==128)return CW_CRT;
        store(out+argc*8,base+at,8);quoted=0;
        while(c[i]) {
            ch=c[i];
            if(!quoted && (ch==' ' || ch=='\t'))break;
            if(!argc) { /* argv[0] quotes group spaces; backslashes are literal. */
                i++;if(ch=='"'){quoted=!quoted;continue;}
            }else {
                n=0;while(c[i]=='\\'){n++;i++;}
                if(c[i]=='"') {
                    for(k=0;k<n/2;k++){if(at+2>=sizeof(out))return CW_CRT;store(out+at,'\\',2);at+=2;}
                    if(n&1){ch='"';i++;}
                    else {i++;if(quoted && c[i]=='"'){ch='"';i++;}else {quoted=!quoted;continue;}}
                }else {
                    for(k=0;k<n;k++){if(at+2>=sizeof(out))return CW_CRT;store(out+at,'\\',2);at+=2;}
                    ch=c[i];if(!ch || (!quoted && (ch==' ' || ch=='\t')))break;i++;
                }
            }
            if(at+2>=sizeof(out))return CW_CRT;
            store(out+at,ch,2);at+=2;
        }
        at+=2;argc++;
    }
    memcpy(s->crt_argv,out,sizeof(out));store(s->crt_globals+8,argc,4);
    store(s->crt_globals+16,base,8);s->crt_argv_ready=mode+1;return CW_OK;
}
/* FILE values are opaque guest tokens. Provider handles retain the directory
 * grant and are closed by the same namespace cleanup as CreateFileW. */
#define CRT_STREAM_BASE UINT64_C(0x0500000000000000)
#define CRT_TEXT 0x4000U
#define CRT_BINARY 0x8000U

static CwCrtStream *stream_for(CwServices *s,uint64_t token) {
    unsigned int slot=(unsigned int)(token&255);
    if(slot>=CW_CRT_STREAMS || !token || s->crt_streams[slot].token!=token)return NULL;
    return &s->crt_streams[slot];
}

static CwCrtStream *standard_stream(CwServices *s,unsigned int fd) {
    CwCrtStream *stream=&s->crt_streams[fd];
    if(!stream->mode) {
        stream->token=CRT_STREAM_BASE|fd;
        stream->mode=CRT_TEXT;
    }
    return stream;
}

static int stream_output(CwServices *s,unsigned int fd,const unsigned char *data,uint32_t n,uint32_t mode) {
    uint32_t i,bytes=n,offset;
    unsigned int index;
    if(fd<1 || fd>2)return 9;
    index=fd-1;
    if(!(s->launch.console_mask&(1U<<index)) || (s->console_closed&(1U<<index)))return 9;
    if(mode==CRT_TEXT)for(i=0;i<n;i++)if(data[i]=='\n')bytes++;
    if(bytes>CW_OUTPUT_LIMIT-s->output_bytes[0]-s->output_bytes[1])return 28;
    offset=s->output_bytes[index];
    for(i=0;i<n;i++){
        if(data[i]=='\n' && mode==CRT_TEXT)s->output[index][offset++]='\r';
        s->output[index][offset++]=data[i];
    }
    s->output_bytes[index]=offset;
    return 0;
}

static int read_stream(CwMachine *m,CwCrtStream *stream) {
    if(stream->start==stream->end) {
        uint32_t n,error;
        error=cw_file_read_bytes(m,stream->handle,stream->buffer,sizeof(stream->buffer),&n);
        if(error){stream->error=1;error_number(m->services,5);return -1;}
        if(!n){stream->eof=1;return -1;}
        stream->start=0;
        stream->end=n;
    }
    return stream->buffer[stream->start++];
}

static int stream_byte(CwMachine *m,CwCrtStream *stream) {
    int value,next;
    if(stream->eof)return -1;
    value=read_stream(m,stream);
    if(stream->mode==CRT_TEXT) {
        if(value==26){stream->eof=1;return -1;}
        if(value=='\r'){
            next=read_stream(m,stream);
            if(next=='\n')return '\n';
            if(next>=0)stream->start--;
        }
    }
    return value;
}

static uint32_t file_errno(uint32_t error) {
    switch(error) {
    case 2:case 3:return 2;
    case 4:return 24;
    case 5:case 32:return 13;
    case 6:return 9;
    case 87:case 123:return 22;
    default:return 5;
    }
}

static int stdio_call(CwMachine *m,unsigned int id,const uint64_t *a,uint64_t *result) {
    CwServices *s=m->services;
    CwCrtStream *stream;
    uint32_t fd,mode,n,error,i,x,y;
    uint64_t args[7]={0},token,count;
    unsigned char byte,*buffer;
    int ch;
    switch(id) {
    case CW_CRT_IOB:
        if(a[0]<3)*result=standard_stream(s,(unsigned int)a[0])->token;
        return CW_OK;
    case CW_CRT_WFOPEN:
        if(unit(m,a[1],2,0,&x) || unit(m,a[1],2,1,&y))return CW_CRT;
        mode=CRT_TEXT;
        if(x!='r'){error_number(s,13);return CW_OK;}
        if(y){
            if(y!='b' && y!='t'){error_number(s,22);return CW_OK;}
            if(unit(m,a[1],2,2,&x))return CW_CRT;
            if(x){error_number(s,22);return CW_OK;}
            if(y=='b')mode=CRT_BINARY;
        }
        for(fd=3;fd<CW_CRT_STREAMS;fd++)if(!s->crt_streams[fd].token)break;
        if(fd==CW_CRT_STREAMS || s->crt_stream_serial==UINT32_MAX){error_number(s,24);return CW_OK;}
        args[0]=a[0];args[1]=0x80000000U;args[2]=3;args[4]=3;
        token=cw_file_call(m,CW_CREATE_FILE,args);
        if(token==UINT64_MAX){error_number(s,file_errno(s->last_error));return CW_OK;}
        stream=&s->crt_streams[fd];
        stream->token=CRT_STREAM_BASE|((uint64_t)++s->crt_stream_serial<<8)|fd;
        stream->handle=token;
        stream->mode=mode;
        *result=stream->token;
        return CW_OK;
    case CW_CRT_SETMODE:case CW_CRT_ISATTY:case CW_CRT_OSFHANDLE:case CW_CRT_WRITE:
        fd=(uint32_t)a[0];
        stream=fd<3?standard_stream(s,fd):fd<CW_CRT_STREAMS?&s->crt_streams[fd]:NULL;
        if(!stream || !stream->token || (fd>=1 && fd<=2 && (s->console_closed&(1U<<(fd-1))))){error_number(s,9);*result=id==CW_CRT_ISATTY?0:UINT64_MAX;return CW_OK;}
        if(id==CW_CRT_SETMODE){
            mode=(uint32_t)a[1];
            if(mode!=CRT_BINARY && mode!=CRT_TEXT){error_number(s,22);*result=UINT32_MAX;return CW_OK;}
            if(stream->start!=stream->end)return CW_CRT;
            *result=stream->mode;stream->mode=mode;
            return CW_OK;
        }
        if(id==CW_CRT_ISATTY)return CW_OK; /* Captured streams and granted files are not terminals. */
        if(id==CW_CRT_OSFHANDLE){
            if(fd==0){*result=UINT64_MAX;error_number(s,9);}
            else *result=fd<3?0x10000U+fd:stream->handle;
            return CW_OK;
        }
        n=(uint32_t)a[2];
        if(n>CRT_LIMIT)return CW_CRT;
        buffer=n?cw_memory(m,a[1],n,CW_R):NULL;
        if(n && !buffer)return CW_CRT;
        error=stream_output(s,fd,buffer,n,stream->mode);
        if(error){error_number(s,error);*result=UINT32_MAX;}
        else *result=n;
        return CW_OK;
    default:break;
    }

    token=a[0];
    if(id==CW_CRT_FREAD || id==CW_CRT_FWRITE)token=a[3];
    if(id==CW_CRT_FGETS)token=a[2];
    if(id==CW_CRT_FPUTC || id==CW_CRT_FPUTS)token=a[1];
    if(id==CW_CRT_PUTCHAR || id==CW_CRT_PUTS)token=standard_stream(s,1)->token;
    if(id==CW_CRT_FFLUSH && !token)return CW_OK; /* All writes are synchronous. */
    stream=stream_for(s,token);
    if(!stream)return CW_CRT;
    fd=(uint32_t)(token&255);
    switch(id) {
    case CW_CRT_FILENO:
        if(fd>=1 && fd<=2 && (s->console_closed&(1U<<(fd-1)))){error_number(s,9);*result=UINT32_MAX;}
        else *result=fd;
        return CW_OK;
    case CW_CRT_FERROR:*result=stream->error;return CW_OK;
    case CW_CRT_FEOF:*result=stream->eof;return CW_OK;
    case CW_CRT_CLEARERR:stream->error=stream->eof=0;return CW_OK;
    case CW_CRT_FFLUSH:
        if(fd>=3)return CW_CRT; /* Input-buffer synchronization is outside this profile. */
        if(fd>=1 && (s->console_closed&(1U<<(fd-1)))){error_number(s,9);*result=UINT32_MAX;}
        return CW_OK;
    case CW_CRT_FCLOSE:
        if(!fd){error_number(s,9);*result=UINT32_MAX;return CW_OK;}
        args[0]=fd<3?0x10000U+fd:stream->handle;
        if(!cw_file_call(m,CW_CLOSE_HANDLE,args)){error_number(s,file_errno(s->last_error));*result=UINT32_MAX;}
        if(fd>=3)memset(stream,0,sizeof(*stream));
        return CW_OK;
    case CW_CRT_GETC:case CW_CRT_FREAD:case CW_CRT_FGETS:
        if(fd<3){error_number(s,9);stream->error=1;*result=id==CW_CRT_GETC?UINT32_MAX:0;return CW_OK;}
        if(id==CW_CRT_GETC){*result=(uint32_t)stream_byte(m,stream);return CW_OK;}
        if(id==CW_CRT_FREAD) {
            if(!a[1] || !a[2])return CW_OK;
            if(a[2]>CRT_LIMIT/a[1])return CW_CRT;
            n=(uint32_t)(a[1]*a[2]);
        }else {
            n=(uint32_t)a[1];
            if(!n || n>CRT_LIMIT)return CW_CRT;
        }
        buffer=cw_memory(m,a[0],n,CW_W);if(!buffer)return CW_CRT;
        for(i=0;i<n-(id==CW_CRT_FGETS);i++) {
            ch=stream_byte(m,stream);
            if(ch<0)break;
            buffer[i]=(unsigned char)ch;
            if(id==CW_CRT_FGETS && ch=='\n'){i++;break;}
        }
        if(id==CW_CRT_FREAD)*result=i/a[1];
        else if(i || n==1){buffer[i]=0;*result=a[0];}
        return CW_OK;
    case CW_CRT_FPUTC:case CW_CRT_PUTCHAR:
        byte=(unsigned char)a[0];buffer=&byte;n=1;break;
    case CW_CRT_FWRITE:
        if(!a[1] || !a[2])return CW_OK;
        if(a[2]>CRT_LIMIT/a[1])return CW_CRT;
        n=(uint32_t)(a[1]*a[2]);
        buffer=cw_memory(m,a[0],n,CW_R);if(!buffer)return CW_CRT;
        break;
    case CW_CRT_FPUTS:case CW_CRT_PUTS:
        for(count=0;count<CRT_LIMIT;count++){
            if(unit(m,a[0],1,count,&x))return CW_CRT;
            if(!x)break;
        }
        if(count==CRT_LIMIT)return CW_CRT;
        n=(uint32_t)count;
        buffer=n?cw_memory(m,a[0],n,CW_R):NULL;
        if(n && !buffer)return CW_CRT;
        break;
    default:return CW_API;
    }
    /* Reserve both parts of puts before changing the output. */
    if(id==CW_CRT_PUTS){
        uint32_t needed=n+(stream->mode==CRT_TEXT?2:1);
        if(stream->mode==CRT_TEXT)for(i=0;i<n;i++)if(buffer[i]=='\n')needed++;
        if(needed>CW_OUTPUT_LIMIT-s->output_bytes[0]-s->output_bytes[1])error=28;
        else {
            error=stream_output(s,fd,buffer,n,stream->mode);
            if(!error){byte='\n';error=stream_output(s,fd,&byte,1,stream->mode);}
        }
    }else error=stream_output(s,fd,buffer,n,stream->mode);
    if(error){
        stream->error=1;error_number(s,error);
        *result=id==CW_CRT_FWRITE?0:UINT32_MAX;
    }else if(id==CW_CRT_FWRITE)*result=a[2];
    else if(id==CW_CRT_FPUTC || id==CW_CRT_PUTCHAR)*result=byte;
    return CW_OK;
}

/* The virtual current directory is C:\\. This is lexical normalization
 * only. Opening the resulting path still requires a matching file grant. */
static int path_separator(uint32_t c) { return c=='/' || c=='\\'; }

static int full_path(CwMachine *m,const uint64_t *a,uint64_t *result) {
    char input[CW_PATH_LIMIT+1],output[CW_PATH_LIMIT+4];
    unsigned int n=0,i=0,j,start,out=3;
    uint32_t c;
    uint64_t at=a[0];
    unsigned char *dst;
    if(a[1])for(;n<sizeof(input);n++){
        if(unit(m,a[1],1,n,&c))return CW_CRT;
        input[n]=(char)c;
        if(!c)break;
        if(c<32 || c>=127){error_number(m->services,22);return CW_OK;}
    }
    if(n==sizeof(input)){error_number(m->services,34);return CW_OK;}
    output[0]='C';output[1]=':';output[2]='\\';
    if(n>=2 && input[1]==':'){
        c=(unsigned char)input[0];
        if(c>='a' && c<='z')c-=32;
        if(c<'A' || c>'Z' || (c!='C' && (n<3 || !path_separator(input[2]))))goto invalid;
        output[0]=(char)c;i=2;
    }
    if(i+1<n && path_separator(input[i]) && path_separator(input[i+1]))goto invalid;
    while(i<n){
        while(i<n && path_separator(input[i]))i++;
        start=i;
        while(i<n && !path_separator(input[i])){if(input[i]==':')goto invalid;i++;}
        if(start==i)break;
        if(i-start==1 && input[start]=='.')continue;
        if(i-start==2 && input[start]=='.' && input[start+1]=='.'){
            if(out==3)goto invalid;
            do {out--;}while(out>3 && output[out-1]!='\\');
            if(out>3)out--;
            continue;
        }
        if(out>3)output[out++]='\\';
        for(j=start;j<i;j++)output[out++]=input[j];
    }
    output[out++]=0;
    if(at){
        if(a[2]<out){error_number(m->services,34);return CW_OK;}
    }else {
        at=allocate(m,out);
        if(!at)return CW_OK;
    }
    dst=cw_memory(m,at,out,CW_W);
    if(!dst)return CW_CRT;
    memcpy(dst,output,out);
    *result=at;
    return CW_OK;
invalid:
    error_number(m->services,22);
    return CW_OK;
}

int cw_crt_call(CwMachine *m,unsigned int id,const uint64_t *a,uint64_t *result) {
    CwServices *s=m->services;unsigned char *dst,*src;uint64_t n=a[2],i;uint32_t x,y;unsigned int width;
    *result=0;
    if(id>=CW_CRT_IOB && id<=CW_CRT_WRITE)return stdio_call(m,id,a,result);
    switch(id) {
    case CW_CRT_FULLPATH:return full_path(m,a,result);
    case CW_CRT_LOCK_FILE:case CW_CRT_UNLOCK_FILE:
        /* FILE operations have one execution thread in this runtime. */
        return stream_for(s,a[0])?CW_OK:CW_CRT;
    case CW_CRT_STRERROR:{
        const char *message;
        switch((uint32_t)a[0]){
        case 2:message="No such file or directory";break;
        case 13:message="Permission denied";break;
        default:message="Unknown error";break;
        }
        memcpy(s->crt_error_text,message,strlen(message)+1);
        *result=s->command_base+CW_CRT_ERROR_TEXT_OFFSET;
        return CW_OK;
    }
    case CW_CRT_LOCALE_CODEPAGE:
        return CW_OK; /* C locale reports CP_ACP, not a configured UTF-8 locale. */
    case CW_CRT_GETENV:{
        unsigned int j,k;
        char name[64];
        for(j=0;j<sizeof(name);j++){
            if(unit(m,a[0],1,j,&x))return CW_CRT;
            name[j]=(char)(x>='a' && x<='z'?x-32:x);
            if(!x)break;
        }
        if(j==sizeof(name))return CW_OK;
        for(j=0;j<s->launch.environment_count;j++){
            const CwEnvironment *env=&s->launch.environment[j];
            for(k=0;k<sizeof(name);k++){
                x=env->name[k];
                if(x>='a' && x<='z')x-=32;
                if(x!=(unsigned char)name[k] || !x)break;
            }
            if(k==sizeof(name) || x)continue;
            if(name[k])continue;
            for(k=0;k<256;k++){
                x=env->value[k];
                if(x>=128)return CW_CRT; /* Narrow C-locale environment is ASCII. */
                s->crt_narrow_env[j][k]=(unsigned char)x;
                if(!x)break;
            }
            *result=s->command_base+32768+j*256;
            return CW_OK;
        }
        return CW_OK;
    }
    case CW_CRT_SETLOCALE:
        if((uint32_t)a[0]>5)return CW_OK;
        if(a[1]) {
            unsigned char *p=cw_memory(m,a[1],1,CW_R);if(!p)return CW_CRT;
            if(*p) {
                char name[7];unsigned int k;
                for(k=0;k<sizeof(name);k++){p=cw_memory(m,a[1]+k,1,CW_R);if(!p)return CW_CRT;name[k]=(char)*p;if(!*p)break;}
                if(k==sizeof(name) || (strcmp(name,"C") && strcmp(name,"POSIX")))return CW_OK;
            }
        }
        *result=s->command_base+6144;return CW_OK;
    case CW_CRT_RAND_S:
        dst=cw_memory(m,a[0],4,CW_W);if(!dst)return CW_CRT;
        if(!s->random_read)return CW_API;
        {unsigned char random[4];
            if(!s->random_read(s->random_context,random,4)){memset(dst,0,4);error_number(s,22);*result=22;return CW_OK;}
            memcpy(dst,random,4);return CW_OK;
        }
    case CW_CRT_ATEXIT:
        if(!a[0] || !cw_memory(m,a[0],1,CW_X))return CW_CRT;
        if(s->crt_exit_count==32){*result=UINT32_MAX;return CW_OK;}
        s->crt_exit_callbacks[s->crt_exit_count++]=a[0];return CW_OK;
    case CW_CRT_CEXIT:return terminate(m,0,1,1);
    case CW_CRT_EXIT:return terminate(m,(uint32_t)a[0],1,0);
    case CW_CRT_QUICK_EXIT:return terminate(m,(uint32_t)a[0],0,0);
    case CW_CRT_NEW_MODE:
        if(a[0]>1){error_number(s,22);*result=UINT32_MAX;return CW_OK;}
        *result=s->crt_new_mode;s->crt_new_mode=(uint32_t)a[0];return CW_OK;
    case CW_CRT_WENV:*result=s->command_base+4136;return CW_OK;
    case CW_CRT_WENV_INIT:return wide_environment(s);
    case CW_CRT_WARGV_CONFIG:return wide_arguments(s,(uint32_t)a[0]);
    case CW_CRT_ARGC:*result=s->command_base+4120;return CW_OK;
    case CW_CRT_WARGV:*result=s->command_base+4128;return CW_OK;
    case CW_CRT_INITTERM:case CW_CRT_INITTERM_E:return initializers(m,a,id==CW_CRT_INITTERM_E);
    case CW_CRT_FMODE:*result=s->command_base+4112;return CW_OK;
    case CW_CRT_COMMODE:*result=s->command_base+4116;return CW_OK;
    case CW_CRT_APP_TYPE:
        if(a[0]>2)return CW_CRT;
        s->crt_app_type=(uint32_t)a[0];return CW_OK;
    case CW_CRT_INVALID_HANDLER:
        if(a[0] && !cw_memory(m,a[0],1,CW_X))return CW_CRT;
        *result=s->invalid_parameter_handler;s->invalid_parameter_handler=a[0];return CW_OK;
    case CW_MEMCPY:case CW_MEMMOVE:case CW_MEMSET:case CW_MEMCMP:
        if(n>CRT_LIMIT)return CW_CRT;
        if(!n){*result=id==CW_MEMCMP?0:a[0];return CW_OK;}
        dst=cw_memory(m,a[0],(size_t)n,id==CW_MEMCMP?CW_R:CW_W);if(!dst)return CW_CRT;
        if(id==CW_MEMSET){memset(dst,(int)(a[1]&255),(size_t)n);*result=a[0];return CW_OK;}
        src=cw_memory(m,a[1],(size_t)n,CW_R);if(!src)return CW_CRT;
        if(id==CW_MEMCPY) {
            if(a[0]<a[1]?a[1]-a[0]<n:a[0]-a[1]<n)return CW_CRT;
            memcpy(dst,src,(size_t)n);
        }else if(id==CW_MEMMOVE)memmove(dst,src,(size_t)n);
        else {for(i=0;i<n;i++)if(dst[i]!=src[i]){*result=(uint32_t)((int)dst[i]-(int)src[i]);break;}return CW_OK;}
        *result=a[0];return CW_OK;
    case CW_STRLEN:case CW_WCSLEN:
        width=id==CW_WCSLEN?2:1;
        for(i=0;i<CRT_LIMIT/width;i++){if(unit(m,a[0],width,i,&x))return CW_CRT;if(!x){*result=i;return CW_OK;}}return CW_CRT;
    case CW_STRCMP:case CW_STRNCMP:
        n=id==CW_STRNCMP?a[2]:CRT_LIMIT;if(n>CRT_LIMIT)return CW_CRT;
        for(i=0;i<n;i++) {
            if(unit(m,a[0],1,i,&x) || unit(m,a[1],1,i,&y))return CW_CRT;
            if(x!=y){*result=(uint32_t)((int)x-(int)y);return CW_OK;}
            if(!x)return CW_OK;
        }
        return id==CW_STRNCMP?CW_OK:CW_CRT;
    case CW_CRT_ISALPHA:case CW_CRT_ISALNUM:case CW_CRT_ISSPACE:
        x=(uint32_t)a[0];
        if(id==CW_CRT_ISSPACE)*result=x==' ' || (x>=9 && x<=13);
        else {
            *result=(x>='A' && x<='Z') || (x>='a' && x<='z');
            if(id==CW_CRT_ISALNUM && x>='0' && x<='9')*result=1;
        }
        return CW_OK;
    case CW_CRT_STRCHR:case CW_CRT_STRRCHR:case CW_CRT_MEMCHR:
        n=id==CW_CRT_MEMCHR?a[2]:CRT_LIMIT;
        if(n>CRT_LIMIT)return CW_CRT;
        for(i=0;i<n;i++){
            if(unit(m,a[0],1,i,&x))return CW_CRT;
            if(x==(a[1]&255)){*result=a[0]+i;if(id!=CW_CRT_STRRCHR)return CW_OK;}
            if(!x && id!=CW_CRT_MEMCHR)return CW_OK;
        }
        return id==CW_CRT_MEMCHR?CW_OK:CW_CRT;
    case CW_CRT_STRNLEN:case CW_CRT_WCSNLEN:
        width=id==CW_CRT_WCSNLEN?2:1;
        if(a[1]>CRT_LIMIT/width)return CW_CRT;
        for(i=0;i<a[1];i++){if(unit(m,a[0],width,i,&x))return CW_CRT;if(!x)break;}
        *result=i;
        return CW_OK;
    case CW_CRT_STRDUP:case CW_CRT_STRCPY:case CW_CRT_STRNCPY:{
        uint64_t source=id==CW_CRT_STRDUP?a[0]:a[1];
        uint64_t target=a[0],length=0;
        n=id==CW_CRT_STRNCPY?a[2]:CRT_LIMIT;
        if(n>CRT_LIMIT)return CW_CRT;
        for(i=0;i<n;i++){
            if(unit(m,source,1,i,&x))return CW_CRT;
            length++;
            if(!x)break;
        }
        if(id!=CW_CRT_STRNCPY && i==n)return CW_CRT;
        if(id==CW_CRT_STRDUP){
            target=allocate(m,length);
            if(!target)return CW_OK;
        }
        if(id!=CW_CRT_STRNCPY)n=length;
        if(!n){*result=target;return CW_OK;}
        src=cw_memory(m,source,(size_t)length,CW_R);
        dst=cw_memory(m,target,(size_t)n,CW_W);
        if(!src || !dst)return CW_CRT;
        if(source<=target?target-source<length:source-target<n)return CW_CRT;
        memcpy(dst,src,(size_t)length);
        if(n>length)memset(dst+length,0,(size_t)(n-length));
        *result=target;
        return CW_OK;
    }
    case CW_MALLOC:*result=allocate(m,a[0]);return CW_OK;
    case CW_CALLOC:
        if(a[0] && a[1]>UINT64_MAX/a[0]){error_number(s,12);return CW_OK;}
        *result=allocate(m,a[0]*a[1]);return CW_OK; /* new committed pages are zero */
    case CW_FREE:return release(m,a[0]);
    case CW_REALLOC: {
        CwCrtBlock *old;uint64_t at,bytes,old_size;
        if(!a[0]){*result=allocate(m,a[1]);return CW_OK;}
        old=block(s,a[0]);if(!old)return CW_CRT;
        if(!a[1])return release(m,a[0]);
        if(a[1]<=old->capacity){old->size=a[1];*result=a[0];return CW_OK;}
        old_size=old->size;
        at=allocate(m,a[1]);if(!at)return CW_OK;
        bytes=old_size<a[1]?old_size:a[1];dst=cw_memory(m,at,(size_t)bytes,CW_W);src=cw_memory(m,a[0],(size_t)bytes,CW_R);
        if(bytes && (!dst || !src))return CW_CRT;
        if(bytes)memcpy(dst,src,(size_t)bytes);
        if(release(m,a[0]))return CW_CRT;
        *result=at;return CW_OK;
    }
    case CW_ERRNO:*result=s->command_base+4096;return CW_OK;
    default:return CW_API;
    }
}
