/* SPDX-License-Identifier: GPL-3.0-only */
#include "api.h"
#include "files_native.h"
static int random_bytes(void *context,unsigned char *out,size_t n) {
    int fd=*(int *)context;size_t at=0;long got;
    while(at<n){got=read(fd,out+at,n-at);if(got<=0)return 0;at+=got;}
    return 1;
}
static unsigned char *readimage(char *path,size_t *size) {
    Dir *d;unsigned char *bytes;int fd;long n;size_t got=0;
    fd=open(path,OREAD);if(fd<0)sysfatal("executable capability: %r");
    d=dirfstat(fd);if(!d || d->length<=0 || d->length>CW_MAX_FILE){print("CW_NATIVE status=1 executed=0 admission=1\n");exits("image size");}
    *size=d->length;free(d);bytes=malloc(*size);if(!bytes)sysfatal("input buffer");
    while(got<*size){n=read(fd,bytes+got,*size-got);if(n<=0)sysfatal("executable read: %r");got+=n;}
    close(fd);return bytes;
}
static void text16(uint16_t *out,const char *in,size_t capacity) {
    size_t i;for(i=0;in[i];i++){if(i+1>=capacity || (unsigned char)in[i]>=128)sysfatal("ASCII launch argument exceeds contract");out[i]=(unsigned char)in[i];}out[i]=0;
}
void main(int argc,char **argv) {
    CwMachine *m;CwServices *s;CwLaunch *launch;CwFileNamespace *ns=nil;CwFileNative *provider=nil;
    CwDirectoryGrant grant;CwPlan plan;unsigned char *file,*arena,*heap;size_t size,owned;
    uint32_t budget=CW_MAX_STEPS,rights=31,apis=CW_LEGACY_APIS,api_hi=0,api_words[CW_API_WORDS-1]={0},profile=0,heap_limit,word,committed=0;int status,syncfd=-1,randomfd=-1,i=1;char *root=nil,*syncpath=nil,*end,*command="flex.exe --w3-test two words",capability[512];
    while(i<argc && argv[i][0]=='-') {
        if(!strcmp(argv[i],"-b") && i+1<argc){budget=strtoul(argv[++i],&end,0);if(*end || !budget || budget>CW_TRACE_MAX_STEPS)sysfatal("instruction limit");}
        else if(!strcmp(argv[i],"-c") && i+1<argc)command=argv[++i];
        else if(!strcmp(argv[i],"-P") && i+1<argc){if(strcmp(argv[++i],"trace"))sysfatal("execution profile");profile=CW_PROFILE_TRACE;}
        else if(!strcmp(argv[i],"-g") && i+1<argc){
            word=strtoul(argv[++i],&end,0);if(*end!=':' || !end[1] || word<2 || word>=CW_API_WORDS)sysfatal("API grant word");
            api_words[word-1]=strtoul(end+1,&end,0);if(*end || (api_words[word-1]&~cw_api_word_mask(word)))sysfatal("API grant mask");
        }
        else if(!strcmp(argv[i],"-r") && i+1<argc)root=argv[++i];
        else if(!strcmp(argv[i],"-s") && i+1<argc)syncpath=argv[++i];
        else if(!strcmp(argv[i],"-R") && i+1<argc){rights=strtoul(argv[++i],&end,0);if(*end || !rights || rights>31)sysfatal("rights");}
        else if(!strcmp(argv[i],"-a") && i+1<argc){apis=strtoul(argv[++i],&end,0);if(*end || apis>CW_LOW_API_MASK)sysfatal("API mask");}
        else if(!strcmp(argv[i],"-A") && i+1<argc){api_hi=strtoul(argv[++i],&end,0);if(*end || (api_hi&~cw_api_word_mask(1)))sysfatal("high API mask");}
        else sysfatal("usage: compact-windows [-b steps] [-r root [-s cw-hjfs-control] [-R rights]] [-a API-mask] [-A high-API-mask] [-g word:mask] [-P trace] [-c ASCII-command-line] PE");
        i++;
    }
    heap_limit=CW_HEAP_LIMIT_FOR(profile);
    if(budget>CW_STEP_LIMIT(profile))sysfatal("instruction limit");
    if(i!=argc-1 || (syncpath && !root))sysfatal("executable or grant arguments");
    if(rfork(RFNAMEG|RFENVG)<0)sysfatal("private namespace: %r");
    file=readimage(argv[i],&size);api_words[0]=api_hi;status=cw_plan_profile(file,size,0,&plan,profile);
    if(!status){
        if(plan.api_mask&~apis)status=CW_API;
        for(i=0;i<CW_API_WORDS-1;i++)if(plan.api_mask_high[i]&~api_words[i])status=CW_API;
    }
    if(status) {
        print("CW_NATIVE status=%d executed=0 admission=1\n",status);free(file);exits("admission");
    }
    if((size_t)plan.image_bytes+CW_STACK+4096+heap_limit>CW_MAX_MEMORY)sysfatal("guest memory admission");
    m=mallocz(sizeof(*m),1);s=mallocz(sizeof(*s),1);launch=mallocz(sizeof(*launch),1);
    arena=malloc((size_t)plan.image_bytes+CW_STACK);heap=malloc(heap_limit);
    if(!m || !s || !launch || !arena || !heap)sysfatal("bounded runtime allocation");
    launch->api_mask=apis;launch->profile_flags=profile;for(i=0;i<CW_API_WORDS-1;i++)launch->api_mask_high[i]=api_words[i];launch->console_mask=3;
    text16(launch->command_line,command,CW_COMMAND_UNITS);
    launch->environment_count=1;text16(launch->environment[0].name,"FLEX_W3_PROBE",64);text16(launch->environment[0].value,"ready",256);
    status=cw_load_profile(file,size,0,arena,(size_t)plan.image_bytes+CW_STACK,m,profile);
    if(!status)status=cw_attach_services(m,s,launch,heap,heap_limit);
    if(root && !status) {
        ns=mallocz(sizeof(*ns),1);if(!ns)sysfatal("namespace state");
        if(syncpath) {
            snprint(capability,sizeof capability,"%s/.ryzova-sync-v1",root);
            if(strcmp(capability,syncpath))sysfatal("sync capability must belong to grant root");
            syncfd=open(syncpath,ORDWR);if(syncfd<0)sysfatal("storage barrier capability: %r");
        }
        provider=cw_file_native_new(root,syncfd);if(syncfd>=0)close(syncfd);
        if(!provider)sysfatal("directory capability: %r");
        memset(&grant,0,sizeof grant);strcpy(grant.ref,"work");grant.drive='C';grant.rights=rights;
        status=cw_attach_files(m,ns,&grant,1,cw_file_native_ops(),provider);
    }
    owned=size+plan.image_bytes+CW_STACK+heap_limit+sizeof(*m)+sizeof(*s)+sizeof(*launch)+(ns?sizeof(*ns):0);
    if(!status && profile){randomfd=open("/dev/random",OREAD);if(randomfd>=0){s->random_read=random_bytes;s->random_context=&randomfd;}}
    if(!status)status=cw_run(m,budget);
    if(randomfd>=0)close(randomfd);
    for(i=0;i<heap_limit/4096;i++)if(s->protection[i]&128)committed+=4096;
    print("CW_NATIVE status=%d executed=%d exited=%d code=%ud steps=%ud stop=%s ip=%llud owned=%llud guest=%ud open=%ud peak_handles=%ud heap=%ud error=%ud flushes=%ud rights=%ud read_bytes=%llud write_bytes=%llud profile=%ud stop_import=%ud\n",status,m->instructions!=0,m->exited,m->exit_code,m->instructions,cw_status_name(status),m->last_guest_ip,(uvlong)owned,plan.image_bytes+CW_STACK+4096+heap_limit,provider?cw_file_native_open_count(provider):0,provider?cw_file_native_peak_count(provider):0,committed,s->last_error,provider?cw_file_native_sync_count(provider):0,
          s->files?ns->mounts[0].rights:0,
          (uvlong)(provider?cw_file_native_read_bytes(provider):0),
          (uvlong)(provider?cw_file_native_write_bytes(provider):0),
          m->plan.profile_flags,m->stop_import);
    print("CW_PROFILE flags=%ud unresolved=%ud stop_import=%ud\n",profile,plan.unresolved_imports,m->stop_import);
    print("CW_OUT ");for(i=0;i<(int)s->output_bytes[0];i++)print("%02ux",s->output[0][i]);print("\nCW_ERR ");for(i=0;i<(int)s->output_bytes[1];i++)print("%02ux",s->output[1][i]);print("\n");
    for(i=0;i<CW_API_COUNT;i++)if(s->calls[i])print("CW_CALL %s %ud\n",cw_api_name(i),s->calls[i]);
    cw_files_close_all(m);cw_file_native_destroy(provider);free(ns);free(heap);free(arena);free(launch);free(s);free(m);free(file);
    exits(status?"guest stopped":nil);
}
