/* SPDX-License-Identifier: AGPL-3.0-only */
#include "api.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
static int utf16(const char *text,uint16_t *out,size_t cap) {
    size_t n=0;const unsigned char *p=(const unsigned char *)text;
    while(*p) {
        uint32_t c;unsigned int extra,i;
        if(*p<128){c=*p++;extra=0;}
        else if(*p>=0xc2 && *p<=0xdf){c=*p++&31;extra=1;}
        else if(*p>=0xe0 && *p<=0xef){c=*p++&15;extra=2;}
        else if(*p>=0xf0 && *p<=0xf4){c=*p++&7;extra=3;}
        else return 0;
        for(i=0;i<extra;i++){if((*p&0xc0)!=0x80)return 0;c=(c<<6)|(*p++&63);}
        if((extra==1 && c<128) || (extra==2 && c<2048) || (extra==3 && c<65536) || c>0x10ffff || (c>=0xd800 && c<=0xdfff))return 0;
        if(c>=65536){if(n+2>=cap)return 0;c-=65536;out[n++]=(uint16_t)(0xd800+(c>>10));out[n++]=(uint16_t)(0xdc00+(c&1023));}
        else {if(n+1>=cap)return 0;out[n++]=(uint16_t)c;}
    }
    out[n]=0;return 1;
}
static int number(const char *text,uint32_t max,uint32_t *out) {
    char *end;unsigned long n;errno=0;n=strtoul(text,&end,0);if(errno || !*text || *end || n>max)return 0;*out=(uint32_t)n;return 1;
}
static void hex(const unsigned char *bytes,uint32_t n) { uint32_t i;for(i=0;i<n;i++)printf("%02x",bytes[i]); }
int main(int argc,char **argv) {
    FILE *file;long length;unsigned char *input,*arena=NULL,*heap=NULL;
    CwMachine m;CwPlan plan;CwLaunch launch;CwServices *s;uint32_t budget=CW_MAX_STEPS;int status;
    unsigned int i;
    if(argc<2 || argc>9 || argc==4)return 64;
    memset(&launch,0,sizeof(launch));
    if(!utf16(argc>2?argv[2]:"flex.exe",launch.command_line,CW_COMMAND_UNITS))return 64;
    if(argc>4){if(!utf16(argv[3],launch.environment[0].name,64) || !utf16(argv[4],launch.environment[0].value,256))return 64;launch.environment_count=1;}
    if(argc>5 && !number(argv[5],3,&launch.console_mask))return 64;
    if(argc>6 && !number(argv[6],CW_ALL_APIS,&launch.api_mask))return 64;
    if(argc>7 && !number(argv[7],CW_MAX_STEPS,&budget))return 64;
    if(argc>8)return 64;
    file=fopen(argv[1],"rb");if(!file)return 65;
    if(fseek(file,0,SEEK_END) || (length=ftell(file))<0 || length>CW_MAX_FILE || fseek(file,0,SEEK_SET)){fclose(file);return 65;}
    input=(unsigned char *)malloc(length?(size_t)length:1);if(!input){fclose(file);return 66;}
    if(fread(input,1,(size_t)length,file)!=(size_t)length){free(input);fclose(file);return 65;}fclose(file);
    status=cw_plan(input,(size_t)length,0,&plan);
    if(status){printf("{\"status\":%d,\"executed\":false,\"allocation_bytes\":0}\n",status);free(input);return 1;}
    if(plan.api_mask&~launch.api_mask){printf("{\"status\":10,\"executed\":false,\"allocation_bytes\":0}\n");free(input);return 1;}
    if((size_t)plan.image_bytes+CW_STACK+4096+CW_HEAP_LIMIT>CW_MAX_MEMORY){free(input);return 66;}
    arena=(unsigned char *)malloc((size_t)plan.image_bytes+CW_STACK);
    heap=(unsigned char *)malloc(CW_HEAP_LIMIT);s=(CwServices *)malloc(sizeof(*s));
    if(!arena || !heap || !s){free(arena);free(heap);free(s);free(input);return 66;}
    status=cw_load(input,(size_t)length,0,arena,(size_t)plan.image_bytes+CW_STACK,&m);
    if(!status)status=cw_attach_services(&m,s,&launch,heap,CW_HEAP_LIMIT);
    if(!status)status=cw_run(&m,budget);
    printf("{\"status\":%d,\"executed\":%s,\"exited\":%s,\"exit_code\":%" PRIu32 ",\"exit_kind\":%" PRIu32 ",\"instructions\":%" PRIu32 ",\"imports\":%" PRIu32 ",\"stdout_hex\":\"",status,m.instructions?"true":"false",m.exited?"true":"false",m.exit_code,m.exit_kind,m.instructions,plan.import_count);
    if(m.services)hex(s->output[0],s->output_bytes[0]);
    printf("\",\"stderr_hex\":\"");
    if(m.services)hex(s->output[1],s->output_bytes[1]);
    printf("\",\"api_calls\":{");
    for(i=0;i<CW_API_COUNT;i++)printf("%s\"%s\":%" PRIu32,i?",":"",cw_api_name(i),m.services?s->calls[i]:0);
    printf("},\"native_kernel_qualified\":false}\n");
    free(s);free(heap);free(arena);free(input);return status?1:0;
}
