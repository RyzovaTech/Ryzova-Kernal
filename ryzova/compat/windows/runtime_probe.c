/* SPDX-License-Identifier: AGPL-3.0-only */
#include "runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
int main(int argc,char **argv) {
    FILE *file;long length;unsigned char *input,*arena;CwPlan plan;CwMachine machine;
    uint64_t base=0;unsigned long budget=CW_MAX_STEPS;int status;char *end;
    uint64_t saved[16];unsigned char vectors[16][16];unsigned int i,j;int preserved=1;
    static const unsigned int nonvolatile[]={3,5,6,7,12,13,14,15};
    if(argc<2 || argc>4)return 64;
    if(argc>2){errno=0;base=strtoull(argv[2],&end,0);if(errno || *end)return 64;}
    if(argc>3){errno=0;budget=strtoul(argv[3],&end,0);if(errno || *end || budget>CW_MAX_STEPS)return 64;}
    file=fopen(argv[1],"rb");if(!file)return 65;
    if(fseek(file,0,SEEK_END) || (length=ftell(file))<0 || length>CW_MAX_FILE || fseek(file,0,SEEK_SET)){fclose(file);return 65;}
    input=(unsigned char *)malloc(length?(size_t)length:1);if(!input){fclose(file);return 66;}
    if(fread(input,1,(size_t)length,file)!=(size_t)length){free(input);fclose(file);return 65;}fclose(file);
    status=cw_plan(input,(size_t)length,base,&plan);
    if(status){printf("{\"status\":%d,\"executed\":false,\"allocation_bytes\":0}\n",status);free(input);return 1;}
    arena=(unsigned char *)malloc((size_t)plan.image_bytes+CW_STACK);
    if(!arena){free(input);return 66;}
    status=cw_load(input,(size_t)length,base,arena,(size_t)plan.image_bytes+CW_STACK,&machine);
    for(i=0;i<16;i++){saved[i]=machine.r[i];for(j=0;j<16;j++)vectors[i][j]=machine.xmm[i][j];}
    for(i=0;i<sizeof(nonvolatile)/sizeof(nonvolatile[0]);i++) {
        unsigned int r=nonvolatile[i];machine.r[r]=saved[r]=UINT64_C(0x1357246800000000)+r;
    }
    for(i=6;i<16;i++)for(j=0;j<16;j++)machine.xmm[i][j]=vectors[i][j]=(unsigned char)(i*16+j);
    if(!status)status=cw_run(&machine,(uint32_t)budget);
    if(machine.exited) {
        for(i=0;i<sizeof(nonvolatile)/sizeof(nonvolatile[0]);i++)if(machine.r[nonvolatile[i]]!=saved[nonvolatile[i]])preserved=0;
        for(i=6;i<16;i++)for(j=0;j<16;j++)if(machine.xmm[i][j]!=vectors[i][j])preserved=0;
        if(!preserved)status=CW_ABI;
    }
    printf("{\"status\":%d,\"executed\":%s,\"exited\":%s,\"exit_code\":%" PRIu32 ",\"instructions\":%" PRIu32 ",\"allocation_bytes\":%" PRIu32 ",\"nonvolatile_preserved\":%s,\"base\":%" PRIu64 ",\"native_kernel_qualified\":false}\n",status,machine.instructions?"true":"false",machine.exited?"true":"false",machine.exit_code,machine.instructions,plan.image_bytes+CW_STACK,preserved?"true":"false",plan.base);
    free(arena);free(input);return status?1:0;
}
