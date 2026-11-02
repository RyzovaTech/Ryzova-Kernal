/* SPDX-License-Identifier: AGPL-3.0-only */
#include "arm64_probe.h"
#include <stdio.h>
#include <stdlib.h>
int main(int argc,char **argv) {
    FILE *f;long length;unsigned char *image;CwArm64Result result;
    int status;
    if(argc!=2)return 64;
    f=fopen(argv[1],"rb");
    if(!f)return 65;
    if(fseek(f,0,SEEK_END) || (length=ftell(f))<0 ||
       length>4L*1024L*1024L || fseek(f,0,SEEK_SET)){fclose(f);return 65;}
    image=malloc((size_t)length+1U);
    if(!image){fclose(f);return 65;}
    if(fread(image,1,(size_t)length,f)!=(size_t)length) {
        free(image);fclose(f);return 65;
    }
    fclose(f);
    status=cw_arm64_pe_execute(image,(size_t)length,&result);
    printf("CW_ARM64_RESULT status=%u exit=%u steps=%u pc=%x insn=%08x\n",
           result.status,result.exit_code,result.executed_steps,
           result.last_rva,result.last_opcode);
    free(image);
    return status==CW_A64_OK?0:status+1;
}
