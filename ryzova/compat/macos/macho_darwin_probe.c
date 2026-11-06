/* SPDX-License-Identifier: AGPL-3.0-only */
#include "macho_darwin.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc,char **argv) {
    FILE *file;
    unsigned char *data;
    RyzMac2Result report;
    long length;
    unsigned long budget=128U;
    int code;
    uint32_t i;
    if(argc!=2 && argc!=3)return 64;
    if(argc==3) {
        char *end;
        errno=0;
        budget=strtoul(argv[2],&end,10);
        if(errno || end==argv[2] || *end!='\0' ||
           budget==0 || budget>RYZ_MAC1_STEPS_MAX)return 64;
    }
    file=fopen(argv[1],"rb");
    if(file==NULL)return 65;
    if(fseek(file,0,SEEK_END)!=0){fclose(file);return 65;}
    length=ftell(file);
    if(length<32 || length>RYZ_MAC1_INPUT_MAX ||
       fseek(file,0,SEEK_SET)!=0){fclose(file);return 65;}
    data=(unsigned char *)malloc((size_t)length);
    if(data==NULL){fclose(file);return 65;}
    if(fread(data,1,(size_t)length,file)!=(size_t)length){
        free(data);fclose(file);return 65;
    }
    fclose(file);
    code=ryz_mac2_run(data,(size_t)length,(uint32_t)budget,&report);
    /* Host prints only a hex-encoded, bounded diagnostic; guest bytes
     * are never written to the actual host file descriptor. */
    printf("MAC2_VM status=%d eax=%u steps=%u exited=%u exit_code=%u "
           "capture_bytes=%u native_guest=0 host_syscall_forwarding=0\n",
           code,report.cpu.eax,report.cpu.steps,
           (unsigned int)report.simulated_exited,
           (unsigned int)report.simulated_exit_code,
           report.captured_stdout_bytes);
    printf("MAC2_CAPTURE_HEX ");
    for(i=0;i<report.captured_stdout_bytes;i++)
        printf("%02x",(unsigned int)report.captured_stdout[i]);
    printf("\n");
    free(data);
    return code==RYZ_MAC1_OK?0:2;
}
