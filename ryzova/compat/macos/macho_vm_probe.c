/* SPDX-License-Identifier: AGPL-3.0-only */
#include "macho_vm.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc,char **argv) {
    FILE *f;
    unsigned char *image=NULL;
    RyzMac1Result result;
    long length;
    unsigned long steps=128U;
    int status;
    if(argc!=2 && argc!=3)return 64;
    if(argc==3){
        char *end;
        errno=0;
        steps=strtoul(argv[2],&end,10);
        if(errno || end==argv[2] || *end!='\0' ||
           steps==0 || steps>RYZ_MAC1_STEPS_MAX)return 64;
    }
    f=fopen(argv[1],"rb");
    if(f==NULL)return 65;
    if(fseek(f,0,SEEK_END)!=0){fclose(f);return 65;}
    length=ftell(f);
    if(length<32 || length>RYZ_MAC1_INPUT_MAX ||
       fseek(f,0,SEEK_SET)!=0){fclose(f);return 65;}
    image=(unsigned char *)malloc((size_t)length);
    if(image==NULL){fclose(f);return 65;}
    if(fread(image,1,(size_t)length,f)!=(size_t)length){
        fclose(f);free(image);return 65;
    }
    fclose(f);
    status=ryz_mac1_run(image,(size_t)length,(uint32_t)steps,&result);
    printf("MAC1_VM status=%d eax=%u steps=%u last_rip=0x%llx "
           "test_return=%u host_interpreter=1 native_guest=0 "
           "darwin_syscalls=0\n",
           status,result.eax,result.steps,
           (unsigned long long)result.last_rip,
           (unsigned int)result.returned_from_test_entry);
    free(image);
    return status==RYZ_MAC1_OK?0:2;
}
