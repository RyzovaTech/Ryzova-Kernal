/* SPDX-License-Identifier: AGPL-3.0-only */
#include "macho_static_link.h"
#include "macho_vm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *read_file(const char *path,size_t *size) {
    FILE *f=fopen(path,"rb");
    long n;
    unsigned char *data;
    if(f==NULL)return NULL;
    if(fseek(f,0,SEEK_END)!=0){fclose(f);return NULL;}
    n=ftell(f);
    if(n<32 || n>RYZ_MAC3C_OBJECT_MAX || fseek(f,0,SEEK_SET)!=0){
        fclose(f);return NULL;
    }
    data=(unsigned char *)malloc((size_t)n);
    if(data==NULL){fclose(f);return NULL;}
    if(fread(data,1,(size_t)n,f)!=(size_t)n){
        free(data);fclose(f);return NULL;
    }
    fclose(f);
    *size=(size_t)n;
    return data;
}
int main(int argc,char **argv) {
    unsigned char *first=NULL,*second=NULL,*image=NULL;
    size_t first_len=0,second_len=0;
    RyzMac3LinkReport link;
    RyzMac1Result vm;
    int status,execution=-1;
    if(argc!=3)return 64;
    first=read_file(argv[1],&first_len);
    second=read_file(argv[2],&second_len);
    image=(unsigned char *)calloc(RYZ_MAC3C_OUTPUT_BYTES,1);
    if(first==NULL || second==NULL || image==NULL){
        free(first);free(second);free(image);return 65;
    }
    memset(&vm,0,sizeof(vm));
    status=ryz_mac3_link2(first,first_len,second,second_len,image,
                          RYZ_MAC3C_OUTPUT_BYTES,&link);
    if(status==0)execution=ryz_mac1_run(image,RYZ_MAC3C_OUTPUT_BYTES,128,&vm);
    printf("MAC3C_LINK status=%d objects=%u branch_relocations=%u "
           "resolved_externals=%u output_code_bytes=%u "
           "entry_file_offset=%u vm_status=%d eax=%u returned=%u "
           "native_guest=0 dyld=0 libsystem=0 host_forwarding=0\n",
           status,link.object_count,link.applied_branch_relocations,
           link.resolved_external_symbols,link.output_code_bytes,
           link.entry_file_offset,execution,vm.eax,
           (unsigned int)vm.returned_from_test_entry);
    free(first);free(second);free(image);
    return (status==0 && execution==RYZ_MAC1_OK)?0:2;
}
