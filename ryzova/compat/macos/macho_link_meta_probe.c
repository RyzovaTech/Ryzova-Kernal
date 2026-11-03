/* SPDX-License-Identifier: AGPL-3.0-only */
#include "macho_link_meta.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc,char **argv) {
    FILE *file;
    long n;
    unsigned char *data;
    RyzMac3Manifest manifest;
    int status;
    uint32_t i;
    if(argc!=2)return 64;
    file=fopen(argv[1],"rb");
    if(file==NULL)return 65;
    if(fseek(file,0,SEEK_END)!=0){fclose(file);return 65;}
    n=ftell(file);
    if(n<32 || n>RYZ_MAC3_MAX_INPUT || fseek(file,0,SEEK_SET)!=0){
        fclose(file);return 65;
    }
    data=(unsigned char *)malloc((size_t)n);
    if(data==NULL){fclose(file);return 65;}
    if(fread(data,1,(size_t)n,file)!=(size_t)n){
        free(data);fclose(file);return 65;
    }
    fclose(file);
    status=ryz_mac3_scan(data,(size_t)n,&manifest);
    printf("MAC3_METADATA status=%d filetype=%u segments=%u dependencies=%u "
           "rpaths=%u dyld=%u native_guest=0 dylib_loading=0 "
           "symbol_resolution=0\n",status,manifest.filetype,
           manifest.segment_count,manifest.dependency_count,
           manifest.rpath_count,manifest.dyld_seen);
    if(status==0) {
        for(i=0;i<manifest.dependency_count;i++)
            printf("MAC3_DEP %u %s\n",i,manifest.dependencies[i]);
        for(i=0;i<manifest.rpath_count;i++)
            printf("MAC3_RPATH %u %s\n",i,manifest.rpaths[i]);
        if(manifest.dyld_seen)printf("MAC3_DYLD %s\n",manifest.dyld);
        if(manifest.install_name[0])
            printf("MAC3_INSTALL_NAME %s\n",manifest.install_name);
    }
    free(data);
    return status==0?0:2;
}
