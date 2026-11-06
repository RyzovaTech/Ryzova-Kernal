/* SPDX-License-Identifier: AGPL-3.0-only */
#include "macho_symbol_meta.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc,char **argv) {
    FILE *f;
    unsigned char *buf;
    long size;
    RyzMac3Symbols symbols;
    int status;
    uint32_t i;
    if(argc!=2)return 64;
    f=fopen(argv[1],"rb");
    if(f==NULL)return 65;
    if(fseek(f,0,SEEK_END)!=0){fclose(f);return 65;}
    size=ftell(f);
    if(size<32 || size>4*1024*1024 || fseek(f,0,SEEK_SET)!=0){
        fclose(f);return 65;
    }
    buf=(unsigned char *)malloc((size_t)size);
    if(buf==NULL){fclose(f);return 65;}
    if(fread(buf,1,(size_t)size,f)!=(size_t)size){
        fclose(f);free(buf);return 65;
    }
    fclose(f);
    status=ryz_mac3_symbols(buf,(size_t)size,&symbols);
    printf("MAC3_SYMBOL status=%d count=%u defined=%u undefined=%u "
           "relocations=%u symbol_resolution=0 native_guest=0\n",
           status,symbols.count,symbols.defined_count,
           symbols.undefined_count,symbols.relocation_count);
    if(status==0) {
        for(i=0;i<symbols.count;i++)
            printf("MAC3_SYMBOL_NAME %s %u\n",
                   symbols.symbols[i].name,(unsigned int)symbols.symbols[i].kind);
    }
    free(buf);
    return status==0?0:2;
}
