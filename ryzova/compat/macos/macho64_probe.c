/* SPDX-License-Identifier: AGPL-3.0-only */
#include "macho64.h"
#include <stdio.h>
#include <stdlib.h>
#define LIMIT (4U*1024U*1024U)
int main(int argc,char **argv) {
    FILE *f;
    unsigned char *bytes;
    long n;
    RyzMachoPlan plan;
    int result;
    if (argc!=2) return 64;
    f=fopen(argv[1],"rb");
    if (f==NULL || fseek(f,0,SEEK_END)!=0) return 65;
    n=ftell(f);
    if (n<0 || n>LIMIT || fseek(f,0,SEEK_SET)!=0) {fclose(f);return 65;}
    bytes=(unsigned char*)malloc(n>0?(size_t)n:1);
    if (bytes==NULL || fread(bytes,1,(size_t)n,f)!=(size_t)n) {
        fclose(f);free(bytes);return 65;
    }
    fclose(f);
    result=ryz_macho64_plan(bytes,(size_t)n,&plan);
    printf("MACHO64 status=%d segments=%u entry=%llu (not executed)\n",
           result,result==0?plan.segment_count:0,
           (unsigned long long)(result==0?plan.entry:0));
    free(bytes);
    return result==0?0:2;
}
