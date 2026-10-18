/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../ryzova/compat/linux/namespace.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static uint32_t seed=0x31415926U;
static uint32_t rand32(void) {seed^=seed<<13;seed^=seed>>17;seed^=seed<<5;return seed;}
int main(void) {
    static const char pool[]="/.abcXYZ0123_-\\\n:";
    RyzLinuxNamespace ns={123,1000,1000,42};
    char path[RYZ_NS_PATH_MAX+1];
    enum RyzLinuxNode kind;
    unsigned int k,j;
    size_t length;
    int result;
    for(k=0;k<10000;++k) {
        length=1+(rand32()%RYZ_NS_PATH_MAX);
        for(j=0;j<length-1;++j)
            path[j]=pool[rand32()%(sizeof(pool)-1)];
        path[length-1]='\0';
        result=ryz_linux_ns_resolve(&ns,path,length,&kind);
        if(result!=0 && result!=-2 && result!=-13 && result!=-22 &&
           result!=-36) {
            fprintf(stderr,"unexpected namespace error %d\n",result);
            return 1;
        }
        if(result!=0 && kind!=RYZ_NS_NONE) {
            fprintf(stderr,"resolver returned a node on failure\n");
            return 1;
        }
        if(result==0 && kind!=RYZ_NS_DEV_NULL &&
           kind!=RYZ_NS_DEV_ZERO && kind!=RYZ_NS_PROC_SELF &&
           kind!=RYZ_NS_TMP)
            return 1;
    }
    printf("PHASE5_6_NAMESPACE_FUZZ_PASS 10000\n");
    return 0;
}
