/* SPDX-License-Identifier: AGPL-3.0-only */
#include <stdio.h>
#include <dlfcn.h>
int main(int argc,char **argv){void *p=dlopen(argc>1?argv[1]:"/lib/libflex.so",RTLD_NOW);if(!p){puts(dlerror());return 7;}int (*f)(int)=dlsym(p,"flex_add");if(!f)return 8;printf("FLEX_DLOPEN_OK %d\n",f(5));return dlclose(p);}
