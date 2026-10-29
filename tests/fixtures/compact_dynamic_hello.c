/* SPDX-License-Identifier: AGPL-3.0-only */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
__thread int local=7;
int main(int argc,char **argv){char *p=malloc(32);if(!p)return 9;strcpy(p,"FLEX_DYNAMIC_OK");FILE *f=fopen(argc>2?argv[2]:"/tmp/dynamic-file","w+");char b[8]={0};if(!f || fputs("shared",f)<0 || fflush(f) || fseek(f,0,SEEK_SET) || fread(b,1,6,f)!=6 || strcmp(b,"shared") || fclose(f))return 10;printf("%s %d %s\n",p,local,argc>1?argv[1]:"none");free(p);return 0;}
