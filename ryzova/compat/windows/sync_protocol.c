/* SPDX-License-Identifier: AGPL-3.0-only */
#include "sync_protocol.h"
static void hex(CwSyncNonce value,char *out) {
    static char digits[]="0123456789abcdef";unsigned int i;
    for(i=0;i<16;i++)out[i]=digits[(value>>(60-4*i))&15];
}
void cw_sync_request(CwSyncNonce value,char out[22]) {
    out[0]='S';out[1]='Y';out[2]='N';out[3]='C';out[4]=' ';hex(value,out+5);out[21]='\n';
}
int cw_sync_parse(const char *in,unsigned int n,CwSyncNonce *value) {
    unsigned int i,d;CwSyncNonce v=0;
    if(n!=22 || in[0]!='S' || in[1]!='Y' || in[2]!='N' || in[3]!='C' || in[4]!=' ' || in[21]!='\n')return 0;
    for(i=5;i<21;i++) {
        if(in[i]>='0' && in[i]<='9')d=in[i]-'0';
        else if(in[i]>='a' && in[i]<='f')d=in[i]-'a'+10;
        else return 0;
        v=(v<<4)|d;
    }
    *value=v;return 1;
}
void cw_sync_reply(CwSyncNonce value,char out[21]) {
    out[0]='A';out[1]='C';out[2]='K';out[3]=' ';hex(value,out+4);out[20]='\n';
}
int cw_sync_ack(const char *in,unsigned int n,CwSyncNonce value) {
    char expected[21];unsigned int i;if(n!=21)return 0;
    cw_sync_reply(value,expected);for(i=0;i<21;i++)if(in[i]!=expected[i])return 0;
    return 1;
}
