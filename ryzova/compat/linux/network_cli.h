/* SPDX-License-Identifier: AGPL-3.0-only */
/* Guest destination parser only. Native backends separately parse the grant. */
static int network_guest(const char *text,RyzNetworkGrant *grant,const char **target)
{
    unsigned int i,n;const char *p=text;
    for(i=0;i<4;i++){
        if(*p<'0' || *p>'9')return 0;
        n=0;do{n=n*10+(unsigned int)(*p++-'0');if(n>255)return 0;}while(*p>='0' && *p<='9');
        grant->address[i]=(unsigned char)n;
        if(*p++!=(i==3?':':'.'))return 0;
    }
    n=0;if(*p<'0' || *p>'9')return 0;
    do{n=n*10+(unsigned int)(*p++-'0');if(n>65535)return 0;}while(*p>='0' && *p<='9');
    if(!n || *p++!='=' || !*p)return 0;
    grant->port=n;*target=p;return 1;
}
