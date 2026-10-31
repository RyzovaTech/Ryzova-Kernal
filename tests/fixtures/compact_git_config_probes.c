/* SPDX-License-Identifier: AGPL-3.0-only */
/* Actual libc configure probes, executed as statically linked musl programs. */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <iconv.h>
static int formatted(char *buffer,size_t size,const char *format,...)
{
    int result;va_list args;va_start(args,format);
    result=vsnprintf(buffer,size,format,args);va_end(args);return result;
}
int main(int argc,char **argv)
{
    if(argc!=2)return 64;
    if(!strcmp(argv[1],"iconv")){
        char input[2]={'x',0},output[24]={0},*in=input,*out=output;
        size_t in_size=sizeof input,out_size=sizeof output;
        iconv_t converter=iconv_open("UTF-16","UTF-8");
        if(converter==(iconv_t)-1)return 2;
        if(iconv(converter,&in,&in_size,&out,&out_size)==(size_t)-1){iconv_close(converter);return 2;}
        iconv_close(converter);
        return (unsigned char)output[0]+(unsigned char)output[1]!=0xfe + 0xff;
    }
    if(!strcmp(argv[1],"directory")){
        FILE *file=fopen(".","r");if(file){fclose(file);return 1;}return 0;
    }
    if(!strcmp(argv[1],"snprintf")){
        char buffer[6];
        if(formatted(buffer,3,"%s","12345")!=5 || strcmp(buffer,"12"))return 1;
        return snprintf(buffer,3,"%s","12345")!=5 || strcmp(buffer,"12");
    }
    return 64;
}
