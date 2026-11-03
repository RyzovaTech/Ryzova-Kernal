/* SPDX-License-Identifier: AGPL-3.0-only
 * Ryzova W8 Windows-host only bridge for UNMODIFIED MIT-licensed sbase wc.c.
 * Intentionally ASCII-only: this is NOT the full sbase UTF-8 implementation.
 * Never compile this bridge into the Ryzova kernel or use it to claim guest API compatibility.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "upstream/utf.h"
#include "util.h"

char *argv0;

static void warning(const char *fmt,va_list args) {
    if(argv0 && *argv0)fprintf(stderr,"%s: ",argv0);
    vfprintf(stderr,fmt,args);
    fputc('\n',stderr);
}
void eprintf(const char *fmt,...) {
    va_list args;va_start(args,fmt);warning(fmt,args);va_end(args);
    exit(2);
}
void weprintf(const char *fmt,...) {
    va_list args;va_start(args,fmt);warning(fmt,args);va_end(args);
}
int fshut(FILE *fp,const char *name) {
    (void)name;
    if(fp==stdin)return ferror(stdin)?1:0;
    if(fp==stdout)return fflush(stdout)==0?0:1;
    return fclose(fp)==0?0:1;
}
int efgetrune(Rune *value,FILE *fp,const char *name) {
    int c;
    if(!value || !fp)eprintf("invalid unicode stream");
    c=fgetc(fp);
    if(c==EOF){
        if(ferror(fp))eprintf("read failed: %s",name?name:"<stdin>");
        return 0;
    }
    /* This tiny bridge can only qualify exact ASCII input; fail rather
     * than corrupting upstream wc's Unicode semantics or word counts. */
    if(c>127)eprintf("non-ASCII data unsupported by W8 host reference bridge");
    *value=(Rune)c;
    return 1;
}
int isspacerune(Rune value) {
    return value==' ' || value=='\t' || value=='\n' ||
           value=='\r' || value=='\v' || value=='\f';
}
