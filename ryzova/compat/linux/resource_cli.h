/* SPDX-License-Identifier: AGPL-3.0-only */
/* Explicit launcher capabilities; never populated by guest input. */
typedef struct ResourceCLI {
    RyzFsResources resources;RyzFsMount mounts[RYZ_FS_MOUNTS];ResourceHost hosts[RYZ_FS_MOUNTS];
    RyzFsView views[16];char *mounts_text[RYZ_FS_MOUNTS],*views_text[16],*control;
    unsigned int opened;
} ResourceCLI;
static int resource_cli_prepare(ResourceCLI *c)
{
    size_t i;char *text,*eq,*colon,*end;unsigned long r,w;
    c->resources.mounts=c->mounts;c->resources.views=c->views;
    for(i=0;i<c->resources.view_count;i++){
        text=c->views_text[i];colon=strchr(text,':');if(!colon)return 0;*colon++=0;
        r=strtoul(colon,&end,10);if(*end!=':')return 0;w=strtoul(end+1,&end,10);if(*end || r>15 || w>15 || (w&~r))return 0;
        c->views[i].executable=text;c->views[i].read_mask=(unsigned int)r;c->views[i].write_mask=(unsigned int)w;
    }
    for(i=0;i<c->resources.count;i++){
        text=c->mounts_text[i];colon=strchr(text,':');if(!colon)return 0;*colon++=0;
        if(strcmp(text,"r") && strcmp(text,"rw"))return 0;
        eq=strchr(colon,'=');if(!eq || !eq[1])return 0;*eq++=0;
        if(!resource_host_open(&c->hosts[i],eq,c->control))return 0;
        c->opened++;
        c->mounts[i].path=colon;c->mounts[i].rights=!strcmp(text,"rw")?3:1;
        c->mounts[i].allowed=resource_host_allowed;c->mounts[i].call=resource_host_call;c->mounts[i].context=&c->hosts[i];
    }
    return 1;
}
static void resource_cli_close(ResourceCLI *c)
{unsigned int i;for(i=0;i<c->opened;i++)resource_host_close(&c->hosts[i]);c->opened=0;}
