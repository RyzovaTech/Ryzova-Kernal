/* SPDX-License-Identifier: AGPL-3.0-only */
/* Shared initializer for syscall and snapshot translation units. No host paths. */
static void vfs_init(RyzLinuxWorld *w)
{
    static const char *roots[]={"tmp","etc","home","usr","var"};
    unsigned int i;
    if(w->nodes[0].used)return;
    w->nodes[0].used=w->nodes[0].linked=w->nodes[0].directory=1;
    w->nodes[0].permissions=0700;w->nodes[0].inode=2000;w->next_inode=2001;
    memcpy(w->nodes[0].name,w->root_tree?"root":"tmp",w->root_tree?5:4);
    if(!w->root_tree)return;
    for(i=0;i<5;i++){
        RyzVnode *node=&w->nodes[i+1];
        node->used=node->linked=node->directory=1;node->permissions=0700;
        node->inode=w->next_inode++;memcpy(node->name,roots[i],strlen(roots[i])+1);
    }
}
static int vfs_reserved(const char *path)
{
    static const char *names[]={"/dev","/proc","/input","/output","/compat"};
    unsigned int i;size_t n;
    for(i=0;i<5;i++){n=strlen(names[i]);if(!strncmp(path,names[i],n) && (!path[n] || path[n]=='/'))return 1;}
    return 0;
}
