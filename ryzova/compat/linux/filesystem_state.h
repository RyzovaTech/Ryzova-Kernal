/* SPDX-License-Identifier: AGPL-3.0-only */
/* Validated portable snapshots of the bounded guest /tmp tree. */
static uint64_t fs_checksum(const unsigned char *bytes,size_t size)
{
    uint64_t hash=UINT64_C(0xcbf29ce484222325);size_t i;
    for(i=0;i<size;i++){hash^=bytes[i];hash*=UINT64_C(0x100000001b3);}return hash;
}
static int fs_import(RyzLinuxWorld *w,const unsigned char *bytes,size_t size)
{
    unsigned int count,i,j,index,parent,length,n;uint64_t inode;size_t at=40;
    RyzVnode *node;int version;
    version=size>=8 && !memcmp(bytes,"FLEXFS2\n",8)?2:1;
    if(size<48 || size>RYZ_FS_SNAPSHOT_MAX || (version==1 && memcmp(bytes,"FLEXFS1\n",8)) || little(bytes+8,8)!=size || little(bytes+20,4) || little(bytes+size-8,8)!=fs_checksum(bytes,size-8))return 0;
    count=(unsigned int)little(bytes+16,4);if(!count || count>RYZ_VFS_NODES)return 0;
    w->next_inode=little(bytes+24,8);w->clock=little(bytes+32,8);
    if(w->next_inode<2001 || w->next_inode>UINT64_MAX-16777216U)return 0;
    for(i=0;i<count;i++){
        if(at>size-8 || size-8-at<80)return 0;
        index=(unsigned int)little(bytes+at,4);parent=(unsigned int)little(bytes+at+4,4);
        length=(unsigned int)little(bytes+at+28,4);n=(unsigned int)little(bytes+at+24,4);inode=little(bytes+at+16,8);
        if(index>=RYZ_VFS_NODES || parent>=RYZ_VFS_NODES || w->nodes[index].used || !length || length>=RYZ_NS_PATH_MAX || n>RYZ_LINUX_FILE_MAX || length>size-8-at-80 || n>size-8-at-80-length || little(bytes+at+8,4)>0777 || little(bytes+at+12,4)>(version==2?2U:1U) || inode<2000 || inode>=w->next_inode)return 0;
        node=&w->nodes[index];node->used=node->linked=1;node->parent=parent;node->permissions=(unsigned int)little(bytes+at+8,4);node->directory=little(bytes+at+12,4)==1;node->symlink=little(bytes+at+12,4)==2;node->inode=inode;node->size=n;
        if(node->directory && n)return 0;
        node->atime=little(bytes+at+32,8);node->atime_ns=little(bytes+at+40,8);node->mtime=little(bytes+at+48,8);node->mtime_ns=little(bytes+at+56,8);node->ctime=little(bytes+at+64,8);node->ctime_ns=little(bytes+at+72,8);
        if(node->atime_ns>=1000000000 || node->mtime_ns>=1000000000 || node->ctime_ns>=1000000000)return 0;
        at+=80;
        for(j=0;j<length;j++)if(!bytes[at+j] || bytes[at+j]=='/')return 0;
        memcpy(node->name,bytes+at,length);node->name[length]=0;at+=length;
        if(!strcmp(node->name,".") || !strcmp(node->name,".."))return 0;
        if(n)memcpy(node->bytes,bytes+at,n);
        if(node->symlink){
            if(!n || n>=RYZ_NS_PATH_MAX)return 0;
            for(j=0;j<n;j++)if(!node->bytes[j])return 0;
            node->bytes[n]=0;
        }
        at+=n;
    }
    if(at!=size-8 || !w->nodes[0].used || !w->nodes[0].directory || w->nodes[0].parent || strcmp(w->nodes[0].name,"tmp") || w->nodes[0].inode!=2000)return 0;
    for(i=1;i<RYZ_VFS_NODES;i++)if(w->nodes[i].used){
        size_t path=4;unsigned int cursor=i,depth=0;
        if(!w->nodes[w->nodes[i].parent].used || !w->nodes[w->nodes[i].parent].directory)return 0;
        for(j=0;j<RYZ_VFS_NODES;j++)if(j!=i && w->nodes[j].used && (w->nodes[i].inode==w->nodes[j].inode || (w->nodes[i].parent==w->nodes[j].parent && !strcmp(w->nodes[i].name,w->nodes[j].name))))return 0;
        while(cursor){
            if(++depth>=RYZ_VFS_NODES || !w->nodes[cursor].used)return 0;
            path+=strlen(w->nodes[cursor].name)+1;if(path>=RYZ_NS_PATH_MAX)return 0;
            cursor=w->nodes[cursor].parent;
        }
    }
    return 1;
}
static void fs_export(RyzLinuxWorld *w,RyzFilesystemResources *resource)
{
    unsigned char *bytes=resource->output;unsigned int i,count=0;size_t at=40,length;RyzVnode *node;
    if(!w->nodes[0].used){w->nodes[0].used=w->nodes[0].linked=w->nodes[0].directory=1;w->nodes[0].permissions=0700;w->nodes[0].inode=2000;memcpy(w->nodes[0].name,"tmp",4);w->next_inode=2001;}
    memset(bytes,0,40);memcpy(bytes,"FLEXFS2\n",8);encode(bytes+24,w->next_inode,8);encode(bytes+32,w->clock,8);
    for(i=0;i<RYZ_VFS_NODES;i++)if(w->nodes[i].used && w->nodes[i].linked){
        node=&w->nodes[i];length=strlen(node->name);count++;
        memset(bytes+at,0,80);encode(bytes+at,i,4);encode(bytes+at+4,node->parent,4);encode(bytes+at+8,node->permissions,4);encode(bytes+at+12,(uint64_t)(node->symlink?2:node->directory),4);encode(bytes+at+16,node->inode,8);encode(bytes+at+24,node->size,4);encode(bytes+at+28,length,4);
        encode(bytes+at+32,node->atime,8);encode(bytes+at+40,node->atime_ns,8);encode(bytes+at+48,node->mtime,8);encode(bytes+at+56,node->mtime_ns,8);encode(bytes+at+64,node->ctime,8);encode(bytes+at+72,node->ctime_ns,8);at+=80;
        memcpy(bytes+at,node->name,length);at+=length;
        if(node->size)memcpy(bytes+at,node->bytes,node->size);
        at+=node->size;
    }
    encode(bytes+8,at+8,8);encode(bytes+16,count,4);encode(bytes+at,fs_checksum(bytes,at),8);resource->output_size=at+8;
}
