/* SPDX-License-Identifier: AGPL-3.0-only */
#ifdef MAC_PLAN9
#include <u.h>
#include <libc.h>
#include <libsec.h>
#else
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
typedef uint64_t uvlong;
typedef uint32_t uint;
typedef unsigned char uchar;
#endif

#include "grant.h"

enum { ImageBytes = 8472, Page = 4096, MaxSteps = 64, OutputLimit = 256 };
enum { Base = 0x200000, Stack = 0x400000, WriteThunk = 0x10000, ReturnThunk = 0x10008 };
enum { Ax, Cx, Dx, Bx, Sp, Bp, Si, Di };
static const uchar reference_digest[32] = {
    0x47,0x84,0x99,0xee,0xfd,0x52,0x28,0xf5,0x6f,0xfa,0xed,0x4d,0xaf,0xc0,0x74,0x36,
    0xb0,0x1a,0xe1,0x31,0x9f,0x1c,0xc9,0x59,0x98,0xae,0xcb,0x92,0xe4,0x6a,0xfc,0x1f
};
static const uchar m3_digest[32] = {
    0x4b,0x2f,0xdd,0x6c,0x3f,0xbe,0x8c,0x4c,0x98,0x41,0xf6,0xbe,0x0b,0x3b,0x97,0x2e,
    0x1d,0x73,0xc1,0xac,0xa3,0x41,0xfa,0x1f,0xea,0x9f,0x47,0x16,0xf9,0x0b,0xf4,0x90
};
static int m3, carry, guest_file = -1;
static unsigned long file_offset;
static uint opens, reads, writes, denials;
static uchar image[ImageBytes+1], text[Page], data[Page], linkedit[Page], stack[Page];
static uchar output[OutputLimit];
static uvlong regs[8], ip;
static uint output_size, calls, steps;
static int equal;

static uint
read32(const uchar *p)
{
    return (uint)p[0] | (uint)p[1]<<8 | (uint)p[2]<<16 | (uint)p[3]<<24;
}

static uvlong
read64(const uchar *p)
{
    return read32(p) | (uvlong)read32(p+4)<<32;
}

static void
write64(uchar *p, uvlong value)
{
    int i;
    for(i=0; i<8; i++)
        p[i] = value>>(8*i);
}

static int
within(uvlong addr, uvlong start, uvlong length, uvlong count)
{
    return addr >= start && addr-start <= length && count <= length-(addr-start);
}

static int
push(uvlong value)
{
    if(regs[Sp]<8 || !within(regs[Sp]-8, Stack, Page, 8))
        return 0;
    regs[Sp] -= 8;
    write64(stack+regs[Sp]-Stack, value);
    return 1;
}

static int
pop(uvlong *value)
{
    if(!within(regs[Sp], Stack, Page, 8))
        return 0;
    *value = read64(stack+regs[Sp]-Stack);
    regs[Sp] += 8;
    return 1;
}

static uvlong
relative(uvlong next, uint displacement)
{
    if(displacement & 0x80000000U)
        return next - ((uvlong)0x100000000ULL-displacement);
    return next+displacement;
}

/* Only called after checking the digest of the complete M1 executable.
 * Read its load commands and copy its three mapped segments into private
 * backing arrays. PAGEZERO remains unmapped. The fixture has no rebases. */
static int
load_reference(void)
{
    const uchar *command, *fixups, *starts, *segment, *imports, *symbols;
    uchar *target;
    uint i, kind, offset, length, entry, fixup_offset, fixup_size;
    uvlong preferred, va, file, size, pointer;

    preferred = 0x100000000ULL;
    entry = fixup_offset = fixup_size = 0;
    command = image+32;
    for(i=0; i<read32(image+16); i++){
        kind = read32(command);
        length = read32(command+4);
        if(kind==0x19){
            va = read64(command+24);
            file = read64(command+40);
            size = read64(command+48);
            if(va!=0){
                if(va==preferred)
                    target = text;
                else if(va==preferred+Page)
                    target = data;
                else if(va==preferred+2*Page)
                    target = linkedit;
                else
                    return 0;
                memmove(target, image+file, size);
            }
        }else if(kind==0x80000028U){
            entry = read32(command+8);
        }else if(kind==0x80000034U){
            fixup_offset = read32(command+8);
            fixup_size = read32(command+12);
        }
        command += length;
    }
    if(entry>=Page || entry==0 || fixup_offset!=2*Page || fixup_size!=96)
        return 0;
    fixups = linkedit;
    starts = fixups+read32(fixups+4);
    segment = starts+read32(starts+12); /* segment index 2, DATA_CONST */
    imports = fixups+read32(fixups+8);
    symbols = fixups+read32(fixups+12);
    offset = segment[22] | (uint)segment[23]<<8;
    if(read32(fixups+16)!=1 || read32(fixups+20)!=1 ||
       segment[6]!=6 || segment[7]!=0 || offset!=0)
        return 0;
    pointer = read64(data+offset);
    if(pointer!=((uvlong)1<<63) || (read32(imports)&0xff)!=1 ||
       strcmp((const char *)symbols+(read32(imports)>>9), "_write")!=0)
        return 0;
    write64(data+offset, WriteThunk);
    ip = Base+entry;
    regs[Sp] = Stack+Page;
    return push(ReturnThunk);
}

enum { Data = Base+Page, Scratch = 256, Argv = 256, Envp = 280 };
enum { ArgZero = 512, ArgName = 576, EnvNote = 640, GuestHandle = 3 };
enum { TrapRead = 0x2000003, TrapWrite, TrapOpen, TrapClose };

static int
load_m3(const char *name, const char *note)
{
    unsigned int i;
    uint entry = read32(image+184);

    if(strlen(name)>63 || strlen(note)!=4 || entry>=Page)
        return 0;
    for(i=0; i<4; i++)
        if(note[i]<' ' || note[i]>'~')
            return 0;
    memmove(text, image, Page);
    strcpy((char *)data+ArgZero, "m3");
    strcpy((char *)data+ArgName, name);
    strcpy((char *)data+EnvNote, "FLEX_NOTE=");
    memmove(data+EnvNote+10, note, 4);
    write64(data+Argv, Data+ArgZero);
    write64(data+Argv+8, Data+ArgName);
    write64(data+Envp, Data+EnvNote);
    regs[Di] = 2;
    regs[Si] = Data+Argv;
    regs[Dx] = Data+Envp;
    regs[Sp] = Stack+Page;
    ip = Base+entry;
    return push(ReturnThunk);
}

static int
file_trap(void)
{
    long result = -1;
    uvlong address = regs[Si];
    uvlong size = regs[Dx];
    uvlong handle = regs[Di];
    uchar *bytes;

    switch(regs[Ax]){
    case TrapOpen:
        if(guest_file<0 && regs[Si]==2 && within(handle, Data, Page, 64)){
            bytes = data+handle-Data;
            if(memchr(bytes, 0, 64)){
                guest_file = mac_grant_open((const char *)bytes);
                if(guest_file>=0){
                    file_offset = 0;
                    opens++;
                    result = GuestHandle;
                }
            }
        }
        break;
    case TrapRead:
        if(handle==GuestHandle && guest_file>=0 && size<=Scratch &&
           within(address, Data, Scratch, size)){
            result = mac_grant_read(guest_file, data+address-Data, size, file_offset);
            if(result>=0){
                file_offset += result;
                reads++;
            }
        }
        break;
    case TrapWrite:
        if(size>Scratch || !within(address, Data, Page, size))
            break;
        bytes = data+address-Data;
        if(handle==1 && size<=OutputLimit-output_size){
            memmove(output+output_size, bytes, size);
            output_size += size;
            calls++;
            result = size;
        }else if(handle==GuestHandle && guest_file>=0){
            result = mac_grant_write(guest_file, bytes, size, file_offset);
            if(result>=0){
                file_offset += result;
                writes++;
            }
        }
        break;
    case TrapClose:
        if(handle==GuestHandle && guest_file>=0){
            mac_grant_close(guest_file);
            guest_file = -1;
            result = 0;
        }
        break;
    default:
        return 0;
    }
    carry = result<0;
    if(carry)
        denials++;
    regs[Ax] = carry ? 13 : result;
    return 1;
}

static int
execute(void)
{
    const uchar *p;
    uvlong next, slot, value, count;
    uchar op;

    for(steps=0; steps<MaxSteps; steps++){
        if(!within(ip, Base, Page, 1))
            return 0;
        p = text+ip-Base;
        op = p[0];
        if(op>=0x50 && op<=0x57){
            if(!push(regs[op-0x50]))
                return 0;
            ip++;
        }else if(op>=0x58 && op<=0x5f){
            if(op==0x5c || !pop(&regs[op-0x58]))
                return 0;
            ip++;
        }else if(op>=0xb8 && op<=0xbf && within(ip,Base,Page,5)){
            regs[op-0xb8] = read32(p+1);
            ip += 5;
        }else if(op==0x48 && within(ip,Base,Page,3) && p[1]==0x89 && p[2]==0xe5){
            regs[Bp] = regs[Sp];
            ip += 3;
        }else if(op==0x48 && within(ip,Base,Page,7) && p[1]==0x8d && p[2]==0x35){
            regs[Si] = relative(ip+7, read32(p+3));
            ip += 7;
        }else if(m3 && op==0x48 && within(ip,Base,Page,4) &&
                 p[1]==0x8b && p[2]==0x7e && p[3]==8){
            if(!within(regs[Si],Data,Page,16))
                return 0;
            regs[Di] = read64(data+regs[Si]-Data+8);
            ip += 4;
        }else if(m3 && op==0x48 && within(ip,Base,Page,3) &&
                 p[1]==0x8b && p[2]==0x2a){
            if(!within(regs[Dx],Data,Page,8))
                return 0;
            regs[Bp] = read64(data+regs[Dx]-Data);
            ip += 3;
        }else if(m3 && op==0x48 && within(ip,Base,Page,3) &&
                 p[1]==0x89 && p[2]==0xee){
            regs[Si] = regs[Bp];
            ip += 3;
        }else if(m3 && op==0x89 && within(ip,Base,Page,2) &&
                 (p[1]==0xc3 || p[1]==0xdf)){
            if(p[1]==0xc3)
                regs[Bx] = (uint)regs[Ax];
            else
                regs[Di] = (uint)regs[Bx];
            ip += 2;
        }else if(m3 && op==0x0f && within(ip,Base,Page,2) && p[1]==5){
            if(!file_trap())
                return 0;
            ip += 2;
        }else if(m3 && (op==0x72 || op==0x75) && within(ip,Base,Page,2)){
            value = p[1];
            if(value>=128)
                value |= 0xffffff00U;
            next = ip+2;
            ip = (op==0x72 ? carry : !equal) ? relative(next, value) : next;
        }else if(op==0xe8 && within(ip,Base,Page,5)){
            next = ip+5;
            if(!push(next))
                return 0;
            ip = relative(next, read32(p+1));
        }else if(op==0xff && within(ip,Base,Page,6) && p[1]==0x25){
            slot = relative(ip+6, read32(p+2));
            if(slot!=Base+Page || read64(data)!=WriteThunk ||
               (regs[Sp]&15)!=8 || regs[Di]!=1 || calls!=0)
                return 0;
            count = regs[Dx];
            if(count>OutputLimit || !within(regs[Si],Base,Page,count))
                return 0;
            memmove(output, text+regs[Si]-Base, count);
            output_size = count;
            regs[Ax] = count;
            calls++;
            if(!pop(&ip))
                return 0;
        }else if(op==0x48 && within(ip,Base,Page,4) && p[1]==0x83 && p[2]==0xf8){
            value = p[3];
            if(value>=128)
                value |= ~(uvlong)255;
            equal = regs[Ax]==value;
            ip += 4;
        }else if(op==0x0f && within(ip,Base,Page,3) && p[1]==0x45 && p[2]==0xc3){
            if(!equal)
                regs[Ax] = (uint)regs[Bx];
            ip += 3;
        }else if(op==0x48 && within(ip,Base,Page,4) && p[1]==0x83 && p[2]==0xc4){
            if(p[3]>=128 || !within(regs[Sp],Stack,Page,p[3]))
                return 0;
            regs[Sp] += p[3];
            ip += 4;
        }else if(op==0xc3){
            if(!pop(&ip))
                return 0;
            if(ip==ReturnThunk)
                return regs[Sp]==Stack+Page && (m3 || calls==1);
        }else
            return 0;
    }
    return 0;
}

static int
run_reference(int argc, char **argv)
{
    uchar digest[32];
    char *path;
    unsigned int expected;
    int ok;
    long count;
#ifdef MAC_PLAN9
    int fd;
#else
    FILE *file;
#endif

    if(argc!=2 && argc!=5)
        return 0;
    m3 = argc==5;
    path = argv[1];
    expected = m3 ? Page : ImageBytes;
#ifdef MAC_PLAN9
    fd = open(path, OREAD);
    if(fd<0)
        return 0;
    count = readn(fd, image, sizeof image);
    close(fd);
    if(count!=expected)
        return 0;
    sha2_256(image, expected, digest, nil);
#else
    file = fopen(path, "rb");
    if(file==NULL)
        return 0;
    count = fread(image, 1, sizeof image, file);
    if(ferror(file)){
        fclose(file);
        return 0;
    }
    fclose(file);
    if(count!=expected || SHA256(image, expected, digest)==NULL)
        return 0;
#endif
    if(memcmp(digest, m3 ? m3_digest : reference_digest, sizeof digest)!=0)
        return 0;
    if(m3){
        if(!load_m3(argv[3], argv[4]))
            return 0;
        if(strcmp(argv[2], "-")!=0 && !mac_grant_init(argv[2]))
            return 0;
        ok = execute();
        if(guest_file>=0)
            mac_grant_close(guest_file);
        return ok;
    }
    return load_reference() && execute();
}

#ifdef MAC_PLAN9
void
main(int argc, char **argv)
{
    if(!run_reference(argc, argv))
        sysfatal("unsupported Mac reference image or execution fault");
    if(write(1, output, output_size)!=output_size)
        sysfatal("output failed");
    if(m3)
        print("MAC_M3_EXIT %ud STEPS %ud OPEN %ud READ %ud WRITE %ud DENIED %ud\n",
              (uint)regs[Ax], steps+1, opens, reads, writes, denials);
    else
        print("MAC_M2_EXIT %ud STEPS %ud WRITE_CALLS %ud\n", (uint)regs[Ax], steps+1, calls);
    exits(nil);
}
#else
int
main(int argc, char **argv)
{
    if(!run_reference(argc, argv)){
        fputs("unsupported Mac reference image or execution fault\n", stderr);
        return 125;
    }
    if(fwrite(output, 1, output_size, stdout)!=output_size || fflush(stdout)!=0)
        return 125;
    return (uint)regs[Ax]&255;
}
#endif
