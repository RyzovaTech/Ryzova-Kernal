/* SPDX-License-Identifier: GPL-3.0-only */
#include "m8_fma.h"

typedef unsigned long long Word;
enum { Limbs = 8 };
#define HIDDEN (1ULL<<52)
#define SIGN (1ULL<<63)

static unsigned int
bit(const unsigned int *value, int index)
{
    return (value[index/32]>>(index%32))&1;
}

static int
significand(Word bits, Word *value, int *exponent)
{
    unsigned int biased = (bits>>52)&2047;
    if(biased==2047)
        return 0;
    *value = bits&(HIDDEN-1);
    if(biased)
        *value |= HIDDEN;
    *exponent = (biased ? (int)biased : 1)-1075;
    return 1;
}

static void
place(unsigned int *out, const unsigned int *in, int count, int shift)
{
    int i;
    unsigned int at = shift/32, remainder = shift%32;
    for(i=0; i<count; i++){
        out[at+i] |= in[i]<<remainder;
        if(remainder && at+i+1<Limbs)
            out[at+i+1] |= in[i]>>(32-remainder);
    }
}

/* Exact multiply and add of the finite operands before one round-to-nearest.
 * Unsupported exponent gaps and non-normal nonzero results fail closed. */
int
mac8_fma(Word a, Word b, Word c, Word *out)
{
    Word x, y, z, t, carry, result, sign;
    unsigned int product[4] = {0}, addend[2], left[Limbs] = {0}, right[Limbs] = {0};
    unsigned int *large = left, *small = right;
    int ex, ey, ez, i, j, base, highest, first, exponent, subtract, sticky = 0;

    if(!significand(a, &x, &ex) || !significand(b, &y, &ey) || !significand(c, &z, &ez))
        return 0;
    sign = (a^b)&SIGN;
    if(!x || !y){
        *out = z ? c : (sign&c&SIGN);
        return 1;
    }
    ex += ey;
    base = z && ez<ex ? ez : ex;
    if(ex-base>32*Limbs-107 || (z && ez-base>32*Limbs-54))
        return 0;
    for(i=0; i<2; i++){
        carry = 0;
        for(j=0; j<2; j++){
            t = (Word)(unsigned int)(x>>(32*i))*(unsigned int)(y>>(32*j)) + product[i+j] + carry;
            product[i+j] = t;
            carry = t>>32;
        }
        product[i+2] = carry;
    }
    place(left, product, 4, ex-base);
    if(z){
        addend[0] = z;
        addend[1] = z>>32;
        place(right, addend, 2, ez-base);
    }

    subtract = z && ((sign^c)&SIGN)!=0;
    if(subtract){
        for(i=Limbs-1; i>=0 && left[i]==right[i]; i--)
            ;
        if(i<0){
            *out = 0;
            return 1;
        }
        if(left[i]<right[i]){
            large = right;
            small = left;
            sign = c&SIGN;
        }
    }
    carry = 0;
    for(i=0; i<Limbs; i++){
        if(subtract){
            t = (Word)large[i]-small[i]-carry;
            carry = t>>63;
        }else{
            t = (Word)large[i]+small[i]+carry;
            carry = t>>32;
        }
        large[i] = t;
    }

    for(highest=32*Limbs-1; highest>=0 && !bit(large, highest); highest--)
        ;
    if(highest<0){
        *out = sign;
        return 1;
    }
    exponent = highest+base;
    if(exponent<-1022 || exponent>1023)
        return 0;
    first = highest-52;
    result = 0;
    for(i=highest; i>=first; i--)
        result = (result<<1)|(i>=0 ? bit(large, i) : 0);
    if(first>0 && bit(large, first-1)){
        for(i=0; i<first-1 && !sticky; i++)
            sticky = bit(large, i);
        result += sticky || (result&1);
    }
    if(result==2*HIDDEN){
        result >>= 1;
        if(++exponent>1023)
            return 0;
    }
    *out = sign|((Word)(exponent+1023)<<52)|(result&(HIDDEN-1));
    return 1;
}

int
mac8_fp_div(Word a, Word b, Word *out)
{
    Word x, y, q, r, sign = (a^b)&SIGN;
    int ex, ey, exponent, i;
    if(!significand(a, &x, &ex) || !significand(b, &y, &ey) || !y)
        return 0;
    if(!x){
        *out = sign;
        return 1;
    }
    while(x<HIDDEN){
        x <<= 1;
        ex--;
    }
    while(y<HIDDEN){
        y <<= 1;
        ey--;
    }
    exponent = ex-ey;
    if(x<y){
        x <<= 1;
        exponent--;
    }
    q = 1;
    r = x-y;
    for(i=0; i<52; i++){
        r <<= 1;
        q <<= 1;
        if(r>=y){
            r -= y;
            q |= 1;
        }
    }
    r <<= 1;
    if(r>y || (r==y && (q&1)))
        q++;
    if(q==2*HIDDEN){
        q >>= 1;
        exponent++;
    }
    if(exponent<-1022 || exponent>1023)
        return 0;
    *out = sign|((Word)(exponent+1023)<<52)|(q&(HIDDEN-1));
    return 1;
}

unsigned int
mac8_fp_compare(Word a, Word b)
{
    Word x = a&~SIGN, y = b&~SIGN;
    if(x>(2047ULL<<52) || y>(2047ULL<<52))
        return 3;
    if(a==b || !(x|y))
        return 6;
    if((a^b)&SIGN)
        return a&SIGN ? 8 : 2;
    return ((x<y)!=((a&SIGN)!=0)) ? 8 : 2;
}

Word
mac8_fp_from_int(Word value, unsigned int width, int is_signed)
{
    Word sign = 0, q, remainder, half, mask = width==64 ? ~(Word)0 : 0xffffffffU;
    int exponent = 0, shift;
    value &= mask;
    if(is_signed && (value&((Word)1<<(width-1)))){
        sign = SIGN;
        value = (0-value)&mask;
    }
    if(!value)
        return 0;
    for(q=value; q>>1; q>>=1)
        exponent++;
    shift = exponent-52;
    if(shift>0){
        q = value>>shift;
        half = (Word)1<<(shift-1);
        remainder = value&((half<<1)-1);
        if(remainder>half || (remainder==half && (q&1)))
            q++;
        if(q==2*HIDDEN){
            q >>= 1;
            exponent++;
        }
    }else
        q = value<<(-shift);
    return sign|((Word)(exponent+1023)<<52)|(q&(HIDDEN-1));
}

Word
mac8_fp_to_int(Word value, unsigned int width)
{
    Word magnitude, limit = (Word)1<<(width-1);
    int exponent = (int)((value>>52)&2047)-1023;
    if(exponent==1024 && (value&(HIDDEN-1)))
        return 0;
    if(exponent<0)
        return 0;
    if(exponent>=(int)width-1)
        return value&SIGN ? limit : limit-1;
    magnitude = HIDDEN|(value&(HIDDEN-1));
    if(exponent<52)
        magnitude >>= 52-exponent;
    else
        magnitude <<= exponent-52;
    return value&SIGN ? 0-magnitude : magnitude;
}
