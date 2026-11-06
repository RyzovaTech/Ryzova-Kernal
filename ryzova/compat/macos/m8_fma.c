/* SPDX-License-Identifier: AGPL-3.0-only */
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
