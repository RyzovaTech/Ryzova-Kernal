/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef MAC_M8_FMA_H
#define MAC_M8_FMA_H
int mac8_fma(unsigned long long, unsigned long long, unsigned long long, unsigned long long *);
int mac8_fp_div(unsigned long long, unsigned long long, unsigned long long *);
unsigned int mac8_fp_compare(unsigned long long, unsigned long long);
unsigned long long mac8_fp_from_int(unsigned long long, unsigned int, int);
unsigned long long mac8_fp_to_int(unsigned long long, unsigned int);
#endif
