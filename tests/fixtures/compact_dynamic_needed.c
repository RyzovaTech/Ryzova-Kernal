/* SPDX-License-Identifier: AGPL-3.0-only */
#include <stdio.h>
extern int flex_add(int);
int main(void){printf("FLEX_NEEDED_OK %d\n",flex_add(5));return 0;}
