/* SPDX-License-Identifier: AGPL-3.0-only */
__thread int shared_tls=17;
int library_value=4;
__attribute__((constructor)) static void initialize(void){library_value+=3;}
int flex_add(int x){return x+shared_tls+library_value;}
