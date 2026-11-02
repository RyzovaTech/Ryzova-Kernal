/* SPDX-License-Identifier: AGPL-3.0-only */
/* Real Windows AMD64 PE import inventory. This fixture is compiled and
 * linked with a *metadata-only* import library and is never executed. */
__declspec(dllimport) int WriteFile(void *,const void *,unsigned long,
                                    unsigned long *,void *);
int main(void) { return WriteFile((void *)0,(void *)0,0,
                                   (unsigned long *)0,(void *)0); }
