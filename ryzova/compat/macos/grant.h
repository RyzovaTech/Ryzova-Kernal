/* SPDX-License-Identifier: GPL-3.0-only */
int mac_grant_init(char *);
int mac_grant_open(const char *);
long mac_grant_read(int, void *, unsigned int, unsigned long);
long mac_grant_write(int, const void *, unsigned int, unsigned long);
void mac_grant_close(int);
