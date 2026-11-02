/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef CW_SYNC_PROTOCOL_H
#define CW_SYNC_PROTOCOL_H
typedef unsigned long long CwSyncNonce;
/* Fixed length messages: no allocation, NUL terminator or partial acceptance. */
void cw_sync_request(CwSyncNonce,char [22]);
int cw_sync_parse(const char *,unsigned int,CwSyncNonce *);
void cw_sync_reply(CwSyncNonce,char [21]);
int cw_sync_ack(const char *,unsigned int,CwSyncNonce);
#endif
