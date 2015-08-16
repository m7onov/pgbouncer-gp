/*-------------------------------------------------------------------------
 * Generic types and functions for authentication and communication 
 *
 * Copyright (c) 2015 Pivotal Inc. All Rights Reserved
 *
 *-------------------------------------------------------------------------
 */
#ifndef __PACKAT__H__
#define __PACKAT__H__

typedef enum {
	UNKNOWN = 0 ,
	RESULT_OK ,
	RESULT_FAIL,

	AUTH_LDAP,
	AUTH_FAKE,
	AUTH_GSSAPI,
	AUTH_PG,
} PacketType;

#define BUFSIZE  1024


typedef void (* AuthFun) (const char* buf, int peerfd);
AuthFun GetAuthFunbyType(PacketType pkt);

void LDAP_auth(const char* buf, int peerfd);
void FAKE_auth(const char* buf, int peerfd);

void AuthSuccess(int fd);
void AuthFail(int fd, const char* reason);

#endif
