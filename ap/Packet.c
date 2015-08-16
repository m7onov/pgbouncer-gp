/*-------------------------------------------------------------------------
 * Packet.c:
 *     Implement auth related function
 *
 * Copyright (c) 2015 Pivotal Inc. All Rights Reserved
 *
 *-------------------------------------------------------------------------
 */
#include <stdio.h>

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "packet.h"
#include "auth_util.h"


void FAKE_auth(const char* buf, int peerfd) {
	printf("%s\n",buf);
	sleep_ms(100);
	AuthSuccess(peerfd);
}

AuthFun GetAuthFunbyType(PacketType pkt) {
	return &LDAP_auth;
	//return &FAKE_auth;
}


void AuthSuccess(int fd) {
	PacketType t = RESULT_OK;
	uint32_t len = 0;
	int err;
	err = writen(fd,&t,1);
	if(err < 0) {
		// I don't know how to handle this failure...
		goto faill;
	}
	err = writen(fd,&len,4);
	if(err < 0) {
        goto faill;
	}
 faill:
	return;
}


void AuthFail(int fd, const char* reason) {
	PacketType t = RESULT_FAIL;
	uint32_t len, nlen;
	int err;
	len = strlen(reason) + 1; // tailing  0
	nlen = htonl(len);
	err = writen(fd,&t,1);
	if(err < 0)
		goto faill;
	err = writen(fd,&nlen,4);
	if(err < 0)
		goto faill;
	err = writen(fd,reason,len);
	if(err < 0)
		goto faill;
 faill:
	return;
}
