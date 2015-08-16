/*-------------------------------------------------------------------------
 * authproxy.c:
 *    main loop of authentication. It process auth requirement one by one.
 * TODO:
 *    find a more effeicient way to handle different authentacation request concurrenctly.
 *
 * Copyright (c) 2015 Pivotal Inc. All Rights Reserved
 *
 *-------------------------------------------------------------------------
 */

#include "authproxy.h"

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "packet.h"
#include "auth_util.h"
#include "libunixsocket.h"

#define socket_path  "/tmp/.s.authproxy"

#ifdef _STANDALONE_
int main (int argc, char* argv[] ) {
	return authproxy();
}
#endif
/* main auth program. Listen on unix socket and send back response */
int authproxy (void) {
	char buf[BUFSIZE];
	int fd,cl;
	PacketType  pkt_type = UNKNOWN;
	uint32_t len, readlen;
	AuthFun authfun;

	fd = create_unix_server_socket(socket_path,LIBSOCKET_STREAM, 0);
	if (fd == -1) {
		perror("socket error");
		exit(-1);
	}

	while (1) {
		cl = accept_unix_stream_socket(fd, 0);
		if(cl == -1) {
			perror("accept error");
			break;
		}
		
		readn(cl, &pkt_type, 1);
		readn(cl, &len, 4);
		//len = ntohl(len);
		//fprintf(stdout, "%d\n",len);
		readlen = (uint32_t)readn(cl, buf, (size_t)len);
		if(readlen < len) {
			// incomplete packet
			fprintf(stderr, "incomplete packet, skip");
			close(cl);
			continue;
		}

		authfun = GetAuthFunbyType(pkt_type);
		if(authfun)
			authfun(buf, cl);  // make fd close_on_exec?
		else {
			// fail
		}
		close(cl);
		
	}
	close(fd);
	return 0;
}
