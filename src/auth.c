/*-------------------------------------------------------------------------
 * auth.c
 *    Implement Authcontext that needed by external authentication, and related auth functions.
 *    Each authcontext store the information that external auth-proxy will use to verify user.
 *    async_auth_client send credential to auth-proxy and wait for response.
 *
 *
 * Copyright (c) 2015 Pivotal Inc. All Rights Reserved
 *
 *-------------------------------------------------------------------------
 */
#include <unistd.h>

#include "bouncer.h"

#include "auth.h"
#include "auth_util.h"

struct AuthContext* CreateAuthContext(PgSocket* client, const char* passwd) {
	struct AuthContext *pctx;
	// decide auth function, init context
	pctx = (struct AuthContext*)malloc(sizeof(struct AuthContext));
	if(!pctx) {
		log_error("Allocate context failing");
		return NULL;
	}
	pctx->client = client;
	pctx->passwd = strdup(passwd);
	pctx->data = NULL;
	//	pctx->authfun = authcb;
	return pctx;
}

void DestroyAuthContext(struct AuthContext* auth) {
	if(!auth)
		return;
	if(auth->passwd) 
		free(auth->passwd);
	if(auth->data)
		free(auth->data);
	free(auth);
}

/* Tell front end that authentication success */
bool auth_success(PgSocket *client) {
	/* send the message */
	if (!welcome_client(client))
		return false;
	else {
		client->state = CL_ACTIVE;
		return true;
	}
}

/* Tell front end that authentication fail */
bool auth_fail(PgSocket* client, char* buf) {
	// log error
	log_warning("auth failing");
	if(!buf)
		buf = "external auth fail";
	// send error to client
	// disconnect client
	disconnect_client(client, true, "%s",(const char*)buf);
	return true;
}

/* password start with ldap or ldaps is treated as external authenticatoin */
bool need_external_auth(PgSocket *client) {
#if 1
	PgUser *user = client->login_user;
	if(!user || !*user->passwd) {
		return false;
	}
	return strncmp(user->passwd,"ldap",4) == 0;
#endif // 0
	return true;
}

static int create_unix_stream_socket(const char* path, int flags)
{
    struct sockaddr_un saddr;
    int sfd;
	int rc;
	
    if ( path == NULL )
		return -1;
	sfd = socket(AF_UNIX,SOCK_STREAM|flags,0);
    if ( -1 == sfd )
		return -1;
	
    memset(&saddr,0,sizeof(struct sockaddr_un));
	
    if ( strlen(path) > (sizeof(saddr.sun_path)-1) ) {
        close(sfd);
        return -1;
	}

    saddr.sun_family = AF_UNIX;
    strncpy(saddr.sun_path,path,sizeof(saddr.sun_path)-1);
	rc = connect(sfd,(struct sockaddr*)&saddr,sizeof(saddr.sun_family) + strlen(saddr.sun_path));
    if ( -1 == rc) {
        close(sfd);
        return -1;
    }

    return sfd;
}
/* not fully implemented now */
static unsigned char getAuthType(const char* url) {
	return 0;
}

/* read auth result from auth-proxy process */
static void auth_eventcb(int fd, short flags, void *arg) {
    struct AuthContext* authctx = (struct AuthContext*)arg;
	uint32_t len;
	unsigned char type;
	char buf[AUTH_MSGLEN];
	int err;

	if(flags & EV_TIMEOUT ) {
		// auth timemout
		auth_fail(authctx->client, "Authentication timeout");
		DestroyAuthContext(authctx);
		close(fd);
		return;
	}
	if(flags & EV_READ) {
		//fprintf(stdout, "in event cb\n");
		readn(fd,&type,1);
		readn(fd,(unsigned char*)&len,4);  // skip err check here
		err = readn(fd,(unsigned char*)buf, ntohl(len));
		//if(len > 0)
		//	fprintf(stdout, "%s",buf);
		if((type == 1) && (err >= 0))
			auth_success(authctx->client);
		else
			auth_fail(authctx->client, buf);
	} else {
		//unwatched event???
		auth_fail(authctx->client, "unexptected error");
	}
	DestroyAuthContext(authctx);
	close(fd);
}

#define socket_path  "/tmp/.s.authproxy"
/* This is the function that start an async auth process: send essential information to auth-proxy.
 * Add the fd to libevent so that it can wait for result asynchronously.
 * Communication "protocol" between pgboncer and auth proxy is simple: <type, length, message>. 
 * First two fields are fixed length.
 * For authentication, message is <url, username, password>, separated by '\n'.
 */
bool async_auth_client(PgSocket *client, const char* passwd) 
{
	struct AuthContext* pctx = CreateAuthContext(client, passwd);
	PgUser *user;
	char msg[AUTH_MSGLEN];
	uint32_t len,wlen;
	struct timeval ts;
	int err;
	int fd;
	unsigned char t;
	if(!pctx) {
		// can't allocate memory
		DestroyAuthContext(pctx);
		//disconnect_client(client, true, "allocate auth ctx failed");
		return false;
	}
	user = client->login_user;
	if(!user || !*user->passwd) {
		log_warning("NO user/password specified");
		DestroyAuthContext(pctx);
		return false;
	}
	
	fd = create_unix_stream_socket(socket_path,0);
	if(fd == -1) {
		//disconnect_client(client, true, "can't create auth socket");
		log_warning("create socket error with: %s", strerror(errno));
		goto faill;
	}
	snprintf(msg, AUTH_MSGLEN, "%s\n%s\n%s\n",user->passwd, user->name, passwd);
	t = getAuthType(NULL);
	len = strlen(msg) + 1;
	wlen = len;
	//len = htonl(len);
	// set to nonblocking mode
	//fprintf(stdout,"%d,%d, %s\n",t, len, msg);
	err = writen(fd, (unsigned char*)&t,1);
    if (err < 0) {
		log_warning("auth_client error with: %s", strerror(errno));
		goto faill;
	}

	err = writen(fd, (unsigned char*)&wlen,4);
    if (err < 0) {
		log_warning("auth_client error with: %s", strerror(errno));
		goto faill;
	}

	err = writen(fd, (unsigned char*)msg, len);
    if (err < 0) {
		log_warning("auth_client error with: %s", strerror(errno));
		goto faill;
	}

    event_set(&pctx->ev, fd, EV_READ,
              auth_eventcb, pctx);
    ts.tv_sec =  AUTH_TIMEOUT;
    ts.tv_usec = 0;
    err = event_add(&pctx->ev, &ts);
    if (err < 0) {
		log_warning("auth_client error with: %s", strerror(errno));
		goto faill;
	}

	return true;
 faill:
	if(fd >=0)
		close(fd);
	DestroyAuthContext(pctx);
	return false;
}

extern int authproxy(void);

void start_authproxy(void) {
	authproxy();
}
