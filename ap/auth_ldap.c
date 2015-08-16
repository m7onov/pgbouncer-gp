/*-------------------------------------------------------------------------
 * auth_ldap.c:
 *    Implement LDAP authentication related functions
 *
 * Copyright (c) 2015 Pivotal Inc. All Rights Reserved
 *
 *-------------------------------------------------------------------------
 */
#include <ldap.h>
#include <stdbool.h>
#include <stdio.h>
#include <alloca.h>
#include <sys/time.h>
#include "packet.h"

#define ERRLEN 255
static char err_msg[ERRLEN+1];

/* Do the real LDAP verification work.
 * This function will block and wait for authentication finish. Timeout is 10s
 */
static bool VerifyUser(const char* ldapsrv, const char* user, const char* passwd) {
	LDAP *ld;
	int rc, version;
	struct timeval ts;
	
	if(ldap_initialize(&ld, ldapsrv)) {
		perror("ldap_initialize" );
		snprintf(err_msg, ERRLEN, "ldap_initialize failure\n");
		return false;
	}
	version = LDAP_VERSION3;
	rc = (int) ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version );
	if ( rc != LDAP_OPT_SUCCESS ) {
		snprintf(err_msg, ERRLEN, "ldap_set_option failed!\n");
		return false;
	}
 
	ts.tv_sec = 10;
	ts.tv_usec = 0;
	rc = (int) ldap_set_option( ld, LDAP_OPT_NETWORK_TIMEOUT, &ts);  // set timeout
	if ( rc != LDAP_OPT_SUCCESS ) {
        snprintf(err_msg, ERRLEN, "ldap_set_option failed!\n");
        return false;
    }

	rc = ldap_simple_bind_s(ld, user, passwd);
	if(rc != LDAP_SUCCESS) {
		snprintf(err_msg, ERRLEN,"ldap_simple_bind_s: %s\n", ldap_err2string(rc) );
		ldap_unbind(ld);
		return false;
	}
	ldap_unbind(ld);
	return true;
}

/* Parse creditial from the message send by pgbouncer, verify it and response */
void LDAP_auth(const char* buf, int peerfd) {
	char* ldapsrv, *user, *passwd, *hostaddr;
	bool  result ;
	LDAPURLDesc *ldapdesc;
	int port;
	ldapsrv = (char*)alloca(BUFSIZE);
	hostaddr = (char*)alloca(BUFSIZE);
	passwd = (char*)alloca(BUFSIZE);

	bzero(ldapsrv, BUFSIZE);
	bzero(passwd, BUFSIZE);
	bzero(hostaddr, BUFSIZE);

    // second line is not used in LDAP, just ignore it
	if(sscanf(buf, "%s\n%s\n%s\n", ldapsrv, hostaddr, passwd) < 3) {
        AuthFail(peerfd, "Read credential fail");
        return;
    }
	err_msg[0]=0;
	result = ldap_is_ldap_url( ldapsrv );
	if(!result) {
		AuthFail(peerfd, "Bad ldap url format");
		return;
	}
	
	result = ldap_url_parse(ldapsrv,&ldapdesc);
	user = ldapdesc->lud_dn;
	port = (ldapdesc->lud_port > 0) ? ldapdesc->lud_port : 389;

	snprintf(hostaddr,BUFSIZE,"%s://%s:%d",ldapdesc->lud_scheme,ldapdesc->lud_host,port);

	result = VerifyUser(hostaddr, user, passwd);
	if(result) {
		// tell peerfd success
		AuthSuccess(peerfd);
	} else {
		// failure
		AuthFail(peerfd, err_msg);
	}
	ldap_free_urldesc(ldapdesc);
}
