/*-------------------------------------------------------------------------
 * Implent generic functions
 *
 * Copyright (c) 2015 Pivotal Inc. All Rights Reserved
 *
 *-------------------------------------------------------------------------
 */

#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

#include "auth_util.h"


ssize_t             /* Write "n" bytes to a descriptor  */
writen(int fd, const void *ptr, size_t n)
{
	size_t		nleft;
	ssize_t		nwritten;
	const char* lptr = ptr;
	nleft = n;
	while (nleft > 0) {
		if ((nwritten = write(fd, lptr, nleft)) < 0) {
			if (nleft == n)
				return(-1); /* error, return -1 */
			else
				break;      /* error, return amount written so far */
		} else if (nwritten == 0) {
			break;
		}
		nleft -= nwritten;
		lptr   += nwritten;
	}
	return(n - nleft);      /* return >= 0 */
}

ssize_t             /* Read "n" bytes from a descriptor  */
readn(int fd, void *ptr, size_t n) {
	size_t          nleft;
	ssize_t         nread;
	char* lptr = ptr;
	nleft = n;
	while (nleft > 0) {
		if ((nread = read(fd, lptr, nleft)) < 0) {
			if (nleft == n)
				return(-1); /* error, return -1 */
			else
				break;      /* error, return amount read so far */
		} else if (nread == 0) {
			break;          /* EOF */
		}
		nleft -= nread;
		lptr   += nread;
	}
	return(n - nleft);      /* return >= 0 */
}

void
sleep_us(unsigned int nusecs)
{
    struct timeval  tval;

    tval.tv_sec = nusecs / 1000000;
    tval.tv_usec = nusecs % 1000000;
    select(0, NULL, NULL, NULL, &tval);
}

void sleep_ms(unsigned int msecs)
{
	sleep_us(1000 * msecs);
}
