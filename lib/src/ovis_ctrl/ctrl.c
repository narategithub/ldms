/* -*- c-basic-offset: 8 -*-
 * Copyright (c) 2010 Open Grid Computing, Inc. All rights reserved.
 * Copyright (c) 2010 Sandia Corporation. All rights reserved.
 * Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive
 * license for use of this work by or on behalf of the U.S. Government.
 * Export of this program may require a license from the United States
 * Government.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the BSD-type
 * license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *      Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *      Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 *      Neither the name of Sandia nor the names of any contributors may
 *      be used to endorse or promote products derived from this software
 *      without specific prior written permission. 
 *
 *      Neither the name of Open Grid Computing nor the names of any
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission. 
 *
 *      Modified source versions must be plainly marked as such, and
 *      must not be misrepresented as being the original software.    
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * This is an AF_UNIX version of the muxr program.
 */
#include <unistd.h>
#include <inttypes.h>
#include <stdarg.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/un.h>
#include <ctype.h>
#include <netdb.h>
#include <pthread.h>
#include <libgen.h>

#if USE_TF
#ifdef __linux
#define TF() default_log("Thd%lu:%s:%lu\n", (unsigned long)pthread_self, __FUNCTION__, __LINE__)
#else
#define TF() default_log("%s:%d\n", __FUNCTION__, __LINE__)
#endif /* linux */
#else
#define TF()
#endif /* 1 or 0 disable tf */
#include "ctrl.h"
BIG_DSTRING_TYPE(LDMS_MSG_MAX);

/*
 * The '#' char indicates a comment line. Empty lines are ignored.
 * The keywords are relay, passive, and bridge as follows:
 *
 * active - Connect to the specified host and collect its metrics at the
 *         specified interval
 *
 * passive - Listen for incoming connect requests from the specified host
 *           and when connected collect it's metrics at the specified
 *	     interval.
 *
 * bridge - Just connect to the specified host on the specified port. This is
 *          intended to be the active half of a brdige across a firewall that
 *          only allows outgoing connections.
 *
 * The general syntax of a line is as follows:
 * host-type host-name transport-name port-number sample-interval (usecs)
 * An example configuration file,
 *
 * # this is the comment
 * active nid00016 50000 sock 1000000
 * active mzlogin01-priv 50000 sock 1000000
 * passive mzlogin01e 50000 sock 1000000
 * bridge ovis-shepherd.sandia.gov 8192 sock 1000000
 */

#define ARRAY_SIZE(__a) (sizeof(__a) / sizeof(__a[0]))

static int send_req(struct ctrlsock *sock, char *data, ssize_t data_len)
{
	TF();
	struct msghdr reply;
	struct iovec iov;

	reply.msg_name = sock->sa;
	reply.msg_namelen = sock->sa_len;
	iov.iov_base = data;
	iov.iov_len = data_len;
	reply.msg_iov = &iov;
	reply.msg_iovlen = 1;
	reply.msg_control = NULL;
	reply.msg_controllen = 0;
	reply.msg_flags = 0;
	return sendmsg(sock->sock, &reply, 0);
}

static int recv_rsp(struct ctrlsock *sock, char *data, ssize_t data_len)
{
	TF();
	struct msghdr msg;
	int msglen;
	struct iovec iov;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	iov.iov_base = data;
	iov.iov_len = data_len;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	msg.msg_flags = 0;

	msglen = recvmsg(sock->sock, &msg, 0);
	return msglen;
}

void ctrl_close(struct ctrlsock *sock)
{
	struct sockaddr_un sun;
	socklen_t salen = sizeof(sun);
	if (!getsockname(sock->sock, (struct sockaddr *)&sun, &salen)) {
		if (unlink(sun.sun_path))
			perror("unlink: ");
	} else
		perror("getsockname: ");
	close(sock->sock);
	free(sock);
}

#define BUFFER_OVERFLOWS_ALLOWED 0

#if BUFFER_OVERFLOWS_ALLOWED
static char msg_buf[LDMS_MSG_MAX]; // Brandt changed from 4096 to support large adds
static char arg[LDMS_MSG_MAX]; // Brandt changed from 1024 to support large adds

int ctrl_request(struct ctrlsock *sock, int cmd_id,
		 struct attr_value_list *avl, char *err_str)
{
	TF();
	int rc;
	int status;
	int cnt;
	dsinit;

	sprintf(msg_buf, "%d ", cmd_id);
	for (rc = 0; rc < avl->count; rc++) {
		sprintf(arg, "%s=%s ", avl->list[rc].name, avl->list[rc].value);
		strcat(msg_buf, arg);
	}
	strcat(msg_buf, "\n");
	rc = send_req(sock, msg_buf, strlen(msg_buf)+1);
	if (rc < 0) {
		sprintf(err_str, "Error %d sending request.\n", rc);
		return -1;
	}
	rc = recv_rsp(sock, msg_buf, sizeof(msg_buf));
	if (rc <= 0) {
		sprintf(err_str, "Error %d receiving reply.\n", rc);
		return -1;
	}
	err_str[0] = '\0';
	rc = sscanf(msg_buf, "%d%n", &status, &cnt);
	strcpy(err_str, &msg_buf[cnt]);
	return status;
}

#else 
/* non-threadsafe string buffer (whether dstring_t or char array)
  to avoid constant allocation traffic.
  In the case of dstring, there is possibly a one-time leak at exit in
  corner cases.
 
  This code is both faster and safer than the old code.
*/
static int init_done=0;
big_dstring_t msg_buf;
#define cat(x) bdstrcat(&msg_buf,x,DSTRING_ALL)

int ctrl_request(struct ctrlsock *sock, int cmd_id,
		 struct attr_value_list *avl, char *err_str)
{
	TF();
	int rc;
	int status;
	int cnt;
	static char ibuf[32]; /* big enough for int32 or 64 decimal formatted */
        if (!init_done) {
		init_done = 1;
		bdstr_init(&msg_buf);
	}

	sprintf(ibuf, "%d ", cmd_id);
	bdstr_set(&msg_buf, ibuf);
	for (rc = 0; rc < avl->count; rc++) {
		cat(avl->list[rc].name);
		cat("=");
		cat(avl->list[rc].value);
		cat(" ");
	}
	cat("\n");
	/* cast safe since passing len also */
	rc = send_req(sock, (char *)bdstrval(&msg_buf), bdstrlen(&msg_buf)+1);
	if (rc < 0) {
		sprintf(err_str, "Error %d sending request.\n", rc);
		return -1;
	}
	rc = recv_rsp(sock, (char *)bdstrval(&msg_buf), bdstrcurmaxlen(&msg_buf));
	if (rc <= 0) {
		sprintf(err_str, "Error %d receiving reply.\n", rc);
		return -1;
	}
	err_str[0] = '\0';
	rc = sscanf(bdstrval(&msg_buf), "%d%n", &status, &cnt);
	strcpy(err_str, (bdstrval(&msg_buf)+cnt));
	return status;
}


#endif

#ifdef DEPRECATED
struct ctrlsock *ctrl_inet_connect(struct sockaddr_in *sin)
{
	int rc;
	struct ctrlsock *sock;

	sock = calloc(1, sizeof *sock);
	if (!sock)
		return NULL;

	sock->sin = *sin;
	sock->sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sock->sock < 0)
		goto err;

	return sock;
 err:
	free(sock);
	return NULL;
}
#endif

struct ctrlsock *ctrl_connect(char *my_name, char *sockname)
{
	TF();
	int rc;
	struct sockaddr_un my_un;
	if (!my_name || !sockname)
		return NULL;
	char *mn = strdup(my_name);
	if (!mn) {
		return NULL; /* hopeless situation that may however resolve later */
	}
	char *sockpath;
	struct ctrlsock *sock;

	sock = calloc(1, sizeof *sock);
	if (!sock) {
		free(mn);
		return NULL;
	}
	sockpath = getenv("LDMSD_SOCKPATH");
	if (!sockpath)
		sockpath = "/var/run";

	sock->rem_sun.sun_family = AF_UNIX;
	if (sockname[0] == '/')
		strcpy(my_un.sun_path, sockname);
	else
		sprintf(my_un.sun_path, "%s/%s", sockpath, sockname);

	strncpy(sock->rem_sun.sun_path, my_un.sun_path,
		sizeof(struct sockaddr_un) - sizeof(short));

	/* Create control socket */
	sock->sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sock->sock < 0) {
		free(mn);
		goto err;
	}

	pid_t pid = getpid();
	sock->lcl_sun.sun_family = AF_UNIX;

	sprintf(my_un.sun_path, "%s/%s", sockpath, basename(mn));
	free(mn);

	mkdir(my_un.sun_path, 0755);
	sprintf(sock->lcl_sun.sun_path, "%s/%d", my_un.sun_path, pid);

	/* Bind to our public name */
	rc = bind(sock->sock, (struct sockaddr *)&sock->lcl_sun,
		  sizeof(struct sockaddr_un));
	if (rc < 0) {
		printf("Error creating '%s'\n", sock->lcl_sun.sun_path);
		close(sock->sock);
		goto err;
	}
	sock->sa = (struct sockaddr *)&sock->rem_sun;
	sock->sa_len = sizeof(sock->rem_sun);
	return sock;
 err:
	free(sock);
	return NULL;
}

