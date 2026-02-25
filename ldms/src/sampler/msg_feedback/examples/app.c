/* -*- c-basic-offset: 8 -*-
 * Copyright (c) 2026 National Technology & Engineering Solutions
 * of Sandia, LLC (NTESS). Under the terms of Contract DE-NA0003525 with
 * NTESS, the U.S. Government retains certain rights in this software.
 * Copyright (c) 2026 Open Grid Computing, Inc. All rights reserved.
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

#include <stdio.h>
#include <getopt.h>

#include "ldms/ldms.h"
#include "ldms/ldms_msg_chan.h"

const char *short_opts = "x:h:p:a:i:";

const char *xprt_s = "sock";
const char *host_s = NULL;
int port = 0;
const char *auth_s = NULL;
const char *id_s = NULL; /* id for feedback channel */

ldms_msg_chan_t chan = NULL;

void usage()
{
	printf("usage: porg [-x XPRT] -h HOST -p PORT -i FEEDBACK_ID [-a auth]\n");
}

void process_args(int argc, char **argv)
{
	int c;
	c = getopt(argc, argv, short_opts);
loop:
	if (c < 0)
		goto out;
	switch (c) {
	case 'x':
		xprt_s = optarg;
		break;
	case 'h':
		host_s = optarg;
		break;
	case 'p':
		port = atoi(optarg);
		break;
	case 'a':
		auth_s = optarg;
		break;
	case 'i':
		id_s = optarg;
		break;
	}
	c = getopt(argc, argv, short_opts);
	goto loop;
 out:
	if (!host_s || !port || ! id_s) {
		usage();
		exit(-1);
	}
}

int msg_cb(ldms_msg_event_t ev, void *arg)
{
	if (ev->type != LDMS_MSG_EVENT_RECV)
		return 0; /* ignore other events */
	printf("recv: %.*s\n", ev->recv.data_len, ev->recv.data);
	return 0;
}

int main(int argc, char **argv)
{
	uid_t uid = getuid();
	gid_t gid = getgid();

	process_args(argc, argv);
	chan = ldms_msg_chan_new(id_s, LDMS_MSG_CHAN_MODE_BIDIR, xprt_s, host_s, port, NULL, 0, auth_s, NULL, 1);

	assert(chan);

	char buf[4096];
	int len;

	sleep(2);

	ldms_msg_chan_subscribe(chan, id_s, msg_cb, chan);

	len = snprintf(buf, sizeof(buf), "sub:%s", id_s);
	printf("publishing on %s: %s\n", "feedback_cmd", buf);
	ldms_msg_chan_publish(chan, "feedback_cmd", uid, gid, 0600, LDMS_MSG_STRING, buf, len);

	sleep(2);

	len = snprintf(buf, sizeof(buf), "%s:hello", id_s);
	printf("publishing on %s: %s\n", "app", buf);
	ldms_msg_chan_publish(chan, "app", uid, gid, 0600, LDMS_MSG_STRING, buf, len);

	printf("Hit <ENTER> to tear down & exit ...");
	fgets(buf, sizeof(buf), stdin);

	len = snprintf(buf, sizeof(buf), "unsub:%s", id_s);
	printf("publishing on %s: %s\n", "feedback_cmd", buf);
	ldms_msg_chan_publish(chan, "feedback_cmd", uid, gid, 0600, LDMS_MSG_STRING, buf, len);

	printf("exiting ...\n");
	sleep(2);
	return 0;
}
