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
/**
 * \file msg_feedback.c
 */
#define _GNU_SOURCE
#include <inttypes.h>
#include <unistd.h>
#include <sys/errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <pthread.h>
#include "ldms.h"
#include "ldms_msg_chan.h"
#include "ldmsd.h"
#include "ldmsd_plug_api.h"

typedef struct msg_feedback_s {
	ldms_msg_chan_t chan;
	ldms_msg_client_t mc;
	char *cmd_channel;
	ovis_log_t log;
} *msg_feedback_t;

static const char *usage(ldmsd_plug_handle_t handle)
{
	return  "config name=INST host=HOST port=PORT xprt=XPRT auth=AUTH cmd_channel=CHANNEL" ;
}

int chan_cb(ldms_msg_event_t ev, void *handle)
{
	/* no-op */
	return 0;
}

#define _LOG(m, LVL, FMT, ...) ovis_log((m)->log, LVL, FMT, ## __VA_ARGS__ )

#define _DEBUG(m, FMT, ...) _LOG(m, OVIS_LDEBUG, FMT, ## __VA_ARGS__ )
#define _ERROR(m, FMT, ...) _LOG(m, OVIS_LERROR, FMT, ## __VA_ARGS__ )

int cmd_msg_cb(ldms_msg_event_t ev, void *handle)
{
	msg_feedback_t m = ldmsd_plug_ctxt_get(handle);
	const char *name;
	if (ev->type != LDMS_MSG_EVENT_RECV)
		return 0; /* only handle recv */
	_DEBUG(m, "%s recv: %.*s\n", ldmsd_myname_get(), ev->recv.data_len, ev->recv.data);
	if (0 == strncmp("sub:", ev->recv.data, 4)) {
		name = ev->recv.data + 4;
		ldms_msg_chan_subscribe_exact(m->chan, name, chan_cb, handle);
	} else if (0 == strncmp("unsub:", ev->recv.data, 6)) {
		name = ev->recv.data + 6;
		ldms_msg_chan_unsubscribe(m->chan, name);
	} /* else, ignore */
	return 0;
}

static int config(ldmsd_plug_handle_t handle,
		  struct attr_value_list *kwl, struct attr_value_list *avl)
{
	msg_feedback_t m = ldmsd_plug_ctxt_get(handle);
	struct ldmsd_auth *auth = NULL;
	const char *cmd_channel_s = av_value(avl, "cmd_channel");

	const char *xprt_s = av_value(avl, "xprt");
	const char *port_s = av_value(avl, "port");
	const char *host_s = av_value(avl, "host");
	const char *auth_s = av_value(avl, "auth");

	int port;

	#define PARAM_EXIST(name) \
	if (! name ## _s) { \
		_ERROR(m, #name " config parameter is required\n"); \
		return EINVAL; \
	}

	PARAM_EXIST(cmd_channel);
	PARAM_EXIST(xprt);
	PARAM_EXIST(host);
	PARAM_EXIST(port);

	if (m->chan) {
		_ERROR(m, "already configured\n");
		return EEXIST;
	}

	m->cmd_channel = strdup(cmd_channel_s);

	port = atoi(port_s);
	if (!port) {
		_ERROR(m, "invalid port value: %s\n", port_s);
		return EINVAL;
	}

	if (auth_s) {
		auth = auth_s?ldmsd_auth_find(auth_s):NULL;
		if (!auth) {
			_ERROR(m, "auth '%s' not found\n", auth_s);
			return ENOENT;
		}
	}

	m->chan = ldms_msg_chan_new("ldmsd", LDMS_MSG_CHAN_MODE_BIDIR,
			xprt_s, host_s, port,
			NULL /* lcl host */,
			0 /* local port 0 for not listening */,
			auth?auth->plugin:"none",
			auth?auth->attrs:NULL,
			1 /* reconnect interval in sec */);
	if (!m->chan) {
		_ERROR(m, "channel create error\n");
		return errno;
	}
	m->mc = ldms_msg_subscribe(cmd_channel_s, 0, cmd_msg_cb, handle, "msg_feedback");

	m->log = ldmsd_plug_log_get(handle);
	return 0;
}

static int sample(ldmsd_plug_handle_t handle)
{
	/* no-op */
	return 0;
}

static int constructor(ldmsd_plug_handle_t handle)
{
	msg_feedback_t m = calloc(1, sizeof(*m));

	if (!m)
		return ENOMEM;
	m->log = ldmsd_plug_log_get(handle);
	ldmsd_plug_ctxt_set(handle, m);

	/* NOTE for debugging, comment this out to get rid of debug log in this
	 *      plugin. */
	ovis_log_set_level(m->log, OVIS_ALL_LEVELS);
	return 0;
}

static void destructor(ldmsd_plug_handle_t handle)
{
	msg_feedback_t m = ldmsd_plug_ctxt_get(handle);
	free(m);
};

struct ldmsd_sampler ldmsd_plugin_interface = {
	.base.type = LDMSD_PLUGIN_SAMPLER,
	.base.flags = LDMSD_PLUGIN_MULTI_INSTANCE,
	.base.config = config,
	.base.usage = usage,
	.base.constructor = constructor,
	.base.destructor = destructor,

	.sample = sample,
};
