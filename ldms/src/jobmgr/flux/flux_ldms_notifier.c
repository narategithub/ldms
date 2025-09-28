/* -*- c-basic-offset: 8 -*-
 * Copyright (c) 2025 National Technology & Engineering Solutions
 * of Sandia, LLC (NTESS). Under the terms of Contract DE-NA0003525 with
 * NTESS, the U.S. Government retains certain rights in this software.
 * Copyright (c) 2025 Open Grid Computing, Inc. All rights reserved.
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

#define FLUX_SHELL_PLUGIN_NAME "flux_ldms_notifier"

#include <stdio.h>
#include <flux/core.h>
#include <flux/shell.h>
#include <unistd.h>
#include <sys/types.h>
#include <jansson.h>
#include <stdarg.h>


/* TODO REMOVE ME! (For debug) */
#define LOG_DIR "/tmp/flux-ldms"

char hostname[64];

struct flux_plugin_arg {
	json_error_t error;
	json_t *in;
	json_t *out;
};

static int flog(const char *fmt, ...)
{
	pid_t pid = getpid();
	char path[512];
	FILE *f;
	va_list ap;
	sprintf(path, "%s/%s-%d.log", LOG_DIR, hostname, pid);
	f = fopen(path, "a");
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	fclose(f);
	return 0;
}

static int cb(flux_plugin_t *p, const char *topic,
	      flux_plugin_arg_t *args, void *arg)
{
	static int num = 0;
	char *str = NULL;
	int rc;
	pid_t pid = getpid();
	pid_t ppid = getppid();
	uid_t uid, euid;
	uid = getuid();
	euid = geteuid();
	flog("%s (%d) simple-shell topic: %s, num: %d, uid: %d, euid: %d, "
	       "ppid: %d\n",
			hostname, pid, topic, num++, uid, euid, ppid);
	if (args) {
		flog("%p %p\n", args->in, args->out);
		rc = flux_plugin_arg_get(args, FLUX_PLUGIN_ARG_OUT, &str);
		if (rc) {
			flog("arg error: %s\n", flux_plugin_arg_strerror(args));
		}
		flog("args: %s\n", str);
	} else {
		flog("args is NULL\n");
	}
	if (arg) {
		flog("arg: %s\n", (char*)arg);
	}

	flux_shell_t *shell = flux_plugin_get_shell(p);
	// flux_t *flux = flux_shell_get_flux(shell);
	char *json_str = NULL;
	rc = flux_shell_get_jobspec_info(shell, &json_str);
	if (!rc) {
		flog("jobspec_info: %s\n", json_str);
	}

	free(json_str);
	json_str = NULL;

	rc = flux_shell_get_info(shell, &json_str);
	if (!rc) {
		flog("shell_info: %s\n", json_str);
	}
	free(json_str);
	json_str = NULL;

	return 0;
}

static const struct flux_plugin_handler handlers[] = {
	{"shell.init", cb, "one"},
	{"shell.post-init", cb, "two"},
	{"task.init", cb, "three"},
	{"task.exec", cb, "four"},
	{"task.fork", cb, "five"},
	{"shell.start", cb, "six"},
	{"task.exit", cb, "seven"},
	{"shell.exit", cb, "eight"},
	{0},
};

int flux_plugin_init(flux_plugin_t *p)
{
	gethostname(hostname, sizeof(hostname));
	return (flux_plugin_register(p, FLUX_SHELL_PLUGIN_NAME, handlers) < 0)?-1:0;
}
