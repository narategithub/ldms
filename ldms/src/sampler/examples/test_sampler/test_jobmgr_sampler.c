/* -*- c-basic-offset: 8 -*-
 * Copyright (c) 2025 National Technology & Engineering Solutions
 * of Sandia, LLC (NTESS). Under the terms of Contract DE-NA0003525 with
 * NTESS, the U.S. Government retains certain rights in this software.
 * Copyright (c) 2025,2025 Open Grid Computing, Inc. All rights reserved.
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
#define _GNU_SOURCE

#include "ovis_ref/ref.h"

#include "ldmsd.h"
#include "ldmsd_jobmgr.h"
#include "ldmsd_plug_api.h"

typedef struct test_jobmgr_samp_s {
	struct ref_s ref;
	ldmsd_jobmgr_event_client_t c;
	FILE *f;
	ldmsd_jobmgr_query_t q;
} *test_jobmgr_samp_t;

const char *_usage = "\
This is a test sampler for jobmgr. It subscribes for jobmgr events and print\n\
them to the given file.\n\
\n\
config name=INST file=PATH\n\
\n\
";

static const char *usage(ldmsd_plug_handle_t handle)
{
	return "config name=INST file=PATH";
}

void print_jobset(char *buf, size_t bufsz, const struct ldmsd_jobmgr_event *ev)
{
	ldms_mval_t job_id = ldmsd_jobset_mval(ev->jobset, JOB_ID);
	ldms_mval_t job_uid = ldmsd_jobset_mval(ev->jobset, JOB_UID);
	ldms_mval_t job_gid = ldmsd_jobset_mval(ev->jobset, JOB_GID);
	ldms_mval_t job_start = ldmsd_jobset_mval(ev->jobset, JOB_START);
	ldms_mval_t job_end = ldmsd_jobset_mval(ev->jobset, JOB_END);
	ldms_mval_t node_count = ldmsd_jobset_mval(ev->jobset, NODE_COUNT);
	ldms_mval_t total_tasks = ldmsd_jobset_mval(ev->jobset, TOTAL_TASKS);
	ldms_mval_t local_tasks = ldmsd_jobset_mval(ev->jobset, LOCAL_TASKS);

	snprintf(buf, bufsz,
			"{"
			  "\"job_id\":\"%s\""
			  ",\"uid\":%d"
			  ",\"gid\":%d"
			  ",\"job_start\":%u.%06u"
			  ",\"job_end\":%u.%06u"
			  ",\"node_count\":%u"
			  ",\"total_tasks\":%u"
			  ",\"local_tasks\":%u"
			"}"
			, job_id->a_char
			, job_uid->v_u32
			, job_gid->v_u32
			, job_start->v_ts.sec, job_start->v_ts.usec
			, job_end->v_ts.sec, job_end->v_ts.usec
			, node_count->v_u32
			, total_tasks->v_u32
			, local_tasks->v_u32
			);
}

void print_task(char *buf, size_t bufsz, const struct ldmsd_jobmgr_event *ev)
{
	ldms_mval_t job_id = ldmsd_jobset_mval(ev->jobset, JOB_ID);
	ldms_mval_t task_id = ldmsd_task_rec_mval(ev->task_record, TASK_ID);
	ldms_mval_t task_pid = ldmsd_task_rec_mval(ev->task_record, TASK_PID);
	ldms_mval_t task_rank = ldmsd_task_rec_mval(ev->task_record, TASK_RANK);
	ldms_mval_t task_start = ldmsd_task_rec_mval(ev->task_record, TASK_START);
	ldms_mval_t task_end = ldmsd_task_rec_mval(ev->task_record, TASK_END);
	ldms_mval_t task_exit_status = ldmsd_task_rec_mval(ev->task_record, TASK_EXIT_STATUS);

	snprintf(buf, bufsz,
			"{"
		        "\"job_id\":\"%s\""
			",\"task_id\":\"%s\""
			",\"task_pid\":%lu"
			",\"task_rank\":%u"
			",\"task_start\":%u.%06u"
			",\"task_end\":%u.%06u"
			",\"task_exit_status\":%d"
			"}"
			, job_id->a_char
			, task_id->a_char
			, task_pid->v_u64
			, task_rank->v_u32
			, task_start->v_ts.sec, task_start->v_ts.usec
			, task_end->v_ts.sec, task_end->v_ts.usec
			, task_exit_status->v_s32
		);
}

void jobmgr_cb(ldmsd_jobmgr_event_client_t c,
		const struct ldmsd_jobmgr_event *ev, void *arg)
{
	test_jobmgr_samp_t j = arg;
	char jobset_buf[4096];
	char task_buf[4096];
	print_jobset(jobset_buf, sizeof(jobset_buf), ev);
	switch (ev->type) {
	case LDMSD_JOBMGR_JOB_START:
		fprintf(j->f, "job_start: %s\n", jobset_buf);
		break;
	case LDMSD_JOBMGR_TASK_START:
		print_task(task_buf, sizeof(task_buf), ev);
		fprintf(j->f, "task_start: %s\n", task_buf);
		break;
	case LDMSD_JOBMGR_TASK_END:
		print_task(task_buf, sizeof(task_buf), ev);
		fprintf(j->f, "task_end: %s\n", task_buf);
		break;
	case LDMSD_JOBMGR_JOB_END:
		fprintf(j->f, "job_end: %s\n", jobset_buf);
		break;
	case LDMSD_JOBMGR_SET_DELETE:
		fprintf(j->f, "jobset_delete: %s\n", jobset_buf);
		break;
	case LDMSD_JOBMGR_CLIENT_CLOSE:
		fprintf(j->f, "client_close\n");
		ref_put(&j->ref, "jobmgr_cb");
		break;
	case LDMSD_JOBMGR_STEP_START:
		fprintf(j->f, "step_start: %s\n", jobset_buf);
		break;
	case LDMSD_JOBMGR_STEP_END:
		fprintf(j->f, "step_end: %s\n", jobset_buf);
		break;
	}
}

#define LOG_ERROR(handle, fmt, ...)  \
		ovis_log(ldmsd_plug_log_get(handle), \
			 OVIS_LERROR, fmt, ## __VA_ARGS__ )

static int config(ldmsd_plug_handle_t handle,
		  struct attr_value_list *kwl, struct attr_value_list *avl)
{
	char *val;
	test_jobmgr_samp_t j = ldmsd_plug_ctxt_get(handle);
	if (j->c)
		return EEXIST;
	val = av_value(avl, "file");
	if (!val) {
		LOG_ERROR(handle, "'file' attribute is required.\n");
		return EINVAL;
	}
	j->f = fopen(val, "w");
	if (!j->f) {
		LOG_ERROR(handle, "cannot open file: %s\n", val);
		goto err;
	}
	setbuf(j->f, NULL);
	/*
	ref_get(&j->ref, "jobmgr_cb");
	j->c = ldmsd_jobmgr_event_subscribe(jobmgr_cb, j);
	if (!j->c) {
		ref_put(&j->ref, "jobmgr_cb");
		LOG_ERROR(handle, "jobmgr subscribe error: %d\n", errno);
		goto err;
	}
	*/
	const char *metrics[] = {
		"job_id", "step_id", "task_id", "task_pid",
		"job_start", "job_end", "step_start", "step_end",
		"task_start", "task_end"
	};
	j->q = ldmsd_jobmgr_query_new(sizeof(metrics)/sizeof(metrics[0]), metrics);
	return 0;

 err:
	free(val);
	if (j->f) {
		fclose(j->f);
		j->f = NULL;
	}
	return errno;
}

void __del(void *arg)
{
	test_jobmgr_samp_t j = arg;
	if (j->f)
		fclose(j->f);
	assert(j->c == NULL);
	free(j);
}

static int constructor(ldmsd_plug_handle_t handle)
{
	test_jobmgr_samp_t j = calloc(1, sizeof(*j));
	if (!j)
		return ENOMEM;
	ref_init(&j->ref, "constructor", __del, j);
	ldmsd_plug_ctxt_set(handle, j);
	return 0;
}

static void destructor(ldmsd_plug_handle_t handle)
{
	test_jobmgr_samp_t j = ldmsd_plug_ctxt_get(handle);
	if (!j)
		return;
	ref_put(&j->ref, "constructor");
}

static int sample(ldmsd_plug_handle_t handle)
{
	int i;
	test_jobmgr_samp_t j = ldmsd_plug_ctxt_get(handle);
	ldmsd_jobmgr_qres_list_t list;
	ldmsd_jobmgr_qres_t qres;
	ldms_mval_t mv;
	const char *sep = "";
	list = ldmsd_jobmgr_query_ls(j->q);
	if (!list)
		goto out;
	fprintf(j->f, "[\n");
	TAILQ_FOREACH(qres, &list->tailq, entry) {
		fprintf(j->f, " %s{\n", sep);
		for (i = 0; i < j->q->n_metrics; i++) {
			fprintf(j->f, "  %s\"%s\": ", i?",":"", j->q->mdesc[i].name);
			mv = ldmsd_jobmgr_qres_mval(j->q, qres, i);
			switch (j->q->mdesc[i].type) {
			case LDMS_V_S8:
				fprintf(j->f, "%hhd\n", mv->v_s8);
				break;
			case LDMS_V_U8:
				fprintf(j->f, "%hhu\n", mv->v_s8);
				break;
			case LDMS_V_S16:
				fprintf(j->f, "%hd\n", mv->v_s16);
				break;
			case LDMS_V_U16:
				fprintf(j->f, "%hu\n", mv->v_s16);
				break;
			case LDMS_V_S32:
				fprintf(j->f, "%d\n", mv->v_s32);
				break;
			case LDMS_V_U32:
				fprintf(j->f, "%u\n", mv->v_s32);
				break;
			case LDMS_V_S64:
				fprintf(j->f, "%ld\n", mv->v_s64);
				break;
			case LDMS_V_U64:
				fprintf(j->f, "%lu\n", mv->v_s64);
				break;
			case LDMS_V_CHAR_ARRAY:
				fprintf(j->f, "%s\n", mv->a_char);
				break;
			case LDMS_V_TIMESTAMP:
				fprintf(j->f, "%d.%06d\n", mv->v_ts.sec, mv->v_ts.usec);
				break;
			default:
				break;
			}
		}
		sep = ",";
	}
	fprintf(j->f, "]\n");
 out:
	return 0;
}

struct ldmsd_sampler ldmsd_plugin_interface = {
	.base = {
		.type = LDMSD_PLUGIN_SAMPLER,
		.flags = LDMSD_PLUGIN_MULTI_INSTANCE,
		.config = config,
		.usage = usage,
		.constructor = constructor,
		.destructor = destructor,
	},
	.sample = sample,
};
