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

#include "ldmsd.h"
#include "ldmsd_jobmgr.h"
#include "ldmsd_plug_api.h"

#include "ovis_json/ovis_json.h"

enum jobmgr_flux_metric_e {

	/* top shell */
	JOBMGR_FLUX_METRIC_JOB_ID = 0x1,
	JOBMGR_FLUX_METRIC_USER,
	JOBMGR_FLUX_METRIC_JOB_NAME,
	JOBMGR_FLUX_METRIC_JOB_UID,
	JOBMGR_FLUX_METRIC_JOB_GID,
	JOBMGR_FLUX_METRIC_JOB_START,
	JOBMGR_FLUX_METRIC_JOB_END,
	JOBMGR_FLUX_METRIC_NODE_COUNT,

	/* sub shell */
	JOBMGR_FLUX_METRIC_STEP_ID = 0x101,
	JOBMGR_FLUX_METRIC_STEP_START,
	JOBMGR_FLUX_METRIC_STEP_END,
	JOBMGR_FLUX_METRIC_TOTAL_TASKS,
	JOBMGR_FLUX_METRIC_LOCAL_TASKS,

	/* tasks .. */
	JOBMGR_FLUX_METRIC_TASK_ID = 0x201,
	JOBMGR_FLUX_METRIC_TASK_PID,
	JOBMGR_FLUX_METRIC_TASK_RANK,
	JOBMGR_FLUX_METRIC_TASK_START,
	JOBMGR_FLUX_METRIC_TASK_END,
	JOBMGR_FLUX_METRIC_TASK_EXIT_STATUS,

};

struct jobmgr_flux_mdesc_s {
	const char *name;
	enum ldms_value_type v_type;
	const char *unit;
	int len;
	enum jobmgr_flux_metric_e m_type;
};

struct jobmgr_flux_mdesc_s jobmgr_flux_mdesc_tbl[] = {
	{ "job_id",   LDMS_V_CHAR_ARRAY, NULL,
		      LDMSD_JOBMGR_JOB_ID_LEN, JOBMGR_FLUX_METRIC_JOB_ID },

	{ "user",     LDMS_V_CHAR_ARRAY, NULL,
		      LDMSD_JOBMGR_USER_LEN, JOBMGR_FLUX_METRIC_USER },

	{ "job_name", LDMS_V_CHAR_ARRAY, NULL,
		      LDMSD_JOBMGR_JOB_NAME_LEN, JOBMGR_FLUX_METRIC_USER },

	{ "job_uid",    LDMS_V_U32,       NULL, 1, JOBMGR_FLUX_METRIC_JOB_UID    },
	{ "job_gid",    LDMS_V_U32,       NULL, 1, JOBMGR_FLUX_METRIC_JOB_GID    },
	{ "job_start",  LDMS_V_TIMESTAMP, NULL, 1, JOBMGR_FLUX_METRIC_JOB_START  },
	{ "job_end",    LDMS_V_TIMESTAMP, NULL, 1, JOBMGR_FLUX_METRIC_JOB_END    },
	{ "node_count", LDMS_V_U32,       NULL, 1, JOBMGR_FLUX_METRIC_NODE_COUNT },

	{ "step_id", LDMS_V_CHAR_ARRAY, NULL,
		     LDMSD_JOBMGR_STEP_ID_LEN, JOBMGR_FLUX_METRIC_STEP_ID },
	{ "step_start",       LDMS_V_TIMESTAMP,  NULL, 1, JOBMGR_FLUX_METRIC_STEP_START },
	{ "step_end",         LDMS_V_TIMESTAMP,  NULL, 1, JOBMGR_FLUX_METRIC_STEP_END },

	{ "total_tasks", LDMS_V_U32, NULL, 1, JOBMGR_FLUX_METRIC_TOTAL_TASKS },
	{ "local_tasks", LDMS_V_U32, NULL, 1, JOBMGR_FLUX_METRIC_LOCAL_TASKS },

	{ "task_id", LDMS_V_CHAR_ARRAY, NULL,
		     LDMSD_JOBMGR_TASK_ID_LEN, JOBMGR_FLUX_METRIC_TASK_ID },

	{ "task_pid",         LDMS_V_U64,        NULL, 1, JOBMGR_FLUX_METRIC_TASK_PID },
	{ "task_rank",        LDMS_V_U32,        NULL, 1, JOBMGR_FLUX_METRIC_TASK_RANK },
	{ "task_start",       LDMS_V_TIMESTAMP,  NULL, 1, JOBMGR_FLUX_METRIC_TASK_START },
	{ "task_end",         LDMS_V_TIMESTAMP,  NULL, 1, JOBMGR_FLUX_METRIC_TASK_END },
	{ "task_exit_status", LDMS_V_S32,        NULL, 1, JOBMGR_FLUX_METRIC_TASK_EXIT_STATUS },
};

/* for qsort */
static int __mdesc_cmp(const void *_a, const void *_b)
{
	const struct jobmgr_flux_mdesc_s *a = _a;
	const struct jobmgr_flux_mdesc_s *b = _b;
	return strcmp(a->name, b->name);
}

/* for bsearch */
static int __mdesc_key_cmp(const void *_k, const void *_e)
{
	const char *a = _k;
	const struct jobmgr_flux_mdesc_s *e = _e;
	return strcmp(a, e->name);
}

static const struct jobmgr_flux_mdesc_s *
jobmgr_flux_mdesc_find(const char *name)
{
	const struct jobmgr_flux_mdesc_s *ent;
	ent = bsearch(name, jobmgr_flux_mdesc_tbl,
		sizeof(jobmgr_flux_mdesc_tbl)/sizeof(jobmgr_flux_mdesc_tbl[0]),
		sizeof(jobmgr_flux_mdesc_tbl[0]),
		__mdesc_key_cmp);
	return ent;
}

int u64_node_cmp(void *a, const void *b)
{
	uint64_t l = *(uint64_t*)a;
	uint64_t r = *(uint64_t*)b;
	if (l < r)
		return -1;
	if (l > r)
		return 1;
	return 0;
}

int str_node_cmp(void *a, const void *b)
{
	return strcmp(a, b);
}

typedef enum jobmgr_flux_state_e {
	JOBMGR_FLUX_STOPPED,
	JOBMGR_FLUX_STOPPING,
	JOBMGR_FLUX_STARTING,
	JOBMGR_FLUX_STARTED,
	JOBMGR_FLUX_LAST,
} jobmgr_flux_state_t;

static const char *jobmgr_flux_state_text_tbl[] = {
	[JOBMGR_FLUX_STOPPED]  = "JOBMGR_FLUX_STOPPED",
	[JOBMGR_FLUX_STOPPING] = "JOBMGR_FLUX_STOPPING",
	[JOBMGR_FLUX_STARTING] = "JOBMGR_FLUX_STARTING",
	[JOBMGR_FLUX_STARTED]  = "JOBMGR_FLUX_STARTED",
};

static const char *jobmgr_flux_state_text(enum jobmgr_flux_state_e st)
{
	if (JOBMGR_FLUX_LAST <= st)
		return "UNKNOWN";
	return jobmgr_flux_state_text_tbl[st];
}

struct jobmgr_flux {
	ldmsd_plug_handle_t plug;
	ldms_msg_client_t mc;
	pthread_mutex_t mutex;
	struct rbt rbt;
	char *ch_name;
	enum jobmgr_flux_state_e state;
};
typedef struct jobmgr_flux *jobmgr_flux_t;

/* ID_LEN is max of JOB, STEP, TASK IDs */
#define ID_LEN \
	(LDMSD_JOBMGR_JOB_ID_LEN > LDMSD_JOBMGR_STEP_ID_LEN) ? \
	( (LDMSD_JOBMGR_JOB_ID_LEN > LDMSD_JOBMGR_TASK_ID_LEN) ? \
	    (LDMSD_JOBMGR_JOB_ID_LEN): \
	    (LDMSD_JOBMGR_TASK_ID_LEN) \
	): \
	( (LDMSD_JOBMGR_STEP_ID_LEN > LDMSD_JOBMGR_TASK_ID_LEN) ? \
	    (LDMSD_JOBMGR_STEP_ID_LEN): \
	    (LDMSD_JOBMGR_TASK_ID_LEN) \
	)

struct shell_task_data {
	/* holding shell or task data */
	struct rbn rbn; /* key is `id` */
	int level; /* for now 0 shell, 1 subshell, 2 task */
	enum {
		SHELL_DATA,
		TASK_DATA,
	} type;

	struct shell_task_data *parent;

	uid_t uid;
	gid_t gid;

	char id[ID_LEN];

	int rank;

	char user[LDMSD_JOBMGR_USER_LEN];
	char name[LDMSD_JOBMGR_JOB_NAME_LEN];

	int node_count;

	int total_tasks;
	int local_tasks;

	struct ldms_timestamp start;
	struct ldms_timestamp end;

	pid_t task_pid;
	int task_exit_status;

	struct rbt rbt; /* children */
};

struct query_ctxt {
	int n;
	const struct ldmsd_jobmgr_query_s *q; /* for convenient */
	int level; /* 0 for job, 1 for step, 2 for task */
	const struct jobmgr_flux_mdesc_s *mdesc[OVIS_FLEX];
};

static ldmsd_jobmgr_qres_t make_qres(struct query_ctxt *qc, struct shell_task_data *d);

static const char *usage_str =
"config inst=NAME message_channel=CH_NAME\n"
;

static const char *usage(ldmsd_plug_handle_t p)
{
	return usage_str;
}

/* return 0 if transition failed */
static inline int jobmgr_flux_transition(jobmgr_flux_t jf,
		enum jobmgr_flux_state_e from,
		enum jobmgr_flux_state_e to,
		enum jobmgr_flux_state_e *prev)
{
	int success;
	success = __atomic_compare_exchange_n(&jf->state, &from, to, 0,
					__ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
	if (prev)
		*prev = from;
	return success;
}

#define LOG(p, LVL, FMT, ...) ovis_log(ldmsd_plug_log_get(p), LVL, FMT, ## __VA_ARGS__ )
#define LOG_CRITICAL(p, FMT, ...) LOG(p, OVIS_LCRITICAL, FMT, ## __VA_ARGS__)
#define LOG_ERROR(p, FMT, ...) LOG(p, OVIS_LERROR, FMT, ## __VA_ARGS__)
#define LOG_INFO(p, FMT, ...) LOG(p, OVIS_LINFO, FMT, ## __VA_ARGS__)
#define LOG_DEBUG(p, FMT, ...) LOG(p, OVIS_LDEBUG, FMT, ## __VA_ARGS__)

static int config(ldmsd_plug_handle_t p, struct attr_value_list *kwl, struct attr_value_list *avl)
{
	jobmgr_flux_t jf = ldmsd_plug_ctxt_get(p);
	char *val;
	val = av_value(avl, "message_channel");
	if (!val) {
		if (errno == ENOMEM)
			goto enomem;
		val = strdup("flux"); /* default */
		if (!val) {
			goto enomem;
		}
	}
	jf->ch_name = strdup(val);

	return 0;
 enomem:
	LOG_ERROR(p, "Not enough memory.\n");
	return ENOMEM;
}

struct info_array {
	uid_t uid;
	gid_t gid;
	int n;
	const char *ids[];
};

struct info_array *info_array_from_json(json_entity_t id)
{
	if (json_entity_type(id) != JSON_LIST_VALUE)
		goto einval;
	json_entity_t item;
	struct info_array *a;
	int n = json_list_len(id);
	if (!n)
		goto einval;
	a = calloc(1, sizeof(*a) + n*sizeof(a->ids[0]));
	if (!a)
		return NULL;
	a->n = 0;
	for (item = json_item_first(id); item; item = json_item_next(item)) {
		a->ids[a->n++] = json_value_cstr(item);
	}

	return a;

 einval:
	errno = EINVAL;
	return NULL;
}

int id_to_str(json_entity_t id, char *buf, size_t bufsz)
{
	if (json_entity_type(id) != JSON_LIST_VALUE)
		return EINVAL;
	json_entity_t item;
	off_t off = 0;
	const char *sep = "";
	for (item = json_item_first(id); item; item = json_item_next(item)) {
		off += snprintf(buf + off, bufsz - off,
				"%s%s", sep, json_value_cstr(item));
		if (off >= bufsz) {
			return ENOBUFS;
		}
	}
	return 0;
}

struct shell_task_data *
get_shell_data(jobmgr_flux_t jf, struct info_array *a)
{
	struct shell_task_data *d = NULL;
	struct shell_task_data *parent = NULL;
	struct rbt *parent_rbt;
	struct rbn *rbn;
	int i;
	char key[ID_LEN];
	off_t off = 0;
	size_t sz = sizeof(key);
	const char *sep = "";
	pthread_mutex_lock(&jf->mutex);

	i = 0;
	parent_rbt = &jf->rbt;
 loop:
	if (i == a->n)
		goto out;
	off += snprintf(key + off, sz - off, "%s%s", sep, a->ids[i]);
	if (off >= sz) {
		errno = ENOBUFS;
		goto err;
	}
	rbn = rbt_find(parent_rbt, key);
	if (!rbn) {
		d = calloc(1, sizeof(*d));
		if (!d)
			goto err;
		d->type = SHELL_DATA;
		snprintf(d->id, sizeof(d->id), "%s", key);
		rbn_init(&d->rbn, d->id);
		rbt_ins(parent_rbt, &d->rbn);
		d->uid = a->uid;
		d->gid = a->gid;
		d->parent = parent;
		d->level = i;
		rbt_init(&d->rbt, str_node_cmp);
	} else {
		d = container_of(rbn, struct shell_task_data, rbn);
	}

	/* step into next level */
	i++;
	parent = d;
	parent_rbt = &parent->rbt;

	goto loop;

 out:
	pthread_mutex_unlock(&jf->mutex);
	return d;

 err:
	pthread_mutex_unlock(&jf->mutex);
	return NULL;
}

struct shell_task_data *
get_task_data(jobmgr_flux_t jf, struct shell_task_data *sd, int task_rank)
{
	struct shell_task_data *td = NULL;
	char key[ID_LEN];
	int len;
	struct rbn *rbn;
	len = snprintf(key, sizeof(key), "%s/%d", sd->id, task_rank);
	if (len >= sizeof(key)) {
		errno = EINVAL;
		return NULL;
	}
	pthread_mutex_lock(&jf->mutex);
	rbn = rbt_find(&sd->rbt, key);
	if (!rbn) {
		td = calloc(1, sizeof(*td));
		if (!td)
			goto out;
		snprintf(td->id, sizeof(td->id), "%s", key);
		rbn_init(&td->rbn, td->id);
		rbt_ins(&sd->rbt, &td->rbn);
		td->uid = sd->uid;
		td->gid = sd->gid;
		td->parent = sd;
		td->level = sd->level + 1;
		td->rank = task_rank;
		td->type = TASK_DATA;
	} else {
		td = container_of(rbn, struct shell_task_data, rbn);
	}
 out:
	pthread_mutex_unlock(&jf->mutex);
	return td;
}

static void handle_shell_common(ldmsd_plug_handle_t p, jobmgr_flux_t jf,
			      json_entity_t root, struct shell_task_data *d)
{
	json_entity_t val, jobspec, rank_info, shell_info;

	/* user */
	val = json_value_find(root, "user");
	if (val) {
		snprintf(d->user, sizeof(d->user), "%s", json_value_cstr(val));
	}

	/* data from jobspec */
	jobspec = json_value_find(root, "jobspec_info");
	if (jobspec) {
		/* total_tasks */
		val = json_value_find(jobspec, "ntasks");
		if (val) {
			d->total_tasks = json_value_int(val);
		}

		/* nnodes */
		val = json_value_find(jobspec, "ntasks");
		if (val) {
			d->node_count = json_value_int(val);
		}
	}

	/* data from rank_info */
	rank_info = json_value_find(root, "rank_info");
	if (rank_info) {
		/* local_tasks */
		val = json_value_find(rank_info, "ntasks");
		if (val) {
			d->local_tasks = json_value_int(val);
		}
	}

	/* data from shell_info */
	shell_info = json_value_find(root, "shell_info");
	if (shell_info) {
		/* rank */
		val = json_value_find(shell_info, "rank");
		if (val) {
			d->rank = json_value_int(val);
		}
	}
}


static void handle_shell_init(ldmsd_plug_handle_t p, jobmgr_flux_t jf,
			      json_entity_t root, struct shell_task_data *d)
{
	json_entity_t val;

	handle_shell_common(p, jf, root, d);

	/* ts */
	val = json_value_find(root, "ts");
	if (val) {
		d->start.sec = json_value_int(val);
	}

	struct ldmsd_jobmgr_event ev = {
		.type   = d->level?LDMSD_JOBMGR_STEP_START:LDMSD_JOBMGR_JOB_START,
		.mgr    = jf->plug,
	};

	ldmsd_jobmgr_event_post(&ev, d);
}

static void handle_shell_exit(ldmsd_plug_handle_t p, jobmgr_flux_t jf,
			      json_entity_t root, struct shell_task_data *d)
{
	json_entity_t val;

	handle_shell_common(p, jf, root, d);

	/* ts */
	val = json_value_find(root, "ts");
	if (val) {
		d->end.sec = json_value_int(val);
	}

	struct ldmsd_jobmgr_event ev = {
		.type   = d->level?LDMSD_JOBMGR_STEP_END:LDMSD_JOBMGR_JOB_END,
		.mgr    = jf->plug,
	};

	ldmsd_jobmgr_event_post(&ev, d);
}

static int handle_task_common(ldmsd_plug_handle_t p, jobmgr_flux_t jf,
			      json_entity_t root,
			      struct shell_task_data *sd,
			      struct shell_task_data **td_out)
{
	json_entity_t task_info, val;
	int task_rank;
	struct shell_task_data *td;

	task_info = json_value_find(root, "task_info");
	if (!task_info) {
		return EINVAL;
	}
	val = json_value_find(task_info, "rank");
	if (!val) {
		return EINVAL;
	}
	task_rank = json_value_int(val);
	td = get_task_data(jf, sd, task_rank);
	if (!td)
		return errno;
	*td_out = td;

	val = json_value_find(task_info, "pid");
	if (val) {
		td->task_pid = json_value_int(val);
	}

	val = json_value_find(task_info, "exitcode");
	if (val) {
		td->task_exit_status = json_value_int(val);
	}

	return 0;
}

static void handle_task_fork(ldmsd_plug_handle_t p, jobmgr_flux_t jf,
			      json_entity_t root, struct shell_task_data *sd)
{
	int rc;
	json_entity_t val;
	struct shell_task_data *td = NULL;

	rc = handle_task_common(p, jf, root, sd, &td);
	if (rc)
		return;

	val = json_value_find(root, "ts");
	if (val) {
		td->start.sec = json_value_int(val);
	}

	struct ldmsd_jobmgr_event ev = {
		.type        = LDMSD_JOBMGR_TASK_START,
		.mgr         = jf->plug,
	};
	ldmsd_jobmgr_event_post(&ev, td);
}

static void handle_task_exit(ldmsd_plug_handle_t p, jobmgr_flux_t jf,
			      json_entity_t root, struct shell_task_data *sd)
{
	int rc;
	json_entity_t val;
	struct shell_task_data *td = NULL;

	rc = handle_task_common(p, jf, root, sd, &td);
	if (rc)
		return;

	val = json_value_find(root, "ts");
	if (val) {
		td->end.sec = json_value_int(val);
	}

	struct ldmsd_jobmgr_event ev = {
		.type        = LDMSD_JOBMGR_TASK_END,
		.mgr         = jf->plug,
	};
	ldmsd_jobmgr_event_post(&ev, td);
}

static void handle_msg_recv(ldmsd_plug_handle_t p, jobmgr_flux_t jf, ldms_msg_event_t ev)
{
	json_entity_t root = ev->recv.json;
	json_entity_t val;
	struct info_array *a = NULL;

	if (ev->recv.type != LDMS_MSG_JSON) {
		LOG_DEBUG(p, "Unexpected stream type data...ignoring\n");
		LOG_DEBUG(p, "%s\n", ev->recv.data);
		return;
	}

	val = json_value_find(root, "shell_id_f58");
	if (!val) {
		LOG_ERROR(p, "Missing 'shell_id_f58' attribute\n");
		return;
	}
	a = info_array_from_json(val);
	if (!a) {
		LOG_ERROR(p, "info_array_from_json() error: %d\n", errno);
		return;
	}

	val = json_value_find(root, "uid");
	if (!val) {
		LOG_ERROR(p, "Missing 'uid' attribute\n");
		goto cleanup;
	}
	a->uid = json_value_int(val);

	val = json_value_find(root, "gid");
	if (!val) {
		LOG_ERROR(p, "Missing 'gid' attribute\n");
		goto cleanup;
	}
	a->gid = json_value_int(val);

	struct shell_task_data *sd;
	sd = get_shell_data(jf, a);
	if (!sd) {
		LOG_ERROR(p, "get_shell_data() error: %d\n", errno);
		goto cleanup;
	}

	/* now fill the data according to event */
	val = json_value_find(root, "event");
	if (!val) {
		LOG_ERROR(p, "Missing 'event' attribute\n");
		goto cleanup;
	}
	const char *event = json_value_cstr(val);
	if (0 == strcmp(event, "shell.init")) {
		handle_shell_init(p, jf, root, sd);
	} else if (0 == strcmp(event, "shell.exit")) {
		handle_shell_exit(p, jf, root, sd);
	} else if (0 == strcmp(event, "task.fork")) {
		handle_task_fork(p, jf, root, sd);
	} else if (0 == strcmp(event, "task.exit")) {
		handle_task_exit(p, jf, root, sd);
	}

 cleanup:
	free(a);
}

static int msg_cb(ldms_msg_event_t ev, void *cb_arg)
{
	ldmsd_plug_handle_t p = cb_arg;
	jobmgr_flux_t jf = ldmsd_plug_ctxt_get(p);
	int succ;

	switch (ev->type) {
	case LDMS_MSG_EVENT_RECV:
		handle_msg_recv(p, jf, ev);
		break;
	case LDMS_MSG_EVENT_CLIENT_CLOSE:
		assert(ev->close.client == jf->mc);
		jf->mc = NULL;
		succ = jobmgr_flux_transition(jf, JOBMGR_FLUX_STOPPING,
					       JOBMGR_FLUX_STOPPED, NULL);
		if (!succ) {
			assert(0 == "UNEXPECTED STATE");
		}
		ldmsd_jobmgr_put(p, "msg_subscribe");
		break;
	default:
		/* no-op */ ;
	}

	return 0;
}

static int start(ldmsd_plug_handle_t p)
{
	jobmgr_flux_t jf = ldmsd_plug_ctxt_get(p);
	enum jobmgr_flux_state_e st;
	int succ, rc = 0;

	/* transition to STARTING */
	if (0 == jobmgr_flux_transition(jf, JOBMGR_FLUX_STOPPED,
					     JOBMGR_FLUX_STARTING, &st)) {
		/* failed transition */
		LOG_ERROR(p, "Cannot start jobmgr '%s', state: %s\n",
				ldmsd_plug_name_get(p),
				jobmgr_flux_state_text(st));
		return EBUSY;
	}

	if (!jf->ch_name) {
		LOG_ERROR(p, "jobmgr '%s' is not configured.\n",
				ldmsd_plug_name_get(p));
		rc = EINVAL;
		goto err;
	}

	assert(jf->mc == NULL);

	ldmsd_jobmgr_get(p, "msg_subscribe");

	jf->mc = ldms_msg_subscribe(jf->ch_name, 0, msg_cb,
				    p, "jobmgr_flux");
	if (!jf->mc) {
		ldmsd_jobmgr_put(p, "msg_subscribe");
		LOG_ERROR(p, "msg subscription failed, errno: %d\n", errno);
		rc = errno;
		goto err;
	}

	succ = jobmgr_flux_transition(jf, JOBMGR_FLUX_STARTING, JOBMGR_FLUX_STARTED, &st);
	if (!succ) {
		assert(0 == "BAD STATE");
	}

	return 0;
 err:
	succ = jobmgr_flux_transition(jf, JOBMGR_FLUX_STARTING, JOBMGR_FLUX_STOPPED, &st);
	if (!succ) {
		assert(0 == "BAD STATE");
	}
	return rc;
}

static int stop(ldmsd_plug_handle_t p)
{
	jobmgr_flux_t jf = ldmsd_plug_ctxt_get(p);
	enum jobmgr_flux_state_e st;

	if (0 == jobmgr_flux_transition(jf, JOBMGR_FLUX_STARTED,
					     JOBMGR_FLUX_STOPPING, &st)) {
		/* failed transition */
		LOG_ERROR(p, "Cannot stop jobmgr '%s', state: %s\n",
				ldmsd_plug_name_get(p),
				jobmgr_flux_state_text(st));
		return EBUSY;
	}

	assert(jf->mc);
	ldms_msg_client_close(jf->mc);
	/* Transition from STOPPING to STOPPED when CLOSE event is delivered */

	return 0;
}

static int on_query_new(ldmsd_plug_handle_t p,
			const struct ldmsd_jobmgr_query_s *q,
			void **q_ctxt_out)
{
	int i;
	int mx = 0;
	struct query_ctxt *ctxt;
	ctxt = calloc(1, sizeof(*ctxt) + q->n_metrics*sizeof(q->mdesc[0]));
	if (!ctxt)
		return ENOMEM;
	ctxt->n = q->n_metrics;
	ctxt->q = q;
	for (i = 0; i < q->n_metrics; i++) {
		ctxt->mdesc[i] = jobmgr_flux_mdesc_find(q->mdesc[i].name);
		/* it is OK if we may not have all of the metrics */
		if (!ctxt->mdesc[i])
			continue;
		if (ctxt->mdesc[i]->m_type > mx)
			mx = ctxt->mdesc[i]->m_type;
	}
	if (mx >= 0x200) {
		ctxt->level = 2;
	} else if (mx >= 0x100) {
		ctxt->level = 1;
	} else {
		ctxt->level = 0;
	}
	*q_ctxt_out = ctxt;
	return 0;
}

static void on_query_free(ldmsd_plug_handle_t p,
			const struct ldmsd_jobmgr_query_s *q, void *q_ctxt)
{
	struct query_ctxt *ctxt = q_ctxt;
	free(ctxt);
}

void mv_assign(const struct jobmgr_flux_mdesc_s *mdesc,
	       ldms_mval_t mv,
	       struct shell_task_data *l0,
	       struct shell_task_data *l1,
	       struct shell_task_data *l2)
{
	switch (mdesc->m_type) {
	case JOBMGR_FLUX_METRIC_JOB_ID:
		snprintf(mv->a_char, LDMSD_JOBMGR_JOB_ID_LEN, "%s", l0->id);
		break;
	case JOBMGR_FLUX_METRIC_USER:
		snprintf(mv->a_char, LDMSD_JOBMGR_USER_LEN, "%s", l0->user);
		break;
	case JOBMGR_FLUX_METRIC_JOB_NAME:
		snprintf(mv->a_char, LDMSD_JOBMGR_JOB_NAME_LEN, "%s", l0->name);
		break;
	case JOBMGR_FLUX_METRIC_JOB_UID:
		mv->v_u32 = l0->uid;
		break;
	case JOBMGR_FLUX_METRIC_JOB_GID:
		mv->v_u32 = l0->gid;
		break;
	case JOBMGR_FLUX_METRIC_JOB_START:
		mv->v_ts = l0->start;
		break;
	case JOBMGR_FLUX_METRIC_JOB_END:
		mv->v_ts = l0->end;
		break;
	case JOBMGR_FLUX_METRIC_NODE_COUNT:
		mv->v_u32 = l0->node_count;
		break;

	case JOBMGR_FLUX_METRIC_STEP_ID:
		if (l1)
			snprintf(mv->a_char, LDMSD_JOBMGR_STEP_ID_LEN,
				 "%s", l1->id);
		break;
	case JOBMGR_FLUX_METRIC_STEP_START:
		if (l1)
			mv->v_ts = l1->start;
		break;
	case JOBMGR_FLUX_METRIC_STEP_END:
		if (l1)
			mv->v_ts = l1->end;
		break;
	case JOBMGR_FLUX_METRIC_TOTAL_TASKS:
		if (l1)
			mv->v_u32 = l1->total_tasks;
		break;
	case JOBMGR_FLUX_METRIC_LOCAL_TASKS:
		if (l1)
			mv->v_u32 = l1->local_tasks;
		break;

	case JOBMGR_FLUX_METRIC_TASK_ID:
		if (l2)
			snprintf(mv->a_char, LDMSD_JOBMGR_TASK_ID_LEN, "%s", l2->id);
		break;
	case JOBMGR_FLUX_METRIC_TASK_PID:
		if (l2)
			mv->v_u64 = l2->task_pid;
		break;
	case JOBMGR_FLUX_METRIC_TASK_RANK:
		if (l2)
			mv->v_u32 = l2->rank;
		break;
	case JOBMGR_FLUX_METRIC_TASK_START:
		if (l2)
			mv->v_ts = l2->start;
		break;
	case JOBMGR_FLUX_METRIC_TASK_END:
		if (l2)
			mv->v_ts = l2->end;
		break;
	case JOBMGR_FLUX_METRIC_TASK_EXIT_STATUS:
		if (l2)
			mv->v_s32 = l2->task_exit_status;
		break;
	}
}

static ldmsd_jobmgr_qres_t
make_qres(struct query_ctxt *qc, struct shell_task_data *d)
{
	int i;
	ldms_mval_t mv;
	ldmsd_jobmgr_qres_t qres;

	struct shell_task_data *l[3] = {}, *p;
	p = d;
	while (p) {
		l[p->level] = p;
		p = p->parent;
	}

	qres = calloc(1, sizeof(*qres) + qc->q->qres_size);
	if (!qres)
		goto out;
	for (i = 0; i < qc->n; i++) {
		if (!qc->mdesc[i])
			continue; /* we don't have this metric */
		mv = ldmsd_jobmgr_qres_mval(qc->q, qres, i);
		mv_assign(qc->mdesc[i], mv, l[0], l[1], l[2]);
	}
 out:
	return qres;
}

/*
 * jf->mutex is locked
 */
static int qwalk(jobmgr_flux_t jf, struct rbt *rbt,
		 struct query_ctxt *qc,
		 ldmsd_jobmgr_qres_list_t list)
{
	int rc;
	struct rbn *rbn;
	struct shell_task_data *d;
	ldmsd_jobmgr_qres_t qres;

	for (rbn = rbt_min(rbt); rbn; rbn = rbn_succ(rbn)) {
		d = container_of(rbn, struct shell_task_data, rbn);
		if (d->level < qc->level) {
			rc = qwalk(jf, &d->rbt, qc, list);
			if (rc)
				return rc;
		} else {
			qres = make_qres(qc, d);
			if (qres) {
				TAILQ_INSERT_TAIL(&list->tailq, qres, entry);
				list->len++;
			} else {
				return errno;
			}
		}
	}
	return 0;
}

static int job_ls(jobmgr_flux_t jf, struct query_ctxt *qc,
		  ldmsd_jobmgr_qres_list_t list)
{
	/* TODO */
	int rc;
	pthread_mutex_lock(&jf->mutex);
	rc = qwalk(jf, &jf->rbt, qc, list);
	pthread_mutex_unlock(&jf->mutex);
	return rc;
}

static ldmsd_jobmgr_qres_list_t on_query_ls(ldmsd_plug_handle_t p,
			const struct ldmsd_jobmgr_query_s *q, void *q_ctxt)
{
	jobmgr_flux_t jf = ldmsd_plug_ctxt_get(p);
	struct query_ctxt *ctxt = q_ctxt;
	ldmsd_jobmgr_qres_list_t list;
	list = calloc(1, sizeof(*list));
	if (!list)
		return NULL;
	TAILQ_INIT(&list->tailq);
	job_ls(jf, ctxt, list);
	return list;
}

static int make_event_qres(ldmsd_plug_handle_t p, struct ldmsd_jobmgr_event *ev,
			   void *_q_ctxt, void *_ev_ctxt)
{
	struct query_ctxt *qc = _q_ctxt;
	struct shell_task_data *d = _ev_ctxt;
	ev->res = make_qres(qc, d);
	if (ev->res)
		return 0;
	return errno;
}

void event_done(ldmsd_plug_handle_t p,
		struct ldmsd_jobmgr_event *ev,
		void *ev_ctxt)
{
	/* no-op */
	/* ev_ctxt is the context we gave to event_post.
	 * In our case, ev_ctxt is a node in the shell-task tree. */
}

static int constructor(ldmsd_plug_handle_t p)
{
	jobmgr_flux_t jf;

	jf = calloc(1, sizeof(*jf));
	if (!jf)
		return ENOMEM;
	pthread_mutex_init(&jf->mutex, NULL);
	rbt_init(&jf->rbt, str_node_cmp);
	jf->state = JOBMGR_FLUX_STOPPED;
	ldmsd_plug_ctxt_set(p, jf);
	jf->plug = p;
	return 0;
}

static void destructor(ldmsd_plug_handle_t p)
{
	jobmgr_flux_t jf = ldmsd_plug_ctxt_get(p);
	if (!jf)
		return;
	free(jf->ch_name);
	assert(jf->mc == 0);
}

struct ldmsd_jobmgr ldmsd_plugin_interface = {
	.base = {
		.type = LDMSD_PLUGIN_JOBMGR,
		.config = config,
		.flags = LDMSD_PLUGIN_MULTI_INSTANCE,
		.usage = usage,
		.constructor = constructor,
		.destructor = destructor,
	},
	.start = start,
	.stop  = stop,
	.on_query_new = on_query_new,
	.on_query_free = on_query_free,
	.on_query_ls = on_query_ls,
	.make_event_qres = make_event_qres,
	.event_done = event_done,
};

__attribute__((constructor))
static void __init__()
{
	/* library init */
	qsort(jobmgr_flux_mdesc_tbl,
	      sizeof(jobmgr_flux_mdesc_tbl)/sizeof(jobmgr_flux_mdesc_tbl[0]),
	      sizeof(jobmgr_flux_mdesc_tbl[0]),
	      __mdesc_cmp);
}
