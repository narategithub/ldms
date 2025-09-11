/* -*- c-basic-offset: 8 -*-
 * Copyright (c) 2025 National Technology & Engineering Solutions
 * of Sandia, LLC (NTESS). Under the terms of Contract DE-NA0003525 with
 * NTESS, the U.S. Government retains certain rights in this software.
 * Copyright (c) 2025 Open Grid Computing, Inc. All rights reserved.
 *
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


#define _GNU_SOURCE
#include "ldmsd_jobmgr.h"
#include "ovis_event/ovis_event.h"

extern ovis_log_t config_log;

static ovis_scheduler_t jobmgr_sched;
static pthread_t jobmgr_thr;

struct ldms_metric_template_s common_jobset_metrics[] = {

	{ "component_id", LDMS_MDESC_F_META, LDMS_V_CHAR_ARRAY, NULL,
		          LDMSD_JOBSET_COMPONENT_ID_LEN,   NULL },

	{ "job_id",       LDMS_MDESC_F_META, LDMS_V_CHAR_ARRAY, NULL,
			  LDMSD_JOBSET_JOB_ID_LEN, NULL },

	{ "user",         LDMS_MDESC_F_META, LDMS_V_CHAR_ARRAY, NULL,
			  LDMSD_JOBSET_USER_LEN, NULL },

	{ "job_name",     LDMS_MDESC_F_META, LDMS_V_CHAR_ARRAY, NULL,
			  LDMSD_JOBSET_JOB_NAME_LEN, NULL },

	{ "job_uid",      LDMS_MDESC_F_META, LDMS_V_U32,        NULL, 1,   NULL },
	{ "job_gid",      LDMS_MDESC_F_META, LDMS_V_U32,        NULL, 1,   NULL },
	{ "job_start",    LDMS_MDESC_F_DATA, LDMS_V_TIMESTAMP,  NULL, 1,   NULL },
	{ "job_end",      LDMS_MDESC_F_DATA, LDMS_V_TIMESTAMP,  NULL, 1,   NULL },
	{ "node_count",   LDMS_MDESC_F_DATA, LDMS_V_U32,        NULL, 1,   NULL },
	{ "total_tasks",  LDMS_MDESC_F_DATA, LDMS_V_U32,        NULL, 1,   NULL },
	{ "local_tasks",  LDMS_MDESC_F_DATA, LDMS_V_U32,        NULL, 1,   NULL },
	{ "task_list",    LDMS_MDESC_F_DATA, LDMS_V_LIST,       NULL, 4096, NULL },
	/* "task_rec_def" which describes task records shall also be added
	 * by the plugin. */
	{0},
};

struct ldms_metric_template_s common_task_rec_metrics[] = {

	{ "task_id",          LDMS_MDESC_F_DATA, LDMS_V_CHAR_ARRAY, NULL,
			      LDMSD_JOBSET_TASK_ID_LEN, NULL },

	{ "task_pid",         LDMS_MDESC_F_DATA, LDMS_V_U64,        NULL, 1,   NULL },
	{ "task_rank",        LDMS_MDESC_F_DATA, LDMS_V_U32,        NULL, 1,   NULL },
	{ "task_start",       LDMS_MDESC_F_DATA, LDMS_V_TIMESTAMP,  NULL, 1,   NULL },
	{ "task_end",         LDMS_MDESC_F_DATA, LDMS_V_TIMESTAMP,  NULL, 1,   NULL },
	{ "task_exit_status", LDMS_MDESC_F_DATA, LDMS_V_S32,        NULL, 1,   NULL },
	{0}
};

static int __jobset_cmp(void *tree_key, const void *key);

static pthread_mutex_t jobset_rbt_mutex;
static struct rbt jobset_rbt = RBT_INITIALIZER(__jobset_cmp);

#define JOBSET_RBT_LOCK() pthread_mutex_lock(&jobset_rbt_mutex)
#define JOBSET_RBT_UNLOCK() pthread_mutex_unlock(&jobset_rbt_mutex)

typedef struct jobset_s {
	struct rbn rbn;
	ldms_set_t set;
	const char *job_id; /* points to set['job_id'] */
	struct ovis_event_s del_ev;
	ldmsd_plug_handle_t mgr;
} *jobset_t;

static int __jobset_cmp(void *tree_key, const void *key)
{
	/* tree_key and key are `char*` */
	return strcmp(tree_key, key);
}

static void __client_finalize(ldmsd_jobmgr_event_client_t c);

/* jobset_rbt_mutex must be held */
jobset_t __jobset_new(ldmsd_plug_handle_t p, ldms_schema_t sch, const char *job_id)
{
	char buf[BUFSIZ];
	ldms_set_t set = NULL;
	ldmsd_cfgobj_jobmgr_t j = p;
	jobset_t jobset = NULL;
	ldms_mval_t mval;

	jobset = calloc(1, sizeof(*jobset));
	if (!jobset)
		goto out;

	assert(j->cfg.type == LDMSD_CFGOBJ_JOBMGR);

	snprintf(buf, sizeof(buf), "%s/job_%s", ldmsd_myname_get(), job_id);
	set = ldms_set_new_with_auth(buf, sch, geteuid(), getegid(), 0640);
	if (!set)
		goto err_0;
	jobset->set = set;
	ldms_set_ref_get(set, "jobset");

	jobset->mgr = p;
	ldmsd_jobmgr_get(p, "jobset");

	/* setup job_id  */
	mval = ldmsd_jobset_mval(jobset->set, JOB_ID);
	snprintf(mval->a_char, LDMSD_JOBSET_JOB_ID_LEN, "%s", job_id);
	rbn_init(&jobset->rbn, mval);

	rbt_ins(&jobset_rbt, &jobset->rbn);

	goto out;

 err_0:
	free(jobset);
	jobset = NULL;

 out:
	return jobset;
}

/* jobset_rbt_mutex must be held */
static jobset_t __jobset_find(const char *job_id)
{
	struct rbn *rbn;
	rbn = rbt_find(&jobset_rbt, job_id);
	return (rbn)?(container_of(rbn, struct jobset_s, rbn)):(NULL);
}

static void __jobset_free(jobset_t jobset)
{
	/* already removed from the jobset_tree */
	ldms_set_delete(jobset->set);
	ldms_set_ref_put(jobset->set, "jobset");
	ldmsd_jobmgr_put(jobset->mgr, "jobset");
	free(jobset);
}

ldms_set_t ldmsd_jobset_new(ldmsd_plug_handle_t p, ldms_schema_t sch, const char *job_id)
{
	ldms_set_t set = NULL;
	jobset_t jobset;

	JOBSET_RBT_LOCK();

	jobset = __jobset_find(job_id);
	if (jobset) {
		errno = EEXIST;
		goto out;
	}
	jobset = __jobset_new(p, sch, job_id);
	if (jobset)
		set = jobset->set;
 out:
	JOBSET_RBT_UNLOCK();
	return set;
}

ldms_set_t ldmsd_jobset_find(const char *job_id)
{
	jobset_t jobset;
	JOBSET_RBT_LOCK();
	jobset = __jobset_find(job_id);
	JOBSET_RBT_UNLOCK();
	if (jobset)
		return jobset->set;
	errno = ENOENT;
	return NULL;
}

static void jobset_delete_cb(ovis_event_t ev)
{
	jobset_t jobset = ev->param.ctxt;
	/* note: TIMEOUT event is a loop event :( need to remove it */
	ovis_scheduler_event_del(jobmgr_sched, ev);
	__jobset_free(jobset);
}

void ldmsd_jobset_delete(ldms_set_t set)
{
	/* TODO if ldms_set has app_ctxt ... our life would be easier */
	ldms_mval_t mval;
	jobset_t jobset;

	mval = ldmsd_jobset_mval(set, JOB_ID);
	JOBSET_RBT_LOCK();
	jobset = __jobset_find(mval->a_char);
	if (jobset)
		rbt_del(&jobset_rbt, &jobset->rbn);
	JOBSET_RBT_UNLOCK();

	if (jobset) {
		/* post jobset delete events to clients so that they're aware */
		struct ldmsd_jobmgr_event ev = {
			.type = LDMSD_JOBMGR_SET_DELETE,
			.jobset = jobset->set,
			.mgr = jobset->mgr,
		};

		ldmsd_jobmgr_event_post(&ev);

		/* delay delete */
		OVIS_EVENT_INIT(&jobset->del_ev);
		jobset->del_ev.param.type = OVIS_EVENT_TIMEOUT;
		jobset->del_ev.param.cb_fn = jobset_delete_cb;
		jobset->del_ev.param.ctxt  = jobset;
		jobset->del_ev.param.timeout.tv_sec  = 10;
		jobset->del_ev.param.timeout.tv_usec = 0;
		ovis_scheduler_event_add(jobmgr_sched, &jobset->del_ev);
	}
}

typedef struct jobmgr_ev_s {
	struct ldmsd_jobmgr_event job_ev;
	struct ovis_event_s ovis_ev;
} *jobmgr_ev_t;

struct ldmsd_jobmgr_event_client_s {
	TAILQ_ENTRY(ldmsd_jobmgr_event_client_s) entry;
	ldmsd_jobmgr_event_cb_fn_t cb;
	void *arg;
	int list_ref; /* protected by client_tq_mutex */
};
TAILQ_HEAD(jobmgr_client_tq, ldmsd_jobmgr_event_client_s);

static struct jobmgr_client_tq client_tq = TAILQ_HEAD_INITIALIZER(client_tq);
pthread_mutex_t client_tq_mutex;
#define CLIENT_TQ_LOCK() pthread_mutex_lock(&client_tq_mutex)
#define CLIENT_TQ_UNLOCK() pthread_mutex_unlock(&client_tq_mutex)

static void job_event_cb(ovis_event_t oev)
{
	jobmgr_ev_t jev = oev->param.ctxt;
	struct jobmgr_client_tq rm_tq = TAILQ_HEAD_INITIALIZER(rm_tq);
	ldmsd_jobmgr_event_client_t c, _c;
	CLIENT_TQ_LOCK();
	c = TAILQ_FIRST(&client_tq);
	while (c) {
		assert(c->list_ref > 0);
		c->list_ref++;
		CLIENT_TQ_UNLOCK();
		c->cb(c, &jev->job_ev, c->arg);
		CLIENT_TQ_LOCK();
		c->list_ref--;
		if (0 == c->list_ref) {
			_c = c;
			c = TAILQ_NEXT(c, entry);
			TAILQ_REMOVE(&client_tq, _c, entry);
			TAILQ_INSERT_TAIL(&rm_tq, _c, entry);
		} else {
			c = TAILQ_NEXT(c, entry);
		}
	}
	CLIENT_TQ_UNLOCK();

	while ((c = TAILQ_FIRST(&rm_tq))) {
		TAILQ_REMOVE(&rm_tq, c, entry);
		__client_finalize(c);
	}
}


int ldmsd_jobmgr_event_post(const struct ldmsd_jobmgr_event *ev)
{
	int rc;
	jobmgr_ev_t jev = calloc(1, sizeof(*jev));

	if (!jev)
		return ENOMEM;

	OVIS_EVENT_INIT(&jev->ovis_ev);

	jev->job_ev = *ev; /* copy */
	jev->ovis_ev.param.type  = OVIS_EVENT_ONESHOT;
	jev->ovis_ev.param.cb_fn = job_event_cb;
	jev->ovis_ev.param.ctxt  = jev;

	rc = ovis_scheduler_event_add(jobmgr_sched, &jev->ovis_ev);
	if (rc) {
		free(jev);
		return rc;
	}

	return 0;
}

ldmsd_jobmgr_event_client_t ldmsd_jobmgr_event_subscribe(ldmsd_jobmgr_event_cb_fn_t cb, void *arg)
{
	ldmsd_jobmgr_event_client_t c;

	c = calloc(1, sizeof(*c));
	if (!c)
		goto out;
	c->arg = arg;
	c->cb = cb;
	c->list_ref = 1;
	CLIENT_TQ_LOCK();
	TAILQ_INSERT_TAIL(&client_tq, c, entry);
	CLIENT_TQ_UNLOCK();

 out:
	return c;
}

static void __client_finalize(ldmsd_jobmgr_event_client_t c)
{
	struct ldmsd_jobmgr_event ev = {
		.type = LDMSD_JOBMGR_CLIENT_CLOSE,
	};
	c->cb(c, &ev, c->arg);
	free(c);
}

void ldmsd_jobmgr_event_client_close(ldmsd_jobmgr_event_client_t c)
{
	assert(0 == ENOSYS);
	int removed = 0;
	CLIENT_TQ_LOCK();
	c->list_ref--;
	if (0 == c->list_ref) {
		/* safe to remove from the list */
		TAILQ_REMOVE(&client_tq, c, entry);
		removed = 1;
	}
	CLIENT_TQ_UNLOCK();

	if (removed) {
		__client_finalize(c);
	}
}

ldms_set_t ldmsd_jobset_first()
{
	struct rbn *rbn;
	ldms_set_t set = NULL;

	JOBSET_RBT_LOCK();
	rbn = rbt_min(&jobset_rbt);
	if (rbn) {
		set = container_of(rbn, struct jobset_s, rbn)->set;
		ldms_set_ref_get(set, "jobset_iter");
	} else {
		errno = ENOENT;
	}
	JOBSET_RBT_UNLOCK();
	return set;
}

ldms_set_t ldmsd_jobset_next(ldms_set_t set)
{
	struct rbn *rbn;
	ldms_set_t next_set;
	ldms_mval_t mval;

	/* TODO Maybe add some check to make sure set is a job set */

	JOBSET_RBT_LOCK();
	mval = ldmsd_jobset_mval(set, JOB_ID);
	rbn = rbt_find_lub(&jobset_rbt, mval);
	rbn = rbt_min(&jobset_rbt);
 again:
	if (rbn) {
		next_set = container_of(rbn, struct jobset_s, rbn)->set;
		if (next_set == set) {
			rbn = rbn_succ(rbn);
			goto again;
		}
		ldms_set_ref_get(next_set, "jobset_iter");
	} else {
		errno = ENOENT;
	}
	JOBSET_RBT_UNLOCK();

	ldms_set_ref_put(set, "jobset_iter");
	return next_set;
}

ldms_mval_t ldmsd_task_first(ldms_set_t set)
{
	ldms_mval_t task_list = ldmsd_jobset_mval(set, TASK_LIST);
	ldms_mval_t task;
	task = ldms_list_first(set, task_list, NULL, NULL);
	if (!task)
		errno = ENOENT;
	return task;
}

ldms_mval_t ldmsd_task_next(ldms_set_t set, ldms_mval_t task)
{
	ldms_mval_t next_task = ldms_list_next(set, task, NULL, NULL);
	if (!next_task)
		errno = ENOENT;
	return next_task;
}

int ldmsd_jobmgr_start(ldmsd_cfgobj_jobmgr_t jm)
{
	/* TODO revise me, e.g. check status ... */
	return jm->api->start(jm);
}

int ldmsd_jobmgr_stop(ldmsd_cfgobj_jobmgr_t jm)
{
	/* TODO revise me, e.g. check status ... */
	return jm->api->stop(jm);
}

int ldmsd_jobset_list(struct ldmsd_jobset_tq *tq)
{
	struct rbn *rbn;
	struct ldmsd_jobset_entry *ent;
	struct jobset_s *jset;

	JOBSET_RBT_LOCK();
	RBT_FOREACH(rbn, &jobset_rbt) {
		jset = container_of(rbn, struct jobset_s, rbn);
		ent = calloc(1, sizeof(*ent));
		if (!ent)
			goto err_0;
		ent->set = jset->set;
		ldms_set_ref_get(ent->set, "jobset_list");
		TAILQ_INSERT_TAIL(tq, ent, entry);
	}
	JOBSET_RBT_UNLOCK();
	return 0;

 err_0:
	JOBSET_RBT_UNLOCK();
	while ((ent = TAILQ_FIRST(tq))) {
		TAILQ_REMOVE(tq, ent, entry);
		ldms_set_ref_put(ent->set, "jobset_list");
		free(ent);
	}
	return errno;
}

void ldmsd_jobset_list_free(struct ldmsd_jobset_tq *tq)
{
	struct ldmsd_jobset_entry *ent;
	while ((ent = TAILQ_FIRST(tq))) {
		TAILQ_REMOVE(tq, ent, entry);
		ldms_set_ref_put(ent->set, "jobset_list");
		free(ent);
	}
}

void *jobmgr_sched_proc(void *arg)
{
	ovis_scheduler_loop(jobmgr_sched, 0);
	assert(0 == "jobmgr_sched-proc unexpectedly terminated");
	return NULL;
}

__attribute__((constructor))
static void jobmgr_once()
{
	jobmgr_sched = ovis_scheduler_new();
	pthread_create(&jobmgr_thr, NULL, jobmgr_sched_proc, NULL);
	pthread_setname_np(jobmgr_thr, "jobmgr");
}
