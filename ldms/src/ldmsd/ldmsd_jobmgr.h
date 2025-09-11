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
#ifndef __LDMSD_JOBMGR_H__
#define __LDMSD_JOBMGR_H__
#include "ldmsd.h"

/* jobmgr API */
struct ldmsd_jobmgr {
	struct ldmsd_plugin base;

	/* Called by `ldmsd` to start the plugin.
	 * The plugin can then start manipulating \c jobset. */
	int (*start)(ldmsd_plug_handle_t handle);

	/* Called by `ldmsd` to stop the plugin.
	 * The plugin shall not manipulate \c jobset after this function is called. */
	int (*stop)(ldmsd_plug_handle_t handle);

};

/* jobmgr cfgobj instance */
struct ldmsd_cfgobj_jobmgr {
	struct ldmsd_cfgobj cfg;
	struct ldmsd_plugin_generic *plugin;
	struct ldmsd_jobmgr *api;

	/* Set to 1 if the plugin has been configured */
	int configured;

	/* Private context pointer, managed by plugin */
	void *context;
	/* ovis_log handle to use when logging plugin messages */
	ovis_log_t log;
};
typedef struct ldmsd_cfgobj_jobmgr *ldmsd_cfgobj_jobmgr_t;

#define LDMSD_JOBSET_COMPONENT_ID_LEN   256
#define LDMSD_JOBSET_JOB_ID_LEN   256
#define LDMSD_JOBSET_USER_LEN     32
#define LDMSD_JOBSET_JOB_NAME_LEN 256
#define LDMSD_JOBSET_TASK_ID_LEN  256

typedef enum ldmsd_jobset_metric_id_e {
	/* maintain the same order with common_jobset_metrics[] */
	LDMSD_JOBSET_MID_COMPONENT_ID = 0,
	LDMSD_JOBSET_MID_JOB_ID,
	LDMSD_JOBSET_MID_USER,
	LDMSD_JOBSET_MID_JOB_NAME,
	LDMSD_JOBSET_MID_JOB_UID,
	LDMSD_JOBSET_MID_JOB_GID,
	LDMSD_JOBSET_MID_JOB_START,
	LDMSD_JOBSET_MID_JOB_END,
	LDMSD_JOBSET_MID_NODE_COUNT,
	LDMSD_JOBSET_MID_TOTAL_TASKS,
	LDMSD_JOBSET_MID_LOCAL_TASKS,
	LDMSD_JOBSET_MID_TASK_LIST,
	LDMSD_JOBSET_MID_TASK_REC_DEF,
} ldmsd_jobset_metric_id_t;
#define ldmsd_jobset_mval( set, SYM ) \
		ldms_metric_get( set, LDMSD_JOBSET_MID_ ## SYM )

/*
 * Each job set will have at the least the following metrics.
 * See ldmsd_jobmgr.c
 *
 * This list is {0} terminated.
 */
extern struct ldms_metric_template_s common_jobset_metrics[];


typedef enum ldmsd_task_rec_metric_id_e {
	/* maintain the same order as common_task_rec_metrics[] */
	LDMSD_TASK_REC_MID_TASK_ID = 0,
	LDMSD_TASK_REC_MID_TASK_PID,
	LDMSD_TASK_REC_MID_TASK_RANK,
	LDMSD_TASK_REC_MID_TASK_START,
	LDMSD_TASK_REC_MID_TASK_END,
	LDMSD_TASK_REC_MID_TASK_EXIT_STATUS
} ldmsd_task_rec_metric_id_t;
#define ldmsd_task_rec_mval( rec, SYM ) \
		ldms_record_metric_get( rec, LDMSD_TASK_REC_MID_ ## SYM )

/*
 * The task records will have at least the following metrics.
 * See ldmsd_jobmgr.c.
 *
 * This list is {0} terminated.
 */
extern struct ldms_metric_template_s common_task_rec_metrics[];

static inline ldmsd_cfgobj_jobmgr_t ldmsd_jobmgr_find_get(const char *cfg_name)
{
	struct ldmsd_cfgobj *obj = ldmsd_cfgobj_find_get(cfg_name, LDMSD_CFGOBJ_JOBMGR);
	if (!obj)
		return NULL;
	return container_of(obj, struct ldmsd_cfgobj_jobmgr, cfg);
}

#define ldmsd_jobmgr_find_put(j) ldmsd_cfgobj_find_put(((struct ldmsd_cfgobj*)j))

/* These are functions for plugins to call to manage `jobset` with ldmsd. */

/**
 * \brief Tell `ldmsd` to create a job set.
 *
 * This function is called by job plugins to create a new job set. The job
 * plugins are expected to create a schema containing at least metrics in
 * \c common_jobset_metrics template plus \c task_rec_def task record
 * definition (which has at least \c common_task_rec_metrics).
 *
 * \retval jobset  A handle to the job set.
 * \retval NULL     If there is an error. \c errno will be set.
 */
ldms_set_t ldmsd_jobset_new(ldmsd_plug_handle_t p, ldms_schema_t sch, const char *job_id);

/**
 * \brief Find the \c jobset of the given \c job_id.
 *
 * \retval jobset  A handle to the job set.
 * \retval NULL     If the job set for the \c job_id is not found.
 *                  \c errno is set to \c ENOENT.
 */
ldms_set_t ldmsd_jobset_find(const char *job_id);

struct ldmsd_jobset_entry {
	TAILQ_ENTRY(ldmsd_jobset_entry) entry;
	ldms_set_t set;
};
TAILQ_HEAD(ldmsd_jobset_tq, ldmsd_jobset_entry);

/**
 * List current job sets, insert entries into the given \c tq.
 *
 * \retval 0     If success,
 * \retval errno If error.
 */
int ldmsd_jobset_list(struct ldmsd_jobset_tq *tq);

/**
 * Free entries populated from \c ldmsd_jobset_list().
 */
void ldmsd_jobset_list_free(struct ldmsd_jobset_tq *tq);

/* Tell \c ldmsd that the \c jobset is no longer needed by the plugin. */
void ldmsd_jobset_delete(ldms_set_t jobset);

enum ldmsd_jobmgr_event_type {
	LDMSD_JOBMGR_JOB_START,
	LDMSD_JOBMGR_TASK_START,
	LDMSD_JOBMGR_TASK_END,
	LDMSD_JOBMGR_JOB_END,
	LDMSD_JOBMGR_SET_DELETE, /* the jobset is going away ... stop using it */
	LDMSD_JOBMGR_CLIENT_CLOSE, /* the last event delivered to the cb fn */
};

struct ldmsd_jobmgr_event {
	enum ldmsd_jobmgr_event_type type;
	ldmsd_plug_handle_t mgr; /* The job manager plugin that posted the event */
	ldms_set_t  jobset;     /* for client side convenience */
	ldms_mval_t task_record; /* NULL if type is not LDMSD_JOBMGR_TASK_{START|END} */
};

/**
 * \brief Post an event to ldmsd job event notification system.
 */
int ldmsd_jobmgr_event_post(const struct ldmsd_jobmgr_event *ev);

typedef struct ldmsd_jobmgr_event_client_s *ldmsd_jobmgr_event_client_t;

typedef void (*ldmsd_jobmgr_event_cb_fn_t)(ldmsd_jobmgr_event_client_t c,
		const struct ldmsd_jobmgr_event *ev,
		void *arg);

/**
 * \brief Subscribe for job events from all available job managers.
 *
 * The callback function \c cb will be called when there is a job event has been
 * posted by a job manager plugin. The \c arg specified here will be supplied to
 * \c arg argument when the \c cb() is called.
 *
 * \param cb  The callback function (see \c ldmsd_jobmgr_event_cb_fn_t).
 * \param arg The argument supplied to \c arg in \c cb function.
 *
 * \retval handle If the subscription was a success, or
 * \retval NULL   If subscription failed. \c errno will be set to describe the
 *                error.
 */
ldmsd_jobmgr_event_client_t ldmsd_jobmgr_event_subscribe(ldmsd_jobmgr_event_cb_fn_t cb, void *arg);

/**
 * \brief Terminating the job event client.
 *
 * This will generate \c LDMSD_JOBMGR_CLIENT_CLOSE event to the client \c c,
 * indicating that there will be no more events afterwards.
 */
void ldmsd_jobmgr_event_client_close(ldmsd_jobmgr_event_client_t c);

/* get the first job */
ldms_set_t ldmsd_jobset_first();
/* get the next job */
ldms_set_t ldmsd_jobset_next(ldms_set_t jobset);

/* get the first task in the list */
ldms_mval_t ldmsd_task_first(ldms_set_t jobset);
/* get the next task job */
ldms_mval_t ldmsd_task_next(ldms_set_t jobset, ldms_mval_t task);

#define ldmsd_jobmgr_get(_s_, _r_) ((ldmsd_cfgobj_jobmgr_t)ldmsd_cfgobj_get(&((ldmsd_cfgobj_jobmgr_t)_s_)->cfg, _r_))
#define ldmsd_jobmgr_put(_s_, _r_) ldmsd_cfgobj_put(&((ldmsd_cfgobj_jobmgr_t)_s_)->cfg, _r_)

int ldmsd_jobmgr_start(ldmsd_cfgobj_jobmgr_t jm);
int ldmsd_jobmgr_stop(ldmsd_cfgobj_jobmgr_t jm);

#endif
