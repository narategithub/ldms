/* -*- c-basic-offset: 8 -*-
 * Copyright (c) 2015 Open Grid Computing, Inc. All rights reserved.
 * Copyright (c) 2015 Sandia Corporation. All rights reserved.
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

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <coll/rbt.h>
#include <ovis_util/util.h>
#include "event.h"
#include "ldms.h"
#include "ldmsd.h"
#include "ldms_xprt.h"
#include "config.h"

static void prdcr_task_cb(ldmsd_task_t task, void *arg);

int prdcr_resolve(const char *hostname, short port_no,
		  struct sockaddr_storage *ss, socklen_t *ss_len)
{
	struct hostent *h;

	h = gethostbyname(hostname);
	if (!h) {
		printf("Error resolving hostname '%s'\n", hostname);
		return -1;
	}

	if (h->h_addrtype != AF_INET)
		return -1;

	memset(ss, 0, sizeof *ss);
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;
	sin->sin_addr.s_addr = *(unsigned int *)(h->h_addr_list[0]);
	sin->sin_family = h->h_addrtype;
	sin->sin_port = htons(port_no);
	*ss_len = sizeof(*sin);
	return 0;
}

void ldmsd_prdcr___del(ldmsd_cfgobj_t obj)
{
	ldmsd_prdcr_t prdcr = (ldmsd_prdcr_t)obj;
	if (prdcr->host_name)
		free(prdcr->host_name);
	if (prdcr->xprt_name)
		free(prdcr->xprt_name);
	ldmsd_cfgobj___del(obj);
}

static ldmsd_prdcr_set_t prdcr_set_new(const char *inst_name)
{
	ldmsd_prdcr_set_t set = calloc(1, sizeof *set);
	if (!set)
		goto err_0;
	set->state = LDMSD_PRDCR_SET_STATE_START;
	set->inst_name = strdup(inst_name);
	if (!set->inst_name)
		goto err_1;
	pthread_mutex_init(&set->lock, NULL);
	rbn_init(&set->rbn, set->inst_name);
	return set;
err_1:
	free(set);
err_0:
	return NULL;
}

static void prdcr_set_del(ldmsd_prdcr_set_t set)
{
	if (set->schema_name)
		free(set->schema_name);
	if (set->set)
		ldms_set_delete(set->set);
	else {
		ldms_set_t lset = ldms_set_by_name(set->inst_name);
		if (lset)
			ldms_set_delete(lset);
	}
	ldmsd_strgp_ref_t strgp_ref;
	strgp_ref = LIST_FIRST(&set->strgp_list);
	while (strgp_ref) {
		LIST_REMOVE(strgp_ref, entry);
		ldmsd_strgp_put(strgp_ref->strgp);
		free(strgp_ref);
		strgp_ref = LIST_FIRST(&set->strgp_list);
	}
	free(set->inst_name);
	free(set);
}

/**
 * Destroy all sets for the producer
 */
static void prdcr_reset_sets(ldmsd_prdcr_t prdcr)
{
	ldmsd_prdcr_set_t prd_set;
	struct rbn *rbn;
	while ((rbn = rbt_min(&prdcr->set_tree))) {
		prd_set = container_of(rbn, struct ldmsd_prdcr_set, rbn);
		rbt_del(&prdcr->set_tree, rbn);
		prdcr_set_del(prd_set);
	}
}

/**
 * Find the prdcr_set with the matching instance name
 *
 * Must be called with the prdcr->lock held.
 */
static ldmsd_prdcr_set_t _find_set(ldmsd_prdcr_t prdcr, const char *inst_name)
{
	struct rbn *rbn = rbt_find(&prdcr->set_tree, inst_name);
	if (rbn)
		return container_of(rbn, struct ldmsd_prdcr_set, rbn);
	return NULL;
}

static void prdcr_lookup_cb(ldms_t xprt, enum ldms_lookup_status status,
			    int more, ldms_set_t set, void *arg)
{
	ldmsd_prdcr_set_t prd_set = arg;

	pthread_mutex_lock(&prd_set->lock);
	if (status != LDMS_LOOKUP_OK) {
		ldmsd_log(LDMSD_LERROR, "Error doing lookup for set '%s'\n", prd_set->inst_name);
		if (prd_set->set)
			ldms_set_delete(prd_set->set);
		prd_set->set = NULL;
		goto err;
	}
	/*
	 * Check that the producer name in the metric set matches our
	 * name. If it doesn't, we write a warning to the log file
	 */
	if (strcmp(prd_set->prdcr->obj.name, ldms_set_producer_name_get(set)))
		ldmsd_log(LDMSD_LERROR, "Warning: The producer name '%s' in the configuration\n"
			 "does not match the producer name '%s' in the '%s' metric set.\n",
			 prd_set->prdcr->obj.name, ldms_set_producer_name_get(set),
			 ldms_set_instance_name_get(set));
	prd_set->set = set;
	prd_set->schema_name = strdup(ldms_set_schema_name_get(set));
	prd_set->state = LDMSD_PRDCR_SET_STATE_READY;
	ldmsd_strgp_update(prd_set);
	pthread_mutex_unlock(&prd_set->lock);
	return;
err:
	prd_set->state = LDMSD_PRDCR_SET_STATE_START;
	pthread_mutex_unlock(&prd_set->lock);
}

static void _add_cb(ldms_t xprt, ldmsd_prdcr_t prdcr, const char *inst_name)
{
	ldmsd_prdcr_set_t set;
	int rc;

	ldmsd_log(LDMSD_LINFO, "Adding the metric set '%s'\n", inst_name);

	/* Check to see if it's already there */
	set = _find_set(prdcr, inst_name);
	if (!set) {
		set = prdcr_set_new(inst_name);
		if (!set) {
			ldmsd_log(LDMSD_LERROR, "Memory allocation failure in %s "
				 "for set_name %s\n",
				 __FUNCTION__, inst_name);
			return;
		}
		set->prdcr = prdcr;
		rbt_ins(&prdcr->set_tree, &set->rbn);
	}
	/* Refresh the set with a lookup */
	rc = ldms_xprt_lookup(prdcr->xprt, inst_name,
			      LDMS_LOOKUP_BY_INSTANCE,
			      prdcr_lookup_cb, set);
	if (rc)
		ldmsd_log(LDMSD_LERROR, "Synchronous error %d from ldms_lookup\n", rc);
}

/*
 * Process the directory list and add or restore specified sets.
 */
static void prdcr_dir_cb_add(ldms_t xprt, ldms_dir_t dir, ldmsd_prdcr_t prdcr)
{
	int i;
	for (i = 0; i < dir->set_count; i++)
		_add_cb(xprt, prdcr, dir->set_names[i]);
}

static void prdcr_dir_cb_list(ldms_t xprt, ldms_dir_t dir, ldmsd_prdcr_t prdcr)
{
	return prdcr_dir_cb_add(xprt, dir, prdcr);
}

/*
 * Process the directory list and release the deleted sets
 */
static void prdcr_dir_cb_del(ldms_t xprt, ldms_dir_t dir, ldmsd_prdcr_t prdcr)
{
	ldmsd_prdcr_set_t set;
	int i;

	for (i = 0; i < dir->set_count; i++) {
		struct rbn *rbn = rbt_find(&prdcr->set_tree, dir->set_names[i]);
		if (!rbn)
			continue;
		set = container_of(rbn, struct ldmsd_prdcr_set, rbn);
		rbt_del(&prdcr->set_tree, &set->rbn);
		prdcr_set_del(set);
	}
}

/*
 * The ldms_dir has completed. Decode the directory type and call the
 * appropriate handler function.
 */
static void prdcr_dir_cb(ldms_t xprt, int status, ldms_dir_t dir, void *arg)
{
	ldmsd_prdcr_t prdcr = arg;
	if (status) {
		ldmsd_log(LDMSD_LERROR, "Error %d in lookup on producer %s host %s.\n",
			 status, prdcr->obj.name, prdcr->host_name);
		return;
	}
	ldmsd_prdcr_lock(prdcr);
	switch (dir->type) {
	case LDMS_DIR_LIST:
		prdcr_dir_cb_list(xprt, dir, prdcr);
		break;
	case LDMS_DIR_ADD:
		prdcr_dir_cb_add(xprt, dir, prdcr);
		break;
	case LDMS_DIR_DEL:
		prdcr_dir_cb_del(xprt, dir, prdcr);
		break;
	}
	ldmsd_prdcr_unlock(prdcr);
	ldms_xprt_dir_free(xprt, dir);
}

static void prdcr_connect_cb(ldms_t x, ldms_conn_event_t e, void *cb_arg)
{
	ldmsd_prdcr_t prdcr = cb_arg;
	ldmsd_prdcr_lock(prdcr);
	switch (e) {
	case LDMS_CONN_EVENT_CONNECTED:
		prdcr->conn_state = LDMSD_PRDCR_STATE_CONNECTED;
		if (ldms_xprt_dir(prdcr->xprt, prdcr_dir_cb, prdcr,
				  LDMS_DIR_F_NOTIFY))
			ldms_xprt_close(prdcr->xprt);
		ldmsd_task_stop(&prdcr->task);
		break;
	case LDMS_CONN_EVENT_REJECTED:
		ldmsd_log(LDMSD_LERROR, "Producer %s rejected the "
				"connection\n", prdcr->obj.name);
	case LDMS_CONN_EVENT_DISCONNECTED:
	case LDMS_CONN_EVENT_ERROR:
		prdcr_reset_sets(prdcr);
		if (prdcr->conn_state != LDMSD_PRDCR_STATE_STOPPED) {
			prdcr->conn_state = LDMSD_PRDCR_STATE_DISCONNECTED;
			ldmsd_task_start(&prdcr->task, prdcr_task_cb, prdcr,
					 0, prdcr->conn_intrvl_us, 0);
		}
		ldms_xprt_put(prdcr->xprt);
		prdcr->xprt = NULL;
		break;
	default:
		assert(0);
	}
	ldmsd_prdcr_unlock(prdcr);
}

static void prdcr_connect(ldmsd_prdcr_t prdcr)
{
	int ret;

	assert(prdcr->xprt == NULL);
	switch (prdcr->type) {
	case LDMSD_PRDCR_TYPE_ACTIVE:
		prdcr->conn_state = LDMSD_PRDCR_STATE_CONNECTING;
#ifdef ENABLE_AUTH
		prdcr->xprt = ldms_xprt_with_auth_new(prdcr->xprt_name,
				ldmsd_lcritical, ldmsd_secret_get());
#else
		prdcr->xprt = ldms_xprt_new(prdcr->xprt_name, ldmsd_lcritical);
#endif /* ENABLE_AUTH */
		if (prdcr->xprt) {
			ret  = ldms_xprt_connect(prdcr->xprt,
						 (struct sockaddr *)&prdcr->ss,
						 prdcr->ss_len,
						 prdcr_connect_cb, prdcr);
			if (ret) {
				ldms_xprt_put(prdcr->xprt);
				prdcr->xprt = NULL;
				prdcr->conn_state = LDMSD_PRDCR_STATE_DISCONNECTED;
			}
		} else {
			ldmsd_log(LDMSD_LERROR, "%s Error creating endpoint on transport '%s'.\n",
				 __func__, prdcr->xprt_name);
			prdcr->conn_state = LDMSD_PRDCR_STATE_DISCONNECTED;
		}
		break;
	case LDMSD_PRDCR_TYPE_PASSIVE:
		prdcr->xprt = ldms_xprt_by_remote_sin((struct sockaddr_in *)&prdcr->ss);
		/* Call connect callback to advance state and update timers*/
		if (prdcr->xprt)
			prdcr_connect_cb(prdcr->xprt, LDMS_CONN_EVENT_CONNECTED, prdcr);
		break;
	case LDMSD_PRDCR_TYPE_LOCAL:
		assert(0);
	}
}
static void prdcr_task_cb(ldmsd_task_t task, void *arg)
{
	ldmsd_prdcr_t prdcr = arg;

	ldmsd_prdcr_lock(prdcr);
	switch (prdcr->conn_state) {
	case LDMSD_PRDCR_STATE_STOPPED:
		ldmsd_task_stop(&prdcr->task);
		break;
	case LDMSD_PRDCR_STATE_DISCONNECTED:
		prdcr_connect(prdcr);
		break;
	case LDMSD_PRDCR_STATE_CONNECTING:
		break;
	case LDMSD_PRDCR_STATE_CONNECTED:
		ldmsd_task_stop(&prdcr->task);
		break;
	}
	ldmsd_prdcr_unlock(prdcr);
}

static int set_cmp(void *a, const void *b)
{
	return strcmp(a, b);
}

ldmsd_prdcr_t
ldmsd_prdcr_new(const char *name, const char *xprt_name,
		const char *host_name, const short port_no,
		enum ldmsd_prdcr_type type,
		int conn_intrvl_us)
{
	struct ldmsd_prdcr *prdcr;

	prdcr = (struct ldmsd_prdcr *)
		ldmsd_cfgobj_new(name, LDMSD_CFGOBJ_PRDCR,
				 sizeof *prdcr, ldmsd_prdcr___del);
	if (!prdcr)
		return NULL;

	prdcr->type = type;
	prdcr->conn_intrvl_us = conn_intrvl_us;
	prdcr->port_no = port_no;
	prdcr->conn_state = LDMSD_PRDCR_STATE_STOPPED;
	rbt_init(&prdcr->set_tree, set_cmp);
	prdcr->host_name = strdup(host_name);
	if (!prdcr->host_name)
		goto out;
	prdcr->xprt_name = strdup(xprt_name);
	if (!prdcr->port_no)
		goto out;

	if (prdcr_resolve(host_name, port_no, &prdcr->ss, &prdcr->ss_len)) {
		errno = EAFNOSUPPORT;
		goto out;
	}
	ldmsd_task_init(&prdcr->task);
	ldmsd_cfgobj_unlock(&prdcr->obj);
	return prdcr;
out:
	ldmsd_cfgobj_unlock(&prdcr->obj);
	ldmsd_cfgobj_put(&prdcr->obj);
	return NULL;
}

ldmsd_prdcr_t ldmsd_prdcr_first()
{
	return (ldmsd_prdcr_t)ldmsd_cfgobj_first(LDMSD_CFGOBJ_PRDCR);
}

ldmsd_prdcr_t ldmsd_prdcr_next(struct ldmsd_prdcr *prdcr)
{
	return (ldmsd_prdcr_t)ldmsd_cfgobj_next(&prdcr->obj);
}

/**
 * Get the first producer set
 *
 * This function must be called with the ldmsd_cfgobj_lock held.
 */
ldmsd_prdcr_set_t ldmsd_prdcr_set_first(ldmsd_prdcr_t prdcr)
{
	struct rbn *rbn = rbt_min(&prdcr->set_tree);
	if (rbn)
		return container_of(rbn, struct ldmsd_prdcr_set, rbn);
	return NULL;
}

/**
 * Get the next producer set
 *
 * This function must be called with the ldmsd_cfgobj_lock held.
 */
ldmsd_prdcr_set_t ldmsd_prdcr_set_next(ldmsd_prdcr_set_t prd_set)
{
	struct rbn *rbn = rbn_succ(&prd_set->rbn);
	if (rbn)
		return container_of(rbn, struct ldmsd_prdcr_set, rbn);
	return NULL;
}

int cmd_prdcr_add(char *replybuf, struct attr_value_list *avl, struct attr_value_list *kwl)
{
	char *attr;
	char *type, *name, *xprt_name, *host_name, *port, *interval_us;
	int intrvl_us;
	enum ldmsd_prdcr_type prdcr_type;
	short port_no;

	attr = "name";
	name = av_value(avl, attr);
	if (!name)
		goto einval;

	attr = "type";
	type = av_value(avl, attr);
	if (!type)
		goto einval;

	if (0 == strcasecmp(type, "active"))
		prdcr_type = LDMSD_PRDCR_TYPE_ACTIVE;
	else if (0 == strcasecmp(type, "passive"))
		prdcr_type = LDMSD_PRDCR_TYPE_PASSIVE;
	else if (0 == strcasecmp(type, "local"))
		prdcr_type = LDMSD_PRDCR_TYPE_LOCAL;
	else
		goto einval;

	attr = "xprt";
	xprt_name = av_value(avl, attr);
	if (!xprt_name)
		goto einval;

	attr = "host";
	host_name = av_value(avl, attr);
	if (!host_name)
		goto einval;

	attr = "port";
	port = av_value(avl, attr);
	if (!port)
		goto einval;
	port_no = strtol(port, NULL, 0);

	attr = "interval";
	interval_us = av_value(avl, attr);
	if (!interval_us)
		goto einval;
	intrvl_us = strtol(interval_us, NULL, 0);

	ldmsd_prdcr_t prdcr = ldmsd_prdcr_new(name,
					      xprt_name, host_name, port_no,
					      prdcr_type, intrvl_us);
	if (!prdcr) {
		if (errno == EEXIST)
			goto eexist;
		else
			goto enomem;
	}
	strcpy(replybuf, "0");
	goto out;

eexist:
	sprintf(replybuf, "%dThe prdcr %s already exists.\n", EEXIST, name);
	goto out;
enomem:
	sprintf(replybuf, "%dMemory allocation failed.\n", ENOMEM);
	goto out;
einval:
	sprintf(replybuf, "%dThe attribute '%s' is required.\n", EINVAL, attr);
out:
	return 0;
}

void ldmsd_prdcr_update(ldmsd_strgp_t strgp)
{
	/*
	 * For each producer with a name that matches the storage
	 * policy's regex list, add a reference to this storage policy
	 * to each producer set matching the schema name
	 */
	ldmsd_cfg_lock(LDMSD_CFGOBJ_PRDCR);
	ldmsd_prdcr_t prdcr;
	for (prdcr = ldmsd_prdcr_first(); prdcr; prdcr = ldmsd_prdcr_next(prdcr)) {
		int rc;
		ldmsd_name_match_t match = ldmsd_strgp_prdcr_first(strgp);
		for (rc = 0; match; match = ldmsd_strgp_prdcr_next(match)) {
			rc = regexec(&match->regex, prdcr->obj.name, 0, NULL, 0);
			if (!rc)
				break;
		}
		if (rc)
			continue;

		ldmsd_prdcr_lock(prdcr);
		/*
		 * For each producer set matching our schema, add our policy
		 */
		ldmsd_prdcr_set_t prd_set;
		for (prd_set = ldmsd_prdcr_set_first(prdcr);
		     prd_set; prd_set = ldmsd_prdcr_set_next(prd_set)) {
			if (prd_set->state != LDMSD_PRDCR_SET_STATE_READY)
				continue;
			ldmsd_strgp_update_prdcr_set(strgp, prd_set);
		}
		ldmsd_prdcr_unlock(prdcr);
	}
	ldmsd_cfg_unlock(LDMSD_CFGOBJ_PRDCR);
}

int cmd_prdcr_start(char *replybuf, struct attr_value_list *avl, struct attr_value_list *kwl)
{
	char *prdcr_name, *interval_str;
	prdcr_name = av_value(avl, "name");
	if (!prdcr_name) {
		sprintf(replybuf, "%dThe producer name must be specified\n", EINVAL);
		goto out_0;
	}
	interval_str = av_value(avl, "interval"); /* Can be null if we're not changing it */

	ldmsd_prdcr_t prdcr = ldmsd_prdcr_find(prdcr_name);
	if (!prdcr) {
		sprintf(replybuf, "%dThe producer specified does not exist\n", ENOENT);
		goto out_0;
	}
	ldmsd_prdcr_lock(prdcr);
	if (prdcr->conn_state != LDMSD_PRDCR_STATE_STOPPED) {
		sprintf(replybuf, "%dThe producer is already running\n", EBUSY);
		goto out_1;
	}
	prdcr->conn_state = LDMSD_PRDCR_STATE_DISCONNECTED;
	if (interval_str)
		prdcr->conn_intrvl_us = strtol(interval_str, NULL, 0);

	ldmsd_task_start(&prdcr->task, prdcr_task_cb, prdcr,
			 LDMSD_TASK_F_IMMEDIATE,
			 prdcr->conn_intrvl_us, 0);
	sprintf(replybuf, "0\n");
out_1:
	ldmsd_prdcr_unlock(prdcr);
	ldmsd_prdcr_put(prdcr);
out_0:
	return 0;
}

int cmd_prdcr_stop(char *replybuf, struct attr_value_list *avl, struct attr_value_list *kwl)
{
	char *prdcr_name;

	prdcr_name = av_value(avl, "name");
	if (!prdcr_name) {
		sprintf(replybuf, "%dThe producer name must be specified\n", EINVAL);
		goto out_0;
	}
	ldmsd_prdcr_t prdcr = ldmsd_prdcr_find(prdcr_name);
	if (!prdcr) {
		sprintf(replybuf, "%dThe producer specified does not exist\n", ENOENT);
		goto out_0;
	}
	ldmsd_prdcr_lock(prdcr);
	if (prdcr->conn_state == LDMSD_PRDCR_STATE_STOPPED) {
		sprintf(replybuf, "%dThe producer is already stopped\n", EBUSY);
		goto out_1;
	}
	if (prdcr->xprt)
		ldms_xprt_close(prdcr->xprt);
	ldmsd_task_stop(&prdcr->task);
	ldmsd_task_join(&prdcr->task);
	prdcr->conn_state = LDMSD_PRDCR_STATE_STOPPED;
	sprintf(replybuf, "0\n");
out_1:
	ldmsd_prdcr_unlock(prdcr);
	ldmsd_prdcr_put(prdcr);
out_0:
	return 0;
}

int cmd_prdcr_start_regex(char *replybuf, struct attr_value_list *avl, struct attr_value_list *kwl)
{
	int rc;
	regex_t regex;
	ldmsd_prdcr_t prdcr;
	char *prdcr_regex, *interval_str;

	prdcr_regex = av_value(avl, "regex");
	if (!prdcr_regex) {
		sprintf(replybuf, "%dA producer regular expression must be specified\n", EINVAL);
		goto out_0;
	}
	if (ldmsd_compile_regex(&regex, prdcr_regex, replybuf, sizeof(replybuf)))
		goto out_0;
	interval_str = av_value(avl, "interval"); /* Can be null if we're not changing it */

	ldmsd_cfg_lock(LDMSD_CFGOBJ_PRDCR);
	for (prdcr = ldmsd_prdcr_first(); prdcr; prdcr = ldmsd_prdcr_next(prdcr)) {
		rc = regexec(&regex, prdcr->obj.name, 0, NULL, 0);
		if (rc)
			continue;
		ldmsd_prdcr_lock(prdcr);
		if (prdcr->conn_state == LDMSD_PRDCR_STATE_STOPPED) {
			prdcr->conn_state = LDMSD_PRDCR_STATE_DISCONNECTED;
			if (interval_str)
				prdcr->conn_intrvl_us = strtol(interval_str, NULL, 0);
			ldmsd_task_start(&prdcr->task, prdcr_task_cb, prdcr,
					 LDMSD_TASK_F_IMMEDIATE,
					 prdcr->conn_intrvl_us, 0);
		}
		ldmsd_prdcr_unlock(prdcr);
	}
	ldmsd_cfg_unlock(LDMSD_CFGOBJ_PRDCR);
	regfree(&regex);
	sprintf(replybuf, "0\n");
out_0:
	return 0;
}

int cmd_prdcr_stop_regex(char *replybuf, struct attr_value_list *avl, struct attr_value_list *kwl)
{
	int rc;
	regex_t regex;
	ldmsd_prdcr_t prdcr;
	char *prdcr_regex;

	prdcr_regex = av_value(avl, "regex");
	if (!prdcr_regex) {
		sprintf(replybuf, "%dA producer regular expression must be specified\n", EINVAL);
		goto out_0;
	}
	if (ldmsd_compile_regex(&regex, prdcr_regex, replybuf, sizeof(replybuf)))
		goto out_0;
	ldmsd_cfg_lock(LDMSD_CFGOBJ_PRDCR);
	for (prdcr = ldmsd_prdcr_first(); prdcr; prdcr = ldmsd_prdcr_next(prdcr)) {
		rc = regexec(&regex, prdcr->obj.name, 0, NULL, 0);
		if (rc)
			continue;
		ldmsd_prdcr_lock(prdcr);
		if (prdcr->conn_state != LDMSD_PRDCR_STATE_STOPPED) {
			if (prdcr->xprt)
				ldms_xprt_close(prdcr->xprt);
			ldmsd_task_stop(&prdcr->task);
			ldmsd_task_join(&prdcr->task);
			prdcr->conn_state = LDMSD_PRDCR_STATE_STOPPED;
		}
		ldmsd_prdcr_unlock(prdcr);
	}
	ldmsd_cfg_unlock(LDMSD_CFGOBJ_PRDCR);
	regfree(&regex);
	sprintf(replybuf, "0\n");
	ldmsd_prdcr_put(prdcr);
out_0:
	return 0;
}

int cmd_prdcr_del(char *replybuf, struct attr_value_list *avl, struct attr_value_list *kwl)
{
	char *prdcr_name;
	prdcr_name = av_value(avl, "name");
	if (!prdcr_name) {
		sprintf(replybuf, "%dThe prdcr name must be specified\n", EINVAL);
		goto out_0;
	}
	ldmsd_prdcr_t prdcr = ldmsd_prdcr_find(prdcr_name);
	if (!prdcr) {
		sprintf(replybuf, "%dThe producer specified does not exist\n", ENOENT);
		goto out_0;
	}
	ldmsd_prdcr_lock(prdcr);
	if (prdcr->conn_state != LDMSD_PRDCR_STATE_STOPPED) {
		sprintf(replybuf, "%dConfiguration changes cannot be made "
			"while the producer is running\n", EBUSY);
		goto out_1;
	}
	if (ldmsd_cfgobj_refcount(&prdcr->obj) > 2) {
		sprintf(replybuf, "%dThe producer is in use.\n", EBUSY);
		goto out_1;
	}
	/* Make sure any outstanding callbacks are complete */
	ldmsd_task_join(&prdcr->task);
	/* Put the find reference */
	ldmsd_prdcr_put(prdcr);
	/* Drop the lock and drop the create reference */
	ldmsd_prdcr_unlock(prdcr);
	ldmsd_prdcr_put(prdcr);
	sprintf(replybuf, "0\n");
	goto out_0;
out_1:
	ldmsd_prdcr_put(prdcr);
	ldmsd_prdcr_unlock(prdcr);
out_0:
	return 0;
}
