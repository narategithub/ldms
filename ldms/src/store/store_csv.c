/*
 * Copyright (c) 2013 Open Grid Computing, Inc. All rights reserved.
 * Copyright (c) 2013 Sandia Corporation. All rights reserved.
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

#include <ctype.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <linux/limits.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <coll/idx.h>
#include "ldms.h"
#include "ldmsd.h"

#define TV_SEC_COL    0
#define TV_USEC_COL    1
#define GROUP_COL    2
#define VALUE_COL    3


#define MAX_ROLLOVER_STORE_KEYS 20
static idx_t store_idx; //NOTE: this doesnt have an iterator. Hence storekeys.
static char* storekeys[MAX_ROLLOVER_STORE_KEYS]; //FIXME: make this variablesize
static int nstorekeys = 0;
static char *root_path;
static int altheader;
static int id_pos;
static int rollover;
/** rolltype determines how to interpret rollover values > 0. */
static int rolltype;
/** ROLLTYPES documents rolltype and is used in help output. */
#define ROLLTYPES \
"                     1: wake approximately every rollover seconds and roll.\n" \
"                     2: wake daily at rollover seconds after midnight (>=0) and roll.\n" \
"                     3: roll after approximately rollover records are written.\n" \
"                     4: roll after approximately rollover bytes are written.\n"

#define MAXROLLTYPE 4
#define MINROLLTYPE 1
/** default -- do not roll */
#define DEFAULT_ROLLTYPE -1
/** minimum rollover for type 1;
    rolltype==1 and rollover < MIN_ROLL_1 -> rollover = MIN_ROLL_1
    also used for minimum sleep time for type 2;
    rolltype==2 and rollover results in sleep < MIN_ROLL_SLEEPTIME -> skip this roll and do it the next day */
#define MIN_ROLL_1 10
/** minimum rollover for type 3;
    rolltype==3 and rollover < MIN_ROLL_RECORDS -> rollover = MIN_ROLL_RECORDS */
#define MIN_ROLL_RECORDS 3
/** minimum rollover for type 4;
    rolltype==4 and rollover < MIN_ROLL_BYTES -> rollover = MIN_ROLL_BYTES */
#define MIN_ROLL_BYTES 1024
/** Interval to check for passing the record or byte count limits. */
#define ROLL_LIMIT_INTERVAL 60

static struct column_step {
	int begin;
	int end;
	int step;
} cs = {0,0,0};


/* help for column output orders */
#define ORDERTYPES \
"                     forward: metric columns ordered as added in sampler.\n" \
"                     reverse: columns reverse of order added in sampler.\n" \
"                     alnum: sorted per man page (not implemented)\n"

static ldmsd_msg_log_f msglog;
static pthread_t rothread;

#define _stringify(_x) #_x
#define stringify(_x) _stringify(_x)

#define LOGFILE "/var/log/store_csv.log"

/*
 * store_csv - csv compid, value pairs UNLESS id_pos is specified.
 * In that case, two options for which metric's comp id
 * will be used. 0 = last metric added to the sampler,
 * 1 = first metric added to the sampler (order because of the inverse mvec).
 * Interpretation has slightly changed becuase of the sequence options but
 * the values of 0/1  and which metric have not.
 */

struct csv_store_handle {
	struct ldmsd_store *store;
	char *path;
	FILE *file;
	FILE *headerfile;
	int printheader;
	char *store_key;
	pthread_mutex_t lock;
	void *ucontext;
	int64_t store_count;
	int64_t byte_count;

};

static pthread_mutex_t cfg_lock ;

/* Time-based rolltypes will always roll the files when this
function is called.
Volume-based rolltypes must check and shortcircuit within this
function.
*/
static int handleRollover(){
	//get the config lock
	//for every handle we have, do the rollover

	int i;
	struct csv_store_handle *s_handle;

	pthread_mutex_lock(&cfg_lock);

	time_t appx = time(NULL);

	for (i = 0; i < nstorekeys; i++){
		if (storekeys[i] != NULL){
			s_handle = idx_find(store_idx, (void *)storekeys[i], strlen(storekeys[i]));
			if (s_handle){
				FILE* nhfp = NULL;
				FILE* nfp = NULL;
				char tmp_path[PATH_MAX];
				char tmp_headerpath[PATH_MAX];
				//if we've got here then we've called new_store, but it might be closed
				pthread_mutex_lock(&s_handle->lock);
				switch (rolltype) {
				case 1:
					break;
				case 2:
					break;
				case 3:
					if (s_handle->store_count < rollover)  {
						pthread_mutex_unlock(&s_handle->lock);
						continue;
					} else {
						s_handle->store_count = 0;
					}
					break;
				case 4:
					if (s_handle->byte_count < rollover) {
						pthread_mutex_unlock(&s_handle->lock);
						continue;
					} else {
						s_handle->byte_count = 0;
					}
					break;
				default:
					msglog(LDMS_LDEBUG, "Error: unexpected rolltype in store(%d)\n",
						rolltype);
					break;
				}


				if (s_handle->file)
					fflush(s_handle->file);
				if (s_handle->headerfile)
					fflush(s_handle->headerfile);

				//re name: if got here, then rollover requested
				snprintf(tmp_path, PATH_MAX, "%s.%d",
					 s_handle->path, (int) appx);
				nfp = fopen(tmp_path, "a+");
				if (!nfp){
					//we cant open the new file, skip
					msglog(LDMS_LDEBUG, "Error: cannot open file <%s>\n",
					       tmp_path);
					pthread_mutex_unlock(&s_handle->lock);
					continue;
				}
				if (altheader){
					//re name: if got here, then rollover requested
					snprintf(tmp_headerpath, PATH_MAX,
						 "%s.HEADER.%d",
						 s_handle->path, (int)appx);
					/* truncate a separate headerfile if it exists */
					nhfp = fopen(tmp_headerpath, "w");
					if (!nhfp){
						fclose(nfp);
						msglog(LDMS_LDEBUG, "Error: cannot open file <%s>\n",
						       tmp_headerpath);
					}
				} else {
					nhfp = fopen(tmp_path, "a+");
					if (!nhfp){
						fclose(nfp);
						msglog(LDMS_LDEBUG, "Error: cannot open file <%s>\n",
						       tmp_path);
					}
				}
				if (!nhfp) {
					pthread_mutex_unlock(&s_handle->lock);
					continue;
				}

				//close and swap
				if (s_handle->file)
					fclose(s_handle->file);
				if (s_handle->headerfile)
					fclose(s_handle->headerfile);
				s_handle->file = nfp;
				s_handle->headerfile = nhfp;
				s_handle->printheader = 1;
				pthread_mutex_unlock(&s_handle->lock);
			}
		}
	}

	pthread_mutex_unlock(&cfg_lock);

	return 0;

}

static void* rolloverThreadInit(void* m){
	//if got here, then rollover requested

	while(1){
		int tsleep;
		switch (rolltype) {
		case 1:
			tsleep = (rollover < MIN_ROLL_1) ?
				 MIN_ROLL_1 : rollover;
			break;
		case 2: {
				time_t rawtime;
				struct tm *info;

				time( &rawtime );
				info = localtime( &rawtime );
				int secSinceMidnight = info->tm_hour*3600 + 
					info->tm_min*60 + info->tm_sec;
				tsleep = 86400 - secSinceMidnight + rollover;
				if (tsleep < MIN_ROLL_1){
				/* if we just did a roll then skip this one */
					tsleep+=86400;
				}
			}
			break;
		case 3:
			if (rollover < MIN_ROLL_RECORDS)
				rollover = MIN_ROLL_RECORDS;
			tsleep = ROLL_LIMIT_INTERVAL;
			break;
		case 4:
			if (rollover < MIN_ROLL_BYTES)
				rollover = MIN_ROLL_BYTES;
			tsleep = ROLL_LIMIT_INTERVAL;
			break;
		default:
			tsleep = 60;
			break;
		}
		sleep(tsleep);
		handleRollover();
	}

	return NULL;
}


/**
 * \brief Configuration
 */
static int config(struct attr_value_list *kwl, struct attr_value_list *avl)
{
	char *value;
	char *altvalue;
	char *ivalue;
	char *rvalue;
	int roll = -1;
	int rollmethod = DEFAULT_ROLLTYPE;
	int ipos = -1;

	value = av_value(avl, "path");
	if (!value)
		return EINVAL;

	altvalue = av_value(avl, "altheader");

	ivalue = av_value(avl, "id_pos");
	if (ivalue){
		ipos = atoi(ivalue);
		if ((ipos < 0) || (ipos > 1))
			return EINVAL;
	}

	rvalue = av_value(avl, "rollover");
	if (rvalue){
		roll = atoi(rvalue);
		if (roll < 0)
			return EINVAL;
	}

	rvalue = av_value(avl, "rolltype");
	if (rvalue){
		if (roll < 0) /* rolltype not valid without rollover also */
			return EINVAL;
		rollmethod = atoi(rvalue);
		if (rollmethod < MINROLLTYPE )
			return EINVAL;
		if (rollmethod > MAXROLLTYPE)
			return EINVAL;
	}

	rvalue = av_value(avl, "sequence");
	cs.step = 1; //reverse is the default for historical reasons (mvec causes the metrics to be reversed)
	if (rvalue){
		switch (rvalue[0]) {
		case 'f':
			if (strcmp(rvalue,"forward")==0) {
				cs.step = -1;
			}
			break;
		case 'a':
			if (strcmp(rvalue,"alnum")==0) {
				msglog(LDMS_LERROR,"store_csv sequence alnum"
					" unsupported. using reverse.\n");
			}
			/* fallthru */
		default:
			if (strcmp(rvalue,"reverse")!=0) {
				msglog(LDMS_LERROR,"store_csv sequence=reverse"
					" assumed. %s unknown\n",rvalue);
			}
			break;
		}
	}

	pthread_mutex_lock(&cfg_lock);
	if (root_path)
		free(root_path);

	root_path = strdup(value);

	id_pos = ipos;

	rollover = roll;
	if (rollmethod >= MINROLLTYPE) {
		rolltype = rollmethod;
		pthread_create(&rothread, NULL, rolloverThreadInit, NULL);
	}

	if (altvalue)
		altheader = atoi(altvalue);
	else
		altheader = 0;

	pthread_mutex_unlock(&cfg_lock);
	if (!root_path)
		return ENOMEM;
	return 0;
}

static void term(void)
{
}

static const char *usage(void)
{
	return  "    config name=store_csv path=<path> altheader=<0/1> id_pos=<0/1>\n"
		"         - Set the root path for the storage of csvs.\n"
		"           path      The path to the root of the csv directory\n"
		"         - altheader Header in a separate file (optional, default 0)\n"
		"         - rollover  Greater than or equal to zero; enables file rollover and sets interval\n"
		"         - rolltype  [1-n] Defines the policy used to schedule rollover events.\n"
		ROLLTYPES
		"         - id_pos    Use only one comp_id either first metric added to the sampler (1) or last added (0)\n"
		"                     (Optional default use all compid)\n"
		"         - sequence  Determine the metric column ordering:\n"
		ORDERTYPES
		;
}

/*
 * currently store based on set name
   (all metrics for a set in the same store)
 */
static ldmsd_store_handle_t get_store(const char *container)
{
	ldmsd_store_handle_t s_handle;
	pthread_mutex_lock(&cfg_lock);
	s_handle = idx_find(store_idx, (void *)container, strlen(container));
	pthread_mutex_unlock(&cfg_lock);
	return s_handle;
}

static void *get_ucontext(ldmsd_store_handle_t _s_handle)
{
	struct csv_store_handle *s_handle = _s_handle;
	return s_handle->ucontext;
}

static
void get_loop_limits(int num_metrics) {
	switch (cs.step) {
	case 1:
		cs.begin = 0;
		cs.end = num_metrics;
		break;
	case -1:
		cs.begin = num_metrics - 1;
		cs.end = -1;
		break;
	default:
		msglog(LDMS_LERROR, "store_csv sequence bug in loop (%d)\n",
			cs.step);
		cs.begin = 0;
		cs.end = 0;
	}
}

static int print_header(struct csv_store_handle *s_handle,
			ldms_mvec_t mvec)
{

	/* Only called from Store which already has the lock */
	FILE* fp = s_handle->headerfile;
	const char* name;
	int i;

	s_handle->printheader = 0;
	if (!fp){
		msglog(LDMS_LDEBUG,"Cannot print header for store_csv. No headerfile\n");
		return EINVAL;
	}

	/* This allows optional loading a float (Time) into an int field and
	   retaining usec as a separate field */
	fprintf(fp, "#Time, Time_usec");

	int num_metrics = ldms_mvec_get_count(mvec); 
	get_loop_limits(num_metrics);

	if (id_pos < 0) {
		for (i = cs.begin; i != cs.end; i += cs.step) {
			name = ldms_get_metric_name(mvec->v[i]);
			fprintf(fp, ", %s.CompId, %s.value",
				name, name);
		}
	} else {
		fprintf(fp, ", CompId");
		for (i = cs.begin; i != cs.end; i += cs.step) {
			name = ldms_get_metric_name(mvec->v[i]);
			fprintf(fp, ", %s", name);
		}
	}
	fprintf(fp, "\n");


	/* Flush for the header, whether or not it is the data file as well */
	fflush(fp);

	fclose(s_handle->headerfile);
	s_handle->headerfile = 0;

	return 0;
}

static ldmsd_store_handle_t
new_store(struct ldmsd_store *s, const char *comp_type, const char* container,
		struct ldmsd_store_metric_index_list *list, void *ucontext)
{
	struct csv_store_handle *s_handle;
	int add_handle = 0;
	int rc = 0;

	pthread_mutex_lock(&cfg_lock);
	s_handle = idx_find(store_idx, (void *)container, strlen(container));
	if (!s_handle) {
		char tmp_path[PATH_MAX];

		//append or create
		snprintf(tmp_path, PATH_MAX, "%s/%s", root_path, comp_type);
		rc = mkdir(tmp_path, 0777);
		if ((rc != 0) && (errno != EEXIST)){
			msglog(LDMS_LDEBUG,"Error: cannot create dir '%s'\n", tmp_path);
			goto out;
		}
		snprintf(tmp_path, PATH_MAX, "%s/%s/%s", root_path, comp_type,
				container);


		s_handle = calloc(1, sizeof *s_handle);
		if (!s_handle)
			goto out;
		s_handle->ucontext = ucontext;
		s_handle->store = s;
		add_handle = 1;

		pthread_mutex_init(&s_handle->lock, NULL);

		s_handle->path = strdup(tmp_path);
		if (!s_handle->path) {
			/* Take the lock becauase we will unlock in the err path */
			pthread_mutex_lock(&s_handle->lock);
			goto err1;
		}

		s_handle->store_key = strdup(container);
		if (!s_handle->store_key) {
			/* Take the lock becauase we will unlock in the err path */
			pthread_mutex_lock(&s_handle->lock);
			goto err2;
		}

		s_handle->printheader = 1;
		s_handle->store_count = 0;
		s_handle->byte_count = 0;
	}

	/* Take the lock in case its a store that has been closed */
	pthread_mutex_lock(&s_handle->lock);

	/* For both actual new store and reopened store, open the data file */
	char tmp_path[PATH_MAX];
	time_t appx = time(NULL);
	if (rolltype >= MINROLLTYPE){
		//append the files with epoch. assume wont collide to the sec.
		snprintf(tmp_path, PATH_MAX, "%s.%d",
			 s_handle->path, (int)appx);
	} else {
		snprintf(tmp_path, PATH_MAX, "%s",
			 s_handle->path);
	}

	if (!s_handle->file) {
		s_handle->file = fopen(tmp_path, "a+");
	}
	if (!s_handle->file)
		goto err3;

	/* Only bother to open the headerfile if we have to print the header */
	if (s_handle->printheader && !s_handle->headerfile){
		if (altheader) {
			char tmp_headerpath[PATH_MAX];
			if (rolltype >= MINROLLTYPE){
				snprintf(tmp_headerpath, PATH_MAX,
					 "%s.HEADER.%d", s_handle->path, (int)appx);
			} else {
				snprintf(tmp_headerpath, PATH_MAX,
					 "%s.HEADER", s_handle->path);
			}
			/* truncate a separate headerfile if exists */
			s_handle->headerfile = fopen(tmp_headerpath, "w");
		} else {
			s_handle->headerfile = fopen(tmp_path, "a+");
		}

		if (!s_handle->headerfile)
			goto err4;
	}

	if (add_handle) {
		if (nstorekeys == (MAX_ROLLOVER_STORE_KEYS-1)){
			msglog(LDMS_LDEBUG, "Error: Exceeded max store keys\n");
			goto err5;
		} else {
			idx_add(store_idx, (void *)container,
				strlen(container), s_handle);
			storekeys[nstorekeys++] = strdup(container);
		}
	}

	pthread_mutex_unlock(&s_handle->lock);
	goto out;

err5:
err4:
	fclose(s_handle->file);
	s_handle->file = NULL;
err3:
	free(s_handle->store_key);
err2:
	free(s_handle->path);
err1:
	pthread_mutex_unlock(&s_handle->lock);
	pthread_mutex_destroy(&s_handle->lock);
	free(s_handle);
	s_handle = NULL;
out:
	pthread_mutex_unlock(&cfg_lock);
	return s_handle;
}

static int store(ldmsd_store_handle_t _s_handle, ldms_set_t set, ldms_mvec_t mvec)
{
	const struct ldms_timestamp *ts = ldms_get_timestamp(set);
	uint64_t comp_id;
	struct csv_store_handle *s_handle;
	s_handle = _s_handle;
	if (!s_handle)
		return EINVAL;

	pthread_mutex_lock(&s_handle->lock);
	if (!s_handle->file){
		msglog(LDMS_LDEBUG,"Cannot insert values for <%s>: file is closed\n",
				s_handle->path);
		pthread_mutex_unlock(&s_handle->lock);
		return EPERM;
	}

	if (s_handle->printheader)
		print_header(s_handle, mvec);
	fprintf(s_handle->file, "%"PRIu32".%06"PRIu32 ", %"PRIu32,
		ts->sec, ts->usec, ts->usec);

	/* mvec comes to the store as the inverse of how they added to the sampler which is also the inverse of ldms_ls -l display */
	int num_metrics = ldms_mvec_get_count(mvec); 
	get_loop_limits(num_metrics);
	if (id_pos < 0){
		int i, rc;
		for (i = cs.begin; i != cs.end; i += cs.step) {
			comp_id = ldms_get_user_data(mvec->v[i]);
			rc = fprintf(s_handle->file, ", %" PRIu64 ", %" PRIu64,
				     comp_id, ldms_get_u64(mvec->v[i]));
			if (rc < 0)
				msglog(LDMS_LDEBUG,"store_csv: Error %d writing to '%s'\n",
				       rc, s_handle->path);
			else
				s_handle->byte_count += rc;
		}
		fprintf(s_handle->file,"\n");
		s_handle->byte_count += 1;
	} else {
		int i, rc;

		if (num_metrics > 0){
			i = (id_pos == 0)? 0: (num_metrics-1);
			rc = fprintf(s_handle->file, ", %" PRIu64,
				ldms_get_user_data(mvec->v[i]));
			if (rc < 0)
				msglog(LDMS_LDEBUG,"store_csv: Error %d writing to '%s'\n",
				       rc, s_handle->path);
			else
				s_handle->byte_count += rc;
		}
		for (i = cs.begin; i != cs.end; i += cs.step) {
			rc = fprintf(s_handle->file, ", %" PRIu64, ldms_get_u64(mvec->v[i]));
			if (rc < 0)
				msglog(LDMS_LDEBUG,"store_csv: Error %d writing to '%s'\n",
				       rc, s_handle->path);
			else
				s_handle->byte_count += rc;
		}
		fprintf(s_handle->file,"\n");
		s_handle->byte_count += 1;
	}

	s_handle->store_count++;
	pthread_mutex_unlock(&s_handle->lock);

	return 0;
}

static int flush_store(ldmsd_store_handle_t _s_handle)
{
	struct csv_store_handle *s_handle = _s_handle;
	if (!s_handle) {
		msglog(LDMS_LDEBUG,"store_csv: flush error.\n");
		return -1;
	}
	pthread_mutex_lock(&s_handle->lock);
	fflush(s_handle->file);
	pthread_mutex_unlock(&s_handle->lock);
	return 0;
}

static void close_store(ldmsd_store_handle_t _s_handle)
{
	struct csv_store_handle *s_handle = _s_handle;
	if (!s_handle)
		return;

	pthread_mutex_lock(&s_handle->lock);
	if (s_handle->file)
		fclose(s_handle->file);
	s_handle->file = NULL;
	if (s_handle->headerfile)
		fclose(s_handle->headerfile);
	s_handle->headerfile = NULL;
	pthread_mutex_unlock(&s_handle->lock);
}

static void destroy_store(ldmsd_store_handle_t _s_handle)
{

	int i;

	pthread_mutex_lock(&cfg_lock);
	struct csv_store_handle *s_handle = _s_handle;
	if (!s_handle) {
		pthread_mutex_unlock(&cfg_lock);
		return;
	}

	pthread_mutex_lock(&s_handle->lock);
	msglog(LDMS_LDEBUG,"Destroying store_csv with path <%s>\n", s_handle->path);
	fflush(s_handle->file);
	s_handle->store = NULL;
	if (s_handle->path)
		free(s_handle->path);
	s_handle->path = NULL;
	if (s_handle->ucontext)
		free(s_handle->ucontext);
	s_handle->ucontext = NULL;
	if (s_handle->file)
		fclose(s_handle->file);
	s_handle->file = NULL;
	if (s_handle->headerfile)
		fclose(s_handle->headerfile);
	s_handle->headerfile = NULL;

	idx_delete(store_idx, s_handle->store_key, strlen(s_handle->store_key));

	for (i = 0; i < nstorekeys; i++){
		if (strcmp(storekeys[i], s_handle->store_key) == 0){
			free(storekeys[i]);
			storekeys[i] = 0;
			//FIXME: note the space is still there...
			break;
		}
	}
	if (s_handle->store_key)
		free(s_handle->store_key);
	pthread_mutex_unlock(&s_handle->lock);
	pthread_mutex_destroy(&s_handle->lock);
	pthread_mutex_unlock(&cfg_lock);
	free(s_handle);
}

static struct ldmsd_store store_csv = {
	.base = {
			.name = "csv",
			.term = term,
			.config = config,
			.usage = usage,
	},
	.get = get_store,
	.new = new_store,
	.destroy = destroy_store,
	.get_context = get_ucontext,
	.store = store,
	.flush = flush_store,
	.close = close_store,
};

struct ldmsd_plugin *get_plugin(ldmsd_msg_log_f pf)
{
	msglog = pf;
	return &store_csv.base;
}

static void __attribute__ ((constructor)) store_csv_init();
static void store_csv_init()
{
	store_idx = idx_create();
	pthread_mutex_init(&cfg_lock, NULL);
}

static void __attribute__ ((destructor)) store_csv_fini(void);
static void store_csv_fini()
{
	pthread_mutex_destroy(&cfg_lock);
	idx_destroy(store_idx);
}
