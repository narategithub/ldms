/* -*- c-basic-offset: 8 -*-
 * Copyright (c) 2022 National Technology & Engineering Solutions
 * of Sandia, LLC (NTESS). Under the terms of Contract DE-NA0003525 with
 * NTESS, the U.S. Government retains certain rights in this software.
 * Copyright (c) 2022 Open Grid Computing, Inc. All rights reserved.
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

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>

#include <openssl/evp.h>

#include <jansson.h>
#include "coll/rbt.h"

#include "ldmsd.h"
#include "ldmsd_request.h"

static ovis_log_t mylog;

static ldmsd_decomp_t __decomp_static_config(ldmsd_strgp_t strgp,
			json_t *cfg, ldmsd_req_ctxt_t reqc);
static int __decomp_static_decompose(ldmsd_strgp_t strgp, ldms_set_t set,
				     ldmsd_row_list_t row_list, int *row_count);
static void __decomp_static_release_rows(ldmsd_strgp_t strgp,
					 ldmsd_row_list_t row_list);
static void __decomp_static_release_decomp(ldmsd_strgp_t strgp);

struct ldmsd_decomp_s __decomp_static = {
	.config = __decomp_static_config,
	.decompose = __decomp_static_decompose,
	.release_rows = __decomp_static_release_rows,
	.release_decomp = __decomp_static_release_decomp,
};

ldmsd_decomp_t get()
{
	mylog = ovis_log_register("store.decomp.static", "Messages for the static decomposition");
	if (!mylog) {
		ovis_log(NULL, OVIS_LWARN, "Failed to create decomp_static's "
					   "log subsystem. Error %d.\n", errno);
	}
	return &__decomp_static;
}

/* ==== Helpers ==== */

static inline int __ldms_vsz(enum ldms_value_type t)
{
	switch (t) {
	case LDMS_V_CHAR:
	case LDMS_V_U8:
	case LDMS_V_S8:
	case LDMS_V_CHAR_ARRAY:
	case LDMS_V_U8_ARRAY:
	case LDMS_V_S8_ARRAY:
		return sizeof(char);
	case LDMS_V_U16:
	case LDMS_V_S16:
	case LDMS_V_U16_ARRAY:
	case LDMS_V_S16_ARRAY:
		return sizeof(int16_t);
	case LDMS_V_U32:
	case LDMS_V_S32:
	case LDMS_V_U32_ARRAY:
	case LDMS_V_S32_ARRAY:
		return sizeof(int32_t);
	case LDMS_V_U64:
	case LDMS_V_S64:
	case LDMS_V_U64_ARRAY:
	case LDMS_V_S64_ARRAY:
		return sizeof(int64_t);
	case LDMS_V_F32:
	case LDMS_V_F32_ARRAY:
		return sizeof(float);
	case LDMS_V_D64:
	case LDMS_V_D64_ARRAY:
		return sizeof(double);
	default:
		assert(0 == "Unsupported type");
	}
	return -1;
}


/* ==== generic decomp ==== */
/* convenient macro to put error message in both ldmsd log and `reqc` */
#define DECOMP_ERR(_reqc_, rc, fmt, ...) do { \
		ovis_log(mylog, OVIS_LERROR, fmt, ##__VA_ARGS__); \
		if (_reqc_) { \
			(_reqc_)->errcode = rc; \
			Snprintf(&(_reqc_)->line_buf, &(_reqc_)->line_len, fmt, ##__VA_ARGS__); \
		} \
	} while (0)

/* common index config descriptor */
typedef struct __decomp_index_s {
	char *name;
	int col_count;
	int *col_idx; /* dst columns composing the index */
} *__decomp_index_t;

/* ==== static decomposition === */

/* describing a src-dst column pair */
typedef struct __decomp_static_col_cfg_s {
	/* Set in config() */
	char *src;		/* name of the metric */
	char *rec_member;	/* name of the record metric (if applicable) */
	char *dst;		/* destination (storage side) column name */

	/* Set in resolve_mid() when 1st instance of set is available */
	enum ldms_value_type type; /* value type */
	int array_len;		/* length of the array, if type is array */
	ldms_mval_t fill;	/* fill value */
	int fill_len;		/* if fill is an array */
	union ldms_value _fill; /* storing a non-array primitive fill value */
	json_t *jcol;		/* JSON configuration for this column */
} *__decomp_static_col_cfg_t;

typedef struct __decomp_static_row_cfg_s {
	char *schema_name; /* row schema name */
	int col_count;
	int idx_count;
	__decomp_static_col_cfg_t cols; /* array of struct */
	__decomp_index_t idxs; /* array of struct */
	struct ldms_digest_s schema_digest;
	size_t row_sz;
	json_t *jrow;
	struct rbt mid_rbt; /* collection of metric IDs mapping */
} *__decomp_static_row_cfg_t;

typedef struct __decomp_static_cfg_s {
	struct ldmsd_decomp_s decomp;
	int row_count;
	json_t *jcfg;
	struct __decomp_static_row_cfg_s rows[OVIS_FLEX];
} *__decomp_static_cfg_t;

typedef struct __decomp_static_mid_rbn_s {
	struct rbn rbn;
	struct ldms_digest_s ldms_digest;
	int col_count;
	struct {
		int mid;
		int rec_mid;
		enum ldms_value_type mtype;
		enum ldms_value_type rec_mtype;
	} col_mids[OVIS_FLEX];
} *__decomp_static_mid_rbn_t;

int __mid_rbn_cmp(void *tree_key, const void *key)
{
	return memcmp(tree_key, key, sizeof(struct ldms_digest_s));
}

/* str - int pair */
struct str_int_s {
	const char *str;
	int i;
};

struct str_int_tbl_s {
	int len;
	struct str_int_s ent[OVIS_FLEX];
};

int str_int_cmp(const void *a, const void *b)
{
	const struct str_int_s *sa = a, *sb = b;
	return strcmp(sa->str, sb->str);
}

static void __decomp_static_cfg_free(__decomp_static_cfg_t dcfg)
{
	int i, j;
	struct __decomp_static_row_cfg_s *drow;
	struct __decomp_static_col_cfg_s *dcol;
	for (i = 0; i < dcfg->row_count; i++) {
		drow = &dcfg->rows[i];
		/* cols */
		for (j = 0; j < drow->col_count; j++) {
			dcol = &drow->cols[j];
			free(dcol->src);
			free(dcol->dst);
			free(dcol->rec_member);
			if (dcol->fill != &dcol->_fill)
				free(dcol->fill);
		}
		free(drow->cols);
		/* idxs */
		for (j = 0; j < drow->idx_count; j++) {
			free(drow->idxs[j].name);
			free(drow->idxs[j].col_idx);
		}
		free(drow->idxs);
		/* schema */
		free(drow->schema_name);
	}
	free(dcfg);
}

static void
__decomp_static_release_decomp(ldmsd_strgp_t strgp)
{
	if (strgp->decomp) {
		__decomp_static_cfg_free((void*)strgp->decomp);
		strgp->decomp = NULL;
	}
}

static ldmsd_decomp_t
__decomp_static_config(ldmsd_strgp_t strgp, json_t *jcfg,
		       ldmsd_req_ctxt_t reqc )
{
	json_t *jval;
	json_t *jrows, *jcols, *jidxs, *jidx_cols;
	json_t *jrow, *jcol, *jidx;
	__decomp_static_cfg_t dcfg = NULL;
	__decomp_static_row_cfg_t drow;
	__decomp_static_col_cfg_t dcol;
	__decomp_index_t didx;
	int i, j;

	json_incref(jcfg);

	jrows = json_object_get(jcfg, "rows");
	if (!json_is_array(jrows)) {
		DECOMP_ERR(reqc, errno,
			   "strgp '%s': The 'rows' attribute is missing, "
			   "or its value is not an array.\n",
			   strgp->obj.name);
		goto err_0;
	}
	dcfg = calloc(1, sizeof(*dcfg) + json_array_size(jrows) * sizeof(dcfg->rows[0]));
	if (!dcfg) {
		DECOMP_ERR(reqc, errno, "out of memory\n");
		goto err_0;
	}
	dcfg->jcfg = jcfg;
	dcfg->decomp = __decomp_static;

	/* for each row schema */
	json_array_foreach(jrows, i, jrow) {
		if (!json_is_object(jrow)) {
			DECOMP_ERR(reqc, EINVAL,
				   "strgp '%s': row '%d': "
				   "The row entry must be a dictionary.\n",
				   strgp->obj.name, i);
			goto err_0;
		}

		drow = &dcfg->rows[i];
		drow->jrow = jrow;
		drow->row_sz = sizeof(struct ldmsd_row_s);
		rbt_init(&drow->mid_rbt, __mid_rbn_cmp);

		/* schema name */
		jval = json_object_get(jrow, "schema");
		if (!json_is_string(jval)) {
			DECOMP_ERR(reqc, EINVAL,
				   "strgp '%s': row '%d': "
				   "row['schema'] attribute is required"
				   "and must be a string.\n",
				   strgp->obj.name, i);
			goto err_0;
		}
		drow->schema_name = strdup(json_string_value(jval));
		if (!drow->schema_name)
			goto err_enomem;

		/* columns */
		jcols = json_object_get(jrow, "cols");
		if (!json_is_array(jcols)) {
			DECOMP_ERR(reqc, EINVAL,
				   "strgp '%s': row '%d': "
				   "row['cols'] array is required "
				   "and must be an array.\n",
				   strgp->obj.name, i);
			goto err_0;
		}
		drow->col_count = json_array_size(jcols);
		drow->cols = calloc(1, drow->col_count * sizeof(drow->cols[0]));
		if (!drow->cols)
			goto err_enomem;
		drow->row_sz += drow->col_count * sizeof(struct ldmsd_col_s);
		/* for each column */
		json_array_foreach(jcols, j, jcol) {
			dcol = &drow->cols[j];
			if (!json_is_object(jcol)) {
				DECOMP_ERR(reqc, EINVAL,
					   "strgp '%s': row '%d': col '%d': "
					   "A column must be a dictionary.\n",
					   strgp->obj.name, i, j);
				goto err_0;
			}
			dcol->jcol = jcol;
			jval = json_object_get(jcol, "src");
			if (!json_is_string(jval)) {
				DECOMP_ERR(reqc, EINVAL, "strgp '%s': row '%d': col '%d': "
						"column['src'] is required and must be a string\n",
						strgp->obj.name, i, j);
				goto err_0;
			}
			char *rec_member, *src;
			char *src_buf = strdup(json_string_value(jval));
			if (!src_buf)
				goto err_enomem;

			if (NULL != (src = strstr(src_buf, "("))) {
				/* Parse the source as src(rec_member). */
				src = strdup(src_buf);
				rec_member = strdup(src_buf);

				int cnt = sscanf(src_buf, "%[^(](%[^)]", src, rec_member);
				if (cnt != 2) {
					DECOMP_ERR(reqc, EINVAL,
						   "strgp '%s': row '%d': col '%d': "
						   "column['src'] is incorrectly "
						   "formatted. A record member must "
						   "be formatted as "
						   "src-metric(record_member)\n",
						   strgp->obj.name, i, j);
					goto err_0;
				}
				dcol->src = src;
				dcol->rec_member = rec_member;
				free(src_buf);
			} else {
				dcol->src = src_buf;
			}

			if (0 == strcmp("timestamp", dcol->src)) {
				/* add space for the meta timestamp metric */
				drow->row_sz += sizeof(union ldms_value);
			}

			jval = json_object_get(jcol, "rec_member");
			if (jval) {
				if (!json_is_string(jval)) {
					DECOMP_ERR(reqc, EINVAL,
						   "strgp '%s': row '%d': col[dst] '%s': "
						   "column['rec_member'] must be a string\n",
						   strgp->obj.name, i, dcol->dst);
					goto err_0;
				}
				if (dcol->rec_member) {
					DECOMP_ERR(reqc, EINVAL,
						   "strgp '%s': warning : "
						   "row '%d': col[src] '%s': "
						   "col['rec_member'] is overriding "
						   "col['src'] formatting.\n",
						   strgp->obj.name, i, dcol->src);
					free(dcol->rec_member);
				}
				dcol->rec_member = strdup(json_string_value(jval));
				if (!dcol->rec_member)
					goto err_enomem;
			}
			jval = json_object_get(jcol, "dst");
			if (!jval) {
				/* This will be filled in in the
				 * decompose function because records
				 * will need to be handled
				 * differently */
				if (!dcol->rec_member)
					dcol->dst = strdup(dcol->src);
				else
					dcol->dst = strdup(dcol->rec_member);
			} else {
				dcol->dst = strdup(json_string_value(jval));
			}

		}
		jidxs = json_object_get(jrow, "indices");
		if (!jidxs)
			goto next_row;
		/* Syntax check the indices dictinoary */
		if (!json_is_array(jidxs)) {
			DECOMP_ERR(reqc, EINVAL,
				   "strgp '%s': row['indices'] must be an array.\n",
				   strgp->obj.name);
			goto err_0;
		}
		drow->idx_count = json_array_size(jidxs);
		drow->idxs = calloc(1, drow->idx_count*sizeof(drow->idxs[0]));
		if (!drow->idxs)
			goto err_enomem;
		drow->row_sz += drow->idx_count * sizeof(ldmsd_row_index_t);

		/* foreach index */
		json_array_foreach(jidxs, j, jidx) {
			didx = &drow->idxs[j];
			if (!json_is_object(jidx)) {
				ovis_log(mylog, OVIS_LERROR,
					 "strgp '%s': an index must be a dictionary.\n",
					 strgp->obj.name);
				goto err_0;
			}
			jval = json_object_get(jidx, "name");
			if (!json_is_string(jval)) {
				ovis_log(mylog, OVIS_LERROR,
					 "strgp '%s': index '%d': "
					 "index['name'] is a required attribute.\n",
					 strgp->obj.name, j);
				goto err_0;
			}
			didx->name = strdup(json_string_value(jval));
			if (!didx->name)
				goto err_enomem;
			jidx_cols = json_object_get(jidx, "cols");
			if (!json_is_array(jidx_cols)) {
				DECOMP_ERR(reqc, EINVAL,
					   "strgp '%s': row '%d': index '%d':"
					   "index['cols'] is required and must be an array.\n",
					   strgp->obj.name, i, j);
				goto err_0;
			}
			didx->col_count = json_array_size(jidx_cols);
			didx->col_idx = calloc(1, didx->col_count*sizeof(didx->col_idx[0]));
			if (!didx->col_idx)
				goto err_enomem;
			drow->row_sz += sizeof(struct ldmsd_row_index_s) +
				didx->col_count * sizeof(ldmsd_col_t);
		}
	next_row:
		dcfg->row_count++;
	}
	return &dcfg->decomp;

 err_enomem:
	DECOMP_ERR(reqc, errno, "Not enough memory\n");
 err_0:
	json_decref(jcfg);
	__decomp_static_cfg_free(dcfg);
	return NULL;
}

static int __prim_fill_from_json(ldms_mval_t v, enum ldms_value_type type,
				 json_t *jent)
{
	switch (type) {
	case LDMS_V_U8:
		v->v_u8 = (uint8_t)json_integer_value(jent);
		break;
	case LDMS_V_S8:
		v->v_s8 = (int8_t)json_integer_value(jent);
		break;
	case LDMS_V_U16:
		v->v_u16 = htole16((uint16_t)json_integer_value(jent));
		break;
	case LDMS_V_S16:
		v->v_s16 = htole16((int16_t)json_integer_value(jent));
		break;
	case LDMS_V_U32:
		v->v_u32 = htole32((uint32_t)json_integer_value(jent));
		break;
	case LDMS_V_S32:
		v->v_s32 = htole32((int32_t)json_integer_value(jent));
		break;
	case LDMS_V_U64:
		v->v_u64 = htole64((uint64_t)json_integer_value(jent));
		break;
	case LDMS_V_S64:
		v->v_s64 = htole64((int64_t)json_integer_value(jent));
		break;
	case LDMS_V_F32:
		v->v_f = htole32((float)json_real_value(jent));
		break;
	case LDMS_V_D64:
		v->v_d = htole64((double)json_real_value(jent));
		break;
	default:
		return EINVAL;
	}
	return 0;
}

static int __array_fill_from_json(__decomp_static_col_cfg_t dcol, json_t *jfill)
{
	int i;
	json_t *ent;
	ldms_mval_t v = dcol->fill;

	json_array_foreach(jfill, i, ent) {
		if (i >= dcol->array_len)
			break;
		switch (dcol->type) {
		case LDMS_V_U8_ARRAY:
			v->a_u8[i] = (uint8_t)json_integer_value(ent);
			break;
		case LDMS_V_S8_ARRAY:
			v->a_s8[i] = (int8_t)json_integer_value(ent);
			break;
		case LDMS_V_U16_ARRAY:
			v->a_u16[i] = htole16((uint16_t)json_integer_value(ent));
			break;
		case LDMS_V_S16_ARRAY:
			v->a_s16[i] = htole16((int16_t)json_integer_value(ent));
			break;
		case LDMS_V_U32_ARRAY:
			v->a_u32[i] = htole32((uint32_t)json_integer_value(ent));
			break;
		case LDMS_V_S32_ARRAY:
			v->a_s32[i] = htole32((int32_t)json_integer_value(ent));
			break;
		case LDMS_V_U64_ARRAY:
			v->a_u64[i] = htole64((uint64_t)json_integer_value(ent));
			break;
		case LDMS_V_S64_ARRAY:
			v->a_s64[i] = htole64((int64_t)json_integer_value(ent));
			break;
		case LDMS_V_F32_ARRAY:
			v->a_f[i] = htole32((float)json_real_value(ent));
			break;
		case LDMS_V_D64_ARRAY:
			v->a_d[i] = htole64((double)json_real_value(ent));
			break;
		default:
			return EINVAL;
		}
	}
	return 0;
}

static void __decomp_static_resolve_mid(ldmsd_strgp_t strgp,
				       __decomp_static_mid_rbn_t mid_rbn,
				       __decomp_static_row_cfg_t drow,
				       ldms_set_t set)
{
	int i, mid, rc;
	__decomp_static_col_cfg_t dcol;
	ldms_mval_t lh, le, rec_array, rec;
	size_t mlen;
	const char *src;
	enum ldms_value_type mtype;
	json_t *jfill;
	EVP_MD_CTX *evp_ctx = NULL;

	evp_ctx = EVP_MD_CTX_create();
	assert(evp_ctx);
	EVP_DigestInit_ex(evp_ctx, EVP_sha256(), NULL);

	for (i = 0; i < mid_rbn->col_count; i++) {
		mid_rbn->col_mids[i].mid = -1;
		mid_rbn->col_mids[i].rec_mid = -1;
		dcol = &drow->cols[i];
		src = dcol->src;

		if (0 == strcmp(src, "timestamp")) {
			mid_rbn->col_mids[i].mid = LDMSD_META_METRIC_ID_TIMESTAMP;
			mid_rbn->col_mids[i].rec_mtype = LDMS_V_TIMESTAMP;
			dcol->type = LDMS_V_TIMESTAMP;
			goto next_col;
		}

		if (0 == strcmp(src, "producer")) {
			mid_rbn->col_mids[i].mid = LDMSD_META_METRIC_ID_PRODUCER;
			mid_rbn->col_mids[i].rec_mtype = LDMS_V_CHAR_ARRAY;
			dcol->type = LDMS_V_CHAR_ARRAY;
			goto next_col;
		}

		if (0 == strcmp(src, "instance")) {
			mid_rbn->col_mids[i].mid = LDMSD_META_METRIC_ID_INSTANCE;
			mid_rbn->col_mids[i].rec_mtype = LDMS_V_CHAR_ARRAY;
			dcol->type = LDMS_V_CHAR_ARRAY;
			goto next_col;
		}

		mid = ldms_metric_by_name(set, drow->cols[i].src);
		mid_rbn->col_mids[i].mid = mid;
		if (mid < 0) /* OK to not exist */
			goto next_col;

		/* Infer column type from metric value */
		mtype = ldms_metric_type_get(set, mid);
		dcol->type = mtype;
		mid_rbn->col_mids[i].mtype = mtype;
		mid_rbn->col_mids[i].rec_mid = -EINVAL;
		mid_rbn->col_mids[i].rec_mtype = LDMS_V_NONE;

		jfill = json_object_get(dcol->jcol, "fill");
		if (!jfill)
			jfill = json_object_get(dcol->jcol, "default");

		if (!jfill)
			dcol->fill = NULL;

		if (mtype < LDMS_V_CHAR_ARRAY) {
			dcol->array_len = 1;
			if (!jfill) /* fill value is already 0 */
				goto next_col;
			dcol->fill = &dcol->_fill;
			rc = __prim_fill_from_json(dcol->fill, dcol->type, jfill);
			if (rc) {
				ovis_log(mylog, OVIS_LERROR,
					 "strgp '%s': col[dst] '%s' "
					 "Default value error: type mismatch\n",
					 strgp->obj.name, dcol->dst);
				goto next_col;
			}
		} else if (mtype == LDMS_V_CHAR_ARRAY) {
			dcol->array_len = ldms_metric_array_get_len(set, mid_rbn->col_mids[i].mid);
			if (!jfill) /* fill values are already 0 */
				goto next_col;
			if (!json_is_string(jfill)) {
				ovis_log(mylog, OVIS_LERROR,
					   "strgp '%s': col[dst] '%s': "
					   "'fill' type mismatch: expecting a STRING\n",
					   strgp->obj.name, dcol->dst);
				goto next_col;
			}
			dcol->fill = calloc(dcol->array_len, __ldms_vsz(dcol->type));
			assert(dcol->fill);
			dcol->fill_len = json_string_length(jfill) + 1;
			if (dcol->fill_len > dcol->array_len) {
				ovis_log(mylog, OVIS_LWARN,
					 "strgp '%s': col[dst] '%s': "
					 "'fill' array length too long\n",
					 strgp->obj.name, dcol->dst);
			}
			int fill_len = dcol->fill_len > dcol->array_len ? dcol->array_len : dcol->fill_len;
			memcpy(dcol->fill, json_string_value(jfill), fill_len);
		} else if (ldms_type_is_array(mtype)) {
			dcol->array_len = ldms_metric_array_get_len(set, mid_rbn->col_mids[i].mid);
			if (!jfill) /* fill values are already 0 */
				goto next_col;
			if (!json_is_array(jfill)) {
				ovis_log(mylog, OVIS_LWARN,
					 "strgp '%s': col[dst] '%s': "
					 "'fill' type mismatch: expecting a LIST\n",
					 strgp->obj.name, dcol->dst);
				goto next_col;
			}
			dcol->fill_len = json_array_size(jfill);
			rc = __array_fill_from_json(dcol, jfill);
			if (rc) {
				ovis_log(mylog, OVIS_LWARN,
					 "strgp '%s': col[dst] '%s': "
					 "'fill' error: type mismatch\n",
					 strgp->obj.name, dcol->dst);
			}
		} else if (mtype == LDMS_V_LIST) {
			lh = ldms_metric_get(set, mid);
			le = ldms_list_first(set, lh, &mtype, &mlen);
			if (!le) {
				/* list empty. can't init yet */
				mid_rbn->col_mids[i].rec_mid = -1;
				/* TODO: Error message. This function
				   will never be called again so, the
				   comment is nonesense */
				goto next_col;
			}
			if (mtype == LDMS_V_LIST) {
				/* LIST of LIST is not supported */
				mid_rbn->col_mids[i].rec_mid = -EINVAL;
				mid_rbn->col_mids[i].rec_mtype = LDMS_V_NONE;
				/* TODO: Error message */
				continue;
			}
			if (!drow->cols[i].rec_member) {
				/* LIST of non-record elements not supported */
				mid_rbn->col_mids[i].rec_mid = -EINVAL;
				mid_rbn->col_mids[i].rec_mtype = LDMS_V_NONE;
				continue;
			}
			/* LIST of records */
			mid = ldms_record_metric_find(le, drow->cols[i].rec_member);
			mid_rbn->col_mids[i].rec_mid = mid;
			if (mid >= 0) {
				dcol->type = mtype = ldms_record_metric_type_get(le, mid, &mlen);
				mid_rbn->col_mids[i].rec_mtype = mtype;
				if (!drow->cols[i].dst) {
					char name[256];
					(void)snprintf(name, sizeof(name), "%s.%s",
						       drow->cols[i].src, drow->cols[i].rec_member);
					drow->cols[i].dst = strdup(name);
					assert(drow->cols[i].dst);
				}
			} else {
				/* Specified record element not present */
				mid_rbn->col_mids[i].rec_mid = -EINVAL;
				mid_rbn->col_mids[i].rec_mtype = LDMS_V_NONE;
				/* TODO: Error message */
				continue;
			}
		} else if (mtype == LDMS_V_RECORD_ARRAY) {
			rec_array = ldms_metric_get(set, mid);
			rec = ldms_record_array_get_inst(rec_array, 0);
			if (!drow->cols[i].rec_member) {
				/* The 'rec_member' field is missing from the configuration */
				mid_rbn->col_mids[i].rec_mid = -EINVAL;
				mid_rbn->col_mids[i].rec_mtype = LDMS_V_NONE;
				/* TODO: Error message */
				continue;
			}
			mid = ldms_record_metric_find(rec, drow->cols[i].rec_member);
			if (mid < 0) {
				/* The specified record member is not present in the instance */
				mid_rbn->col_mids[i].rec_mid = -ENOENT;
				mid_rbn->col_mids[i].rec_mtype = LDMS_V_NONE;
				/* TODO: Error message */
				continue;
			}
			if (!drow->cols[i].dst) {
				char name[256];
				(void)snprintf(name, sizeof(name), "%s.%s",
					       drow->cols[i].src, drow->cols[i].rec_member);
				drow->cols[i].dst = strdup(name);
				assert(drow->cols[i].dst);
			}
			mtype = ldms_record_metric_type_get(rec, mid, &mlen);
			mid_rbn->col_mids[i].rec_mid = mid;
			dcol->type = mid_rbn->col_mids[i].rec_mtype = mtype;
		}
	next_col:
		mtype = ldms_metric_type_get(set, mid);
		EVP_DigestUpdate(evp_ctx, dcol->dst, strlen(dcol->dst));
		EVP_DigestUpdate(evp_ctx, &mtype, sizeof(mtype));

		if (!drow->cols[i].dst) {
			drow->cols[i].dst = strdup(drow->cols[i].src);
			assert(drow->cols[i].dst);
		}
	}
	/* Finalize row schema digest */
	unsigned int len = LDMS_DIGEST_LENGTH;
	EVP_DigestFinal(evp_ctx, drow->schema_digest.digest, &len);
	EVP_MD_CTX_destroy(evp_ctx);
}

/*
 * Given the row configuration determine the metric-id, metric-type,
 * array-length and other information informed by the metric set schema
 */
static __decomp_static_mid_rbn_t
resolve_metric_ids(ldmsd_strgp_t strgp, __decomp_static_cfg_t dcfg,
		   __decomp_static_row_cfg_t drow, ldms_digest_t digest,
		   ldms_set_t set)
{
	__decomp_static_mid_rbn_t mid_rbn;

	/* mid resolve */
	mid_rbn = (void*)rbt_find(&drow->mid_rbt, digest);
	if (mid_rbn)
		/* This digest is already resolved */
		return mid_rbn;

	/* Resolving `src` -> metric ID */
	mid_rbn = calloc(1, sizeof(*mid_rbn) +
			 drow->col_count * sizeof(mid_rbn->col_mids[0]));
	if (!mid_rbn)
		return NULL;

	/* Add this schema to the tree */
	memcpy(&mid_rbn->ldms_digest, digest, sizeof(*digest));
	rbn_init(&mid_rbn->rbn, &mid_rbn->ldms_digest);
	rbt_ins(&drow->mid_rbt, &mid_rbn->rbn);

	mid_rbn->col_count = drow->col_count;

	/* Fill in the metric-id, metric-type and default value for each column in the row */
	__decomp_static_resolve_mid(strgp, mid_rbn, drow, set);

	/* indices */
	int i, j, k;
	json_t *jidxs, *jidx, *jcols, *jcol;
	jidxs = json_object_get(drow->jrow, "indices");
	json_array_foreach(jidxs, i, jidx) {
		__decomp_index_t didx = &drow->idxs[i];
		/* resolve col name to col id */

		jcols = json_object_get(jidx, "cols");
		json_array_foreach(jcols, j, jcol) {
			const char *name = json_string_value(jcol);
			didx->col_idx[j] = -1;
			for (k = 0; k < drow->col_count; k++) {
				if (0 == strcmp(drow->cols[k].dst, name)) {
					didx->col_idx[j] = k;
					break;
				}
			}
			if (didx->col_idx[j] == -1) {
				ovis_log(mylog, OVIS_LERROR,
					 "strgp '%s': The column '%s' specified "
					 "in the index '%s' was not found.\n",
					 strgp->obj.name, name, didx->name);
				goto err;
			}
		}
	}

	return mid_rbn;
 err:
	free(mid_rbn);
	return NULL;
}

struct _col_mval_s {
	ldms_mval_t mval;
	ldms_mval_t rec_array;
	union {
		ldms_mval_t le;
		ldms_mval_t rec;
	};
	enum ldms_value_type mtype;
	size_t array_len;
	int metric_id;
	int rec_metric_id;
	int rec_array_len;
	int rec_array_idx;
};

static void
col_mvals_fill(__decomp_static_col_cfg_t dcol,
	       struct _col_mval_s *mcol)
{
	mcol->le = NULL;
	mcol->mval = dcol->fill;
	mcol->mtype = dcol->type;
	mcol->array_len = dcol->fill_len;
}

#if 0
static void
col_mvals_rec_mid(__decomp_static_mid_rbn_t mid_rbn, int j,
		  struct _col_mval_s *mcol)
{
	/* handling record */
	int rec_mid = mid_rbn->col_mids[j].rec_mid;
	ldms_mval_t mval;

	if (rec_mid >= 0) {
		mval = ldms_record_metric_get(le, rec_mid);
		mcol->mval = mval;
		mcol->mtype = ldms_record_metric_type_get(mcol->le, rec_mid, &mcol->array_len);
		mcol->rec_metric_id = rec_mid;
		return;
	}
	if (rec_mid == -1) {
		/* has not been resolved yet ..
		 * try resolving it here */
		rec_mid = ldms_record_metric_find(le, drow->cols[j].rec_member);
		mid_rbn->col_mids[j].rec_mid = rec_mid;
		col_mvals_rec_mid(mid_rbn, j, mcol);
		return;
	}
	/* member  doesn't exist, use fill */
	mcol->rec_metric_id = -ENOENT;
	col_mvals_fill(dcol, mcol);
}

static void
col_mvals_rec_mid(
		  ldms_mval_t mval,
		  struct _col_mval_s *mcol,
		  __decomp_static_col_cfg_t dcol)
{
	/* handling record */
	int rec_mid = mid_rbn->col_mids[j].rec_mid;
	if (rec_mid >= 0) {
		mval = ldms_record_metric_get(le, rec_mid);
		mcol->mval = mval;
		mcol->mtype = ldms_record_metric_type_get(mcol->le, rec_mid, &mcol->array_len);
		mcol->rec_metric_id = rec_mid;
		return;
	}
	if (rec_mid == -1) {
		/* has not been resolved yet, try resolving it here */
		rec_mid = ldms_record_metric_find(le, drow->cols[j].rec_member);
		mid_rbn->col_mids[j].rec_mid = rec_mid;
		col_mvals_rec_mid(mval, mcol);
		return;
	}
	/* member does not exist, use fill */
	mcol->rec_metric_id = -ENOENT;
	col_mvals_fill(dcol, mcol);
}

static void
col_mvals_list(ldms_mval_t mval, ldms_set_t set)
{
	ldms_mval_t mval, lh, le, rec_array;

	/* list */
	lh = mval;
	le = mcol->le = ldms_list_first(set, lh, &mtype, &mlen);
	if (!le || mtype > LDMS_V_D64_ARRAY) { /* list end .. use 'fill' */
		col_mvals_fill(dcol, mcol);
		return;
	}
	if (mtype == LDMS_V_RECORD_INST) {
		col_mvals_rec_mid();
	}
	/* list of primitives */
	mcol->mval = le;
	mcol->mtype = mtype;
	mcol->array_len = mlen;
}
#endif

static int __decomp_static_decompose(ldmsd_strgp_t strgp, ldms_set_t set,
				     ldmsd_row_list_t row_list, int *row_count)
{
	__decomp_static_cfg_t dcfg = (void*)strgp->decomp;
	__decomp_static_row_cfg_t drow;
	__decomp_static_col_cfg_t dcol;
	ldmsd_row_t row;
	ldmsd_col_t col;
	ldmsd_row_index_t idx;
	ldms_mval_t mval, lh, le, rec_array;
	enum ldms_value_type mtype;
	size_t mlen;
	int i, j, k, c, mid, rc, rec_mid;
	struct _col_mval_s *col_mvals = NULL, *mcol;
	ldms_digest_t ldms_digest;
	TAILQ_HEAD(, _list_entry) list_cols;
	int row_more_le;
	struct ldms_timestamp ts;
	const char *producer;
	const char *instance;
	int producer_len, instance_len;
	ldms_mval_t phony;
	__decomp_static_mid_rbn_t mid_rbn;

	if (!TAILQ_EMPTY(row_list))
		return EINVAL;

	ts = ldms_transaction_timestamp_get(set);

	producer = ldms_set_producer_name_get(set);
	producer_len = strlen(producer) + 1;
	instance = ldms_set_instance_name_get(set);
	instance_len = strlen(instance) + 1;

	TAILQ_INIT(&list_cols);
	ldms_digest = ldms_set_digest_get(set);

	*row_count = 0;
	for (i = 0; i < dcfg->row_count; i++) {
		drow = &dcfg->rows[i];

		mid_rbn = resolve_metric_ids(strgp, dcfg, drow, ldms_digest, set);
		if (!mid_rbn)
			goto err_0;

		/* col_mvals is a temporary scratch area to create rows from
		 * a set with records. col_mvals is freed at the end of
		 * `make_row`. */
		col_mvals = calloc(1, drow->col_count * sizeof(*col_mvals));
		if (!col_mvals) {
			rc = ENOMEM;
			goto err_0;
		}
		for (j = 0; j < drow->col_count; j++) {
			dcol = &drow->cols[j];
			mid = mid_rbn->col_mids[j].mid;
			mcol = &col_mvals[j];
			if (mid < 0) { /* Metric not present the set, use the default value */
				col_mvals_fill(dcol, mcol);
				continue;
			}

			mcol->metric_id = mid;
			mcol->rec_metric_id = -1;
			mcol->rec_array_idx = -1;
			mcol->rec_array_len = -1;
			switch (mid) {
			case LDMSD_META_METRIC_ID_TIMESTAMP:
				/* mcol->mval will be assigned in `make_row` */
				mcol->mtype = LDMS_V_TIMESTAMP;
				mcol->array_len = 1;
				mcol->le = NULL;
				continue;
			case LDMSD_META_METRIC_ID_PRODUCER:
				mcol->mval = (ldms_mval_t)producer;
				/* mcol->mval->a_char is producer */
				mcol->mtype = LDMS_V_CHAR_ARRAY;
				mcol->array_len = producer_len;
				mcol->le = NULL;
				continue;
			case LDMSD_META_METRIC_ID_INSTANCE:
				mcol->mval = (ldms_mval_t)instance;
				/* mcol->mval->a_char is instance */
				mcol->mtype = LDMS_V_CHAR_ARRAY;
				mcol->array_len = instance_len;
				mcol->le = NULL;
				continue;
			}
			mval = ldms_metric_get(set, mid);
			mtype = ldms_metric_type_get(set, mid);
			if (mtype != mid_rbn->col_mids[j].mtype) {
				ovis_log(mylog, OVIS_LERROR, "strgp '%s': the metric type (%s) of "
					     "row %d:col %d is different from the type (%s) of "
					     "LDMS metric '%s'.\n", strgp->obj.name,
					     ldms_metric_type_to_str(mid_rbn->col_mids[j].mtype),
					     i, j, ldms_metric_type_to_str(mtype),
					     ldms_metric_name_get(set, mid));
				rc = EINVAL;
				goto err_0;
			}

			if (mtype == LDMS_V_LIST)
				goto col_mvals_list;
			if (mtype == LDMS_V_RECORD_ARRAY)
				goto col_mvals_rec_array;
			if (mtype > LDMS_V_D64_ARRAY)
				col_mvals_fill(dcol, mcol);
			/* primitives */
			if (ldms_type_is_array(mtype)) {
				mlen = ldms_metric_array_get_len(set, mid);
			} else {
				mlen = 1;
			}
			mcol->mval = mval;
			mcol->mtype = mtype;
			mcol->array_len = mlen;
			mcol->le = NULL;
			continue;

		col_mvals_list:
			/* list */
			lh = mval;
			le = mcol->le = ldms_list_first(set, lh, &mtype, &mlen);
			if (!le) { /* list end .. use 'fill' */
				col_mvals_fill(dcol, mcol);
				continue;
			}
			if (mtype == LDMS_V_RECORD_INST)
				goto col_mvals_rec_mid;
			/* list of primitives */
			mcol->mval = le;
			mcol->mtype = mtype;
			mcol->array_len = mlen;
			continue;
		col_mvals_rec_mid:
			/* handling record */
			rec_mid = mid_rbn->col_mids[j].rec_mid;
			if (rec_mid >= 0) {
				mval = ldms_record_metric_get(le, rec_mid);
				mcol->mval = mval;
				mcol->mtype = ldms_record_metric_type_get(mcol->le, rec_mid, &mcol->array_len);
				mcol->rec_metric_id = rec_mid;
				continue;
			}
			if (rec_mid == -1) {
				/* has not been resolved yet, try resolving it here */
				rec_mid = ldms_record_metric_find(le, drow->cols[j].rec_member);
				mid_rbn->col_mids[j].rec_mid = rec_mid;
				goto col_mvals_rec_mid;
			}
			/* member does not exist, use fill */
			mcol->rec_metric_id = -ENOENT;
			col_mvals_fill(dcol, mcol);
			continue;

		col_mvals_rec_array:
			rec_mid = mid_rbn->col_mids[j].rec_mid;
			if (rec_mid < 0) {
				mcol->rec_metric_id = rec_mid;
				col_mvals_fill(dcol, mcol);
				continue;
			}
			rec_array = mval;
			mcol->rec_array = rec_array;
			mcol->rec_array_len = ldms_record_array_len(rec_array);
			mcol->rec_array_idx = 0;
			mcol->rec = ldms_record_array_get_inst(rec_array, 0);
			mcol->mval = ldms_record_metric_get(mcol->rec, rec_mid);
			mcol->mtype = ldms_record_metric_type_get(mcol->rec, rec_mid, &mcol->array_len);
			mcol->rec_metric_id = rec_mid;
		} /* drow->col_count */

	make_row: /* make/expand rows according to col_mvals */
		row = calloc(1, drow->row_sz);
		if (!row) {
			rc = errno;
			goto err_0;
		}
		row->schema_name = drow->schema_name;
		row->schema_digest = &drow->schema_digest;
		row->idx_count = drow->idx_count;
		row->col_count = drow->col_count;

		/* indices */
		row->indices = (void*)&row->cols[row->col_count];
		idx = (void*)&row->indices[row->idx_count];
		for (j = 0; j < row->idx_count; j++) {
			row->indices[j] = idx;
			idx->col_count = drow->idxs[j].col_count;
			idx->name = drow->idxs[j].name;
			for (k = 0; k < idx->col_count; k++) {
				c = drow->idxs[j].col_idx[k];
				idx->cols[k] = &row->cols[c];
			}
			idx = (void*)&idx->cols[idx->col_count];
		}

		/* phony mvals are next to the idx data */
		phony = (void*)idx;

		row_more_le = 0;
		/* cols */
		for (j = 0; j < row->col_count; j++) {
			col = &row->cols[j];
			dcol = &drow->cols[j];
			mcol = &col_mvals[j];

			if (dcol->type != mcol->mtype) {
				ovis_log(mylog, OVIS_LERROR, "strgp '%s': row '%d' col[dst] '%s': "
					     "the value type (%s) is not "
					     "compatible with the source metric type (%s). "
					     "Please check the decomposition configuration.\n",
					     strgp->obj.name, i, dcol->dst,
					     ldms_metric_type_to_str(dcol->type),
					     ldms_metric_type_to_str(mcol->mtype));
				rc = EINVAL;
				goto err_0;
			}

			col->metric_id = mcol->metric_id;
			col->rec_metric_id = mcol->rec_metric_id;

			col->name = dcol->dst;
			col->type = mcol->mtype;
			col->array_len = mcol->array_len;
			if (mid_rbn->col_mids[j].mid == LDMSD_META_METRIC_ID_TIMESTAMP) {
				phony->v_ts = ts;
				col->mval = phony;
				phony++;
			} else {
				/* The other phony types are fine */
				col->mval = mcol->mval;
			}

			if (!mcol->le) /* no more elements */
				continue;

			if (mcol->rec_array_idx >= 0) /* array of records */
				goto col_rec_array;

			/* list */
			/* step to next element in the list */
			mcol->le = ldms_list_next(set, mcol->le, &mcol->mtype, &mcol->array_len);
			if (!mcol->le)
				goto col_fill;
			row_more_le = 1;
			if (drow->cols[j].rec_member) {
				/* expect record */
				rec_mid = mid_rbn->col_mids[j].rec_mid;
				if (rec_mid < 0) {
					goto col_fill;
				}
				/* extract the record metric */
				mcol->mval = ldms_record_metric_get(mcol->le, rec_mid);
				mcol->mtype = ldms_record_metric_type_get(mcol->le, rec_mid, &mcol->array_len);
			} else {
				/* expect list of primitives */
				if (mcol->mtype > LDMS_V_D64_ARRAY)
					goto col_fill;
				mcol->mval = mcol->le;
			}
			continue;

		col_rec_array:
			rec_mid = mid_rbn->col_mids[j].rec_mid;
			if (rec_mid < 0 || mcol->rec_array_idx < 0)
				goto col_fill;
			/* step */
			mcol->rec_array_idx++;
			mcol->rec = ldms_record_array_get_inst(mcol->rec_array, mcol->rec_array_idx);
			if (!mcol->rec)
				goto col_fill;
			/* extract the record metric */
			mcol->mval = ldms_record_metric_get(mcol->rec, rec_mid);
			mcol->mtype = ldms_record_metric_type_get(mcol->le, rec_mid, &mcol->array_len);
			continue;

		col_fill:
			mcol->mval = drow->cols[j].fill;
			mcol->array_len = drow->cols[j].array_len;
			mcol->mtype = drow->cols[j].type;
		} /* for each column */

		TAILQ_INSERT_TAIL(row_list, row, entry);
		(*row_count)++;
		row = NULL;
		if (row_more_le)
			goto make_row;
		free(col_mvals);
		col_mvals = NULL;
	} /* for each row */
	return 0;
 err_0:
	/* clean up stuff here */
	if (col_mvals)
		free(col_mvals);
	__decomp_static_release_rows(strgp, row_list);
	return rc;
}

static void __decomp_static_release_rows(ldmsd_strgp_t strgp,
					 ldmsd_row_list_t row_list)
{
	ldmsd_row_t row;
	while ((row = TAILQ_FIRST(row_list))) {
		TAILQ_REMOVE(row_list, row, entry);
		free(row);
	}
}
