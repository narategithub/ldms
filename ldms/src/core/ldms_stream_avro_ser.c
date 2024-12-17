#include "config.h"
#include "ldms.h"
#include "ldms_stream.h"
#include "ldms_stream_avro_ser.h"

#if HAVE_LIBAVRO && HAVE_LIBSERDES

#include "avro.h"
#include <libserdes/serdes.h>
#include <libserdes/serdes-avro.h>

serdes_schema_t * serdes_schema_from_avro(serdes_t *sd, avro_schema_t asch)
{
	char buf[4096] = ""; /* should be sufficient? */
	char ebuf[4096];
	serdes_schema_t *ssch = NULL;
	const char *name;
	int rc;
	avro_writer_t aw = avro_writer_memory(buf, sizeof(buf));
	rc = avro_schema_to_json(asch, aw);
	if (rc) {
		errno = rc;
		goto out;
	}
	name = avro_schema_name(asch);
	ssch = serdes_schema_add(sd, name, -1, buf, strlen(buf),
						     ebuf, sizeof(ebuf));
	if (!ssch) {
		errno = EIO;
	}
	/* serdes schema is cached */
	avro_writer_free(aw);
 out:
	return ssch;
}

int ldms_stream_publish_avro_ser(ldms_t x, const char *stream_name,
				 ldms_cred_t cred, uint32_t perm,
				 avro_value_t *value, serdes_t *sd,
				 struct serdes_schema_s **sch)
{
	serdes_schema_t *ssch = NULL;
	avro_schema_t asch;
	char ebuf[4096];
	serdes_err_t serr;
	int rc;
	size_t sz;
	void *payload;

	if (0 == serdes_serializer_framing_size(sd)) {
		/* Need serdes "serializer.framing" enabled */
		return ENOPROTOOPT;
	}

	if (sch)
		ssch = *sch;
	if (!ssch) {
		/* need to build serdes schema */
		asch = avro_value_get_schema(value);
		ssch = serdes_schema_from_avro(sd, asch);
		if (!ssch)
			return errno;
	}
	if (sch)
		*sch = ssch;
	payload = NULL;
	serr = serdes_schema_serialize_avro(ssch, value, &payload, &sz,
					    ebuf, sizeof(ebuf));
	if (serr != SERDES_ERR_OK) {
		return EIO;
	}

	/* We can use existing stream_publish to publish the serialized data */
	rc = ldms_stream_publish(x, stream_name, LDMS_STREAM_AVRO_SER,
				 cred, perm, payload, sz);
	return rc;
}

int avro_value_from_stream_data(const char *data, size_t data_len,
				serdes_t *sd, avro_value_t **aout,
				serdes_schema_t **sout)
{
	int rc = 0;
	avro_value_t *av;
	char ebuf[4096];
	serdes_err_t serr;

	if (!sd) {
		rc = EINVAL;
		goto out;
	}

	av = malloc(sizeof(*av));
	if (!av) {
		rc = errno;
		goto out;
	}

	serr = serdes_deserialize_avro(sd, av, sout,
					data, data_len,
					ebuf, sizeof(ebuf));
	if (serr) {
		free(av);
		av = NULL;
		rc = EIO;
		goto out;
	}
	/* caller will free av later */
	*aout = av;
	rc = 0;
 out:
	return rc;
}

ldms_stream_client_t
ldms_stream_subscribe_avro_ser(const char *stream, int is_regex,
		      ldms_stream_event_cb_t cb_fn, void *cb_arg,
		      const char *desc, serdes_t *serdes)
{
	ldms_stream_client_t c = NULL;
	int rc;

	if (!cb_fn) {
		errno = EINVAL;
		goto out;
	}

	if (!serdes) {
		errno = EINVAL;
		goto out;
	}

	c = __client_alloc(stream, is_regex, cb_fn, cb_arg, desc);
	if (!c)
		goto out;
	c->serdes = serdes;
	rc = __client_subscribe(c);
	if (rc) {
		__client_free(c);
		c = NULL;
		errno = rc;
	}

 out:
	return c;
}

#else
/* HAVE_LIBAVRO == 0 or HAVE_LIBSERDES == 0 */

void avro_value_decref(avro_value_t *value)
{
	/* no-op */
}

int ldms_stream_publish_avro_ser(ldms_t x, const char *stream_name,
				 ldms_cred_t cred, uint32_t perm,
				 avro_value_t *value, serdes_t *sd,
				 struct serdes_schema_s **sch)
{
	return ENOSYS;
}

int avro_value_from_stream_data(const char *data, size_t data_len,
				serdes_t *sd, avro_value_t **aout,
				serdes_schema_t **sout)
{
	return ENOSYS;
}

ldms_stream_client_t
ldms_stream_subscribe_avro_ser(const char *stream, int is_regex,
		      ldms_stream_event_cb_t cb_fn, void *cb_arg,
		      const char *desc, serdes_t *serdes)
{
	errno = ENOSYS;
	return NULL;
}
#endif
