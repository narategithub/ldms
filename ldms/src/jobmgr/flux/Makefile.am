include $(top_srcdir)/ldms/rules.mk


pkglib_LTLIBRARIES =
dist_man7_MANS=

AM_CPPFLAGS = @OVIS_INCLUDE_ABS@
AM_LDFLAGS = @OVIS_LIB_ABS@
COMMON_LIBADD = $(top_builddir)/ldms/src/core/libldms.la \
		@LDFLAGS_GETTIME@ \
		$(top_builddir)/lib/src/ovis_util/libovis_util.la \
		$(top_builddir)/lib/src/coll/libcoll.la \
		$(top_builddir)/lib/src/ovis_json/libovis_json.la

libjobmgr_flux_la_SOURCES = jobmgr_flux.c
libjobmgr_flux_la_LIBADD = $(COMMON_LIBADD) $(FLUX_LDFLAGS)
libjobmgr_flux_la_CFLAGS = $(FLUX_CFLAGS) -DSYSCONFDIR='"$(sysconfdir)"'
dist_man7_MANS += ldms-jobmgr_flux.man
pkglib_LTLIBRARIES += libjobmgr_flux.la

libflux_ldms_notifier_la_SOURCES = flux_ldms_notifier.c
libflux_ldms_notifier_la_LIBADD = $(COMMON_LIBADD) $(FLUX_LDFLAGS)
libflux_ldms_notifier_la_CFLAGS = $(FLUX_CFLAGS) -DSYSCONFDIR='"$(sysconfdir)"'
dist_man7_MANS += ldms-flux_ldms_notifier.man
pkglib_LTLIBRARIES += libflux_ldms_notifier.la

CLEANFILES = $(dist_man7_MANS)

EXTRA_DIST=ldms-jobmgr_flux.rst
