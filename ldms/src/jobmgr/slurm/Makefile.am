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

libjobmgr_slurm_la_SOURCES = jobmgr_slurm.c
libjobmgr_slurm_la_LIBADD = $(COMMON_LIBADD)
libjobmgr_slurm_la_CFLAGS = $(SLURM_CFLAGS) -DSYSCONFDIR='"$(sysconfdir)"'
dist_man7_MANS += ldms-jobmgr_slurm.man
pkglib_LTLIBRARIES += libjobmgr_slurm.la

CLEANFILES = $(dist_man7_MANS)

EXTRA_DIST=ldms-jobmgr_slurm.rst
