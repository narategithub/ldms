.. _jobmgr_slurm:

============
jobmgr_slurm
============

-----------------------------------------
Man page for the LDMS jobmgr_slurm plugin
-----------------------------------------

:Date:   19 Aug 2025
:Manual section: 7
:Manual group: LDMS job plugin

SYNOPSIS
========

``load`` name=\ `INST` plugin=\ ``jobmgr_slurm``

``config`` name=\ `INST` message_channel=\ `CHANNEL`

``jobmgr_start`` name=\ `INST`

``jobmgr_stop``  name=\ `INST`

``term`` name=\ `INST`



DESCRIPTION
===========

TODO

CONFIGURATION ATTRIBUTE SYNTAX
==============================

TODO


BUGS
====

No known bugs.

EXAMPLES
========

Within ldmsd_controller or a configuration file:

::

   load name=jobmgr_slurm
   config name=jobmgr_slurm message_channel=slurm
   jobmgr_start name=jobmgr_slurm

SEE ALSO
========

:ref:`ldmsd(8) <ldmsd>`, :ref:`ldms_quickstart(7) <ldms_quickstart>`, :ref:`ldmsd_controller(8) <ldmsd_controller>`, :ref:`ldms_sampler_base(7) <ldms_sampler_base>`
