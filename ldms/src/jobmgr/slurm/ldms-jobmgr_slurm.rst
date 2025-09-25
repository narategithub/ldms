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

``config`` name=\ `INST` [message_channel=\ `CHANNEL`] [component_id=\ `COMP_ID`]

``jobmgr_start`` name=\ `INST`

``jobmgr_stop``  name=\ `INST`

``term`` name=\ `INST`


DESCRIPTION
===========

``jobmgr_slurm`` is an LDMSD Job Manager Plugin that receives ``slurm`` events
from ``slurm_notifier`` via ``ldms_msg`` from the channel specified by
``message_channel``, create corresponding job sets, and post ``jobbgr`` events
to the Job Manager event subscribers in ``ldmsd``.

Please see CONFIG ATTRIBUTES section for descriptions of all available
attributes to ``config`` command for this plugin.

This plugin supports multi instances.


CONFIG ATTRIBUTES
=================

``name``\ =\ `INST`
  The instance name of the plugin.


[ ``message_channel``\ =\ `CHANNEL` ]
  The message channel to receive Slurm job data from ``slurm_notiifer``. If
  this is not specified, the default value is "slurm".


[ ``component_id``\ =\ `COMP_ID` ]
  This value (string) will be assigned to ``component_id`` metric in the jobsets
  created by this plugin.


BUGS
====

No known bugs.

EXAMPLES
========

Within ldmsd_controller or a configuration file:

::

   load name=jobmgr_slurm
   config name=jobmgr_slurm message_channel=slurm component_id=node-1
   jobmgr_start name=jobmgr_slurm


SEE ALSO
========

:ref:`ldms-sampler_slurm_notifier(8) <_slurm_notifier>` ,
:ref:`ldmsd(8) <ldmsd>` ,
:ref:`ldms_quickstart(7) <ldms_quickstart>` ,
:ref:`ldmsd_controller(8) <ldmsd_controller>`
