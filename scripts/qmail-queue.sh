#!/bin/sh
exec /var/qmail/bin/qmail-qfilter /export/bin/blackhole -Q -m /var/spool/blackhole/msg

