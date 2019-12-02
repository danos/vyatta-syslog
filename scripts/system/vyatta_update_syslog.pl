#!/usr/bin/perl

# **** License ****
#
# Copyright (c) 2017-2019 AT&T Intellectual Property.
#    All Rights Reserved.
# Copyright (c) 2014-2017, Brocade Communications Systems, Inc.
#    All Rights Reserved.
#
#
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2007-2013 Vyatta, Inc.
# All Rights Reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
# **** End License ****

# Update /etc/rsyslog.d/vyatta-log.conf
# Exit code: 0 - update
#            1 - no change or error

use strict;
use warnings;
use lib "/opt/vyatta/share/perl5";
use Vyatta::Syslog;

die "$0 expects no arguments\n" if (@ARGV);

my $ret = update_rsyslog_config();

exit $ret;
