# Module: Syslog.pm
# Rsyslog configuration generator module

# **** License ****
#
# Copyright (c) 2017-2020 AT&T Intellectual Property.
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

package Vyatta::Syslog;

use base qw(Exporter);

use strict;
use warnings;
use lib "/opt/vyatta/share/perl5";
use Vyatta::Configd;
use Array::Utils qw(array_diff);
use File::Basename;
use File::Compare;
use File::Temp qw/ tempfile /;
use File::Path qw(make_path remove_tree);
use Net::IP;
use NetAddr::IP;
use Sys::Syslog qw(:standard :macros);
use Template;
use Tie::IxHash;

our $SYSLOG_CONF = '/etc/rsyslog.d/vyatta-log.conf';
my $SYSLOG_PORT           = "514";
my $SYSLOG_TMPL           = "/tmp/rsyslog.conf.XXXXXX";
my $MESSAGES              = '/var/log/messages';
my $CONSOLE               = '/dev/console';
my $LOGROTATE_CFG_DIR     = '/opt/vyatta/etc/logrotate';
my $DEFAULT_VRF_NAME      = 'default';
my $DEFAULT_AUTH_LOCATION = '/config/auth';
our $ACTION_TEMPLATE =
  '/opt/vyatta/share/rsyslog-configs/vyatta-action.template';
our $SOURCE_INTERFACE_FILE = "/run/vyatta/rsyslog/source-interface-list";
my $SI_TMP_FILE = "/run/vyatta/rsyslog/si.XXXXXX";

our @EXPORT_OK =
  qw(update_rsyslog_config $SYSLOG_CONF $ACTION_TEMPLATE $SOURCE_INTERFACE_FILE);

# Values come from /usr/include/sys/syslog.h
my %FACILITY_VALS = (
    'kern'     => ( 0 << 3 ),
    'user'     => ( 1 << 3 ),
    'mail'     => ( 2 << 3 ),
    'daemon'   => ( 3 << 3 ),
    'auth'     => ( 4 << 3 ),
    'syslog'   => ( 5 << 3 ),
    'lpr'      => ( 6 << 3 ),
    'news'     => ( 7 << 3 ),
    'uucp'     => ( 8 << 3 ),
    'cron'     => ( 9 << 3 ),
    'authpriv' => ( 10 << 3 ),
    'ftp'      => ( 11 << 3 ),
    'local0'   => ( 16 << 3 ),
    'local1'   => ( 17 << 3 ),
    'local2'   => ( 18 << 3 ),
    'local3'   => ( 19 << 3 ),
    'local4'   => ( 20 << 3 ),
    'local5'   => ( 21 << 3 ),
    'local6'   => ( 22 << 3 ),
    'local7'   => ( 23 << 3 )
);

my %SEVERITY_VALS = (
    'emerg'   => 0,
    'alert'   => 1,
    'crit'    => 2,
    'err'     => 3,
    'warning' => 4,
    'notice'  => 5,
    'info'    => 6,
    'debug'   => 7,
);

my @SEVERITY_NAMES =
  ( 'emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug', );

my %entries;
tie %entries, 'Tie::IxHash';
my %fac_override   = ();
my @discard_regexs = ();
my $rl_interval;
my $rl_burst;
my $si_list = "";

sub get_rate_limit_parms {
    my ($config) = @_;

    $rl_interval = $config->{'rate-limit'}->{'interval'};
    $rl_burst    = $config->{'rate-limit'}->{'burst'};

    return;
}

sub get_discard_regexs {
    my ($config) = @_;

    my $discard = get_node( $config,  'discard' );
    my $msgprop = get_node( $discard, 'msg' );
    my $discardregexlist = $msgprop->{'regex'};

    return unless defined($discardregexlist);

    foreach my $regex ( @{$discardregexlist} ) {
        push @discard_regexs, $regex;
    }
    return;
}

sub add_target_selector {
    my ( $selector, $target ) = @_;

    $entries{$target}{selector} = [] unless $entries{$target}{selector};
    push @{ $entries{$target}{selector} }, $selector;
    return;
}

sub add_target_msgregex {
    my ( $msgregex, $target ) = @_;

    $entries{$target}{msgregex} = [] unless $entries{$target}{msgregex};
    push @{ $entries{$target}{msgregex} }, $msgregex;
    return;
}

sub set_target_param {
    my ( $config, $target, $param ) = @_;

    $entries{$target}{$param} = $config->{'archive'}->{$param};
    return;
}

sub get_target_param {
    my ( $target, $param ) = @_;
    return $entries{$target}{$param};
}

# This allows overloading local values in CLI
my %facmap = (
    'all'       => '*',
    'sensors'   => 'local4',
    'dataplane' => 'local6',
    'protocols' => 'local7',
);

sub build_facility {
    my ($config) = @_;
    my $out = "";

    my $facility = $config->{'facility'};

    return $out if ( !defined($facility) );

    $facility = $facmap{$facility} if ( $facmap{$facility} );
    my $facval;
    if ( $facility ne "*" ) {
        $facval = ( $FACILITY_VALS{$facility} >> 3 )
          if ( defined( $FACILITY_VALS{$facility} ) );
    }

    if ( defined($facval) ) {
        $out = "(\$!facility == $facval)";
    }

    return $out;
}

sub build_severity {
    my ($config) = @_;
    my $sev = $config->{'severity'};

    return "" if ( !defined($sev) );

    my $severity = get_severity( $sev->{'equals'} );
    return "(\$!severity == $severity)" if ( defined($severity) );

    # Severity values are emergency (0) to debug (7) a lower value
    # is a higher severity.
    # at-least matches a severity and any severity of
    # a higher priority, therefore '<='
    $severity = get_severity( $sev->{'at-least'} );
    return "(\$!severity <= $severity)" if ( defined($severity) );

    # at-most matches a severity and any severity of
    # a lower priority, therefore '>='.
    $severity = get_severity( $sev->{'at-most'} );
    return "(\$!severity >= $severity)" if ( defined($severity) );

    return "";
}

sub build_flag {
    my ($config)    = @_;
    my $out         = "";
    my @flags       = ();
    my @wflags      = ();
    my @woflags     = ();
    my $withflag    = $config->{'with-flag'};
    my $withoutflag = $config->{'without-flag'};

    foreach my $wf ( @{$withflag} ) {
        push @wflags, "(\$.flag.$wf == 1)";
    }
    my $with = join ' and ', @wflags;
    $with = '(' . $with . ')' if ( $with ne "" );
    push @flags, $with if ( $with ne "" );

    foreach my $wof ( @{$withoutflag} ) {
        push @woflags, "(\$.flag.$wof == 0)";
    }
    my $without = join ' and ', @woflags;
    $without = '(' . $without . ')' if ( $without ne "" );

    push @flags, $without if ( $without ne "" );

    $out = join ' and ', @flags;

    return $out;
}

sub build_regexes {
    my ( $config, $subtree ) = @_;

    my $out = "";
    my @reg = ();

    my $msgprop = get_node( $config, 'msg' );
    my $regexlist = $msgprop->{$subtree};

    foreach my $match ( @{$regexlist} ) {
        my $regex  = $match->{'regex'};
        my $unless = $match->{'unless'};

        my $ocfg = " re_match(\$msg, \"$regex\") ";

        if ( defined($unless) ) {
            $ocfg .= " and (not(re_match(\$msg, \"$unless\")))";
        }

        push @reg, $ocfg;
    }

    $out = join ' and ', @reg;

    $out = '(' . $out . ')' if ( $out ne "" );

    return $out;
}

sub build_ratelimit {
    my ( $config, $then, $otherwise ) = @_;

    my $rulenum  = $config->{'rule-number'};
    my $prop     = $config->{'rate-limit'}[0];
    my $burst    = $prop->{'burst'};
    my $interval = $prop->{'interval'};
    my $everynth = $prop->{'select-every-nth'};
    my $flag     = $prop->{'flag'};
    my $out      = "";

    if ( defined($burst) and defined($interval) ) {
        $out = <<"END";
if ((\$.tnow - \$/tstart${rulenum}) >= ${interval}) then {
    set \$/tstart${rulenum} = \$.tnow;
    set \$/burstcount${rulenum} = 0;
}
if (\$/burstcount${rulenum} >= ${burst} ) then {
    ${otherwise}
} else {
    set \$/burstcount${rulenum} = \$/burstcount${rulenum} + 1;
    ${then}
}
END
    } elsif ( defined($everynth) ) {
        $out = <<"END";
if (\$/count${rulenum} >= ${everynth}) then {
    set \$/count${rulenum} = 0;
}
if (\$/count${rulenum} == 0) then {
    set \$/count${rulenum} = \$/count${rulenum} + 1;
    ${then}
} else {
    set \$/count${rulenum} = \$/count${rulenum} + 1;
    ${otherwise}
}
END

    }

    if ( $flag ne '*' ) {
        $out = "if (\$.flag.$flag == 1) then {\n" . $out . "\n}\n";
    }

    return $out;
}

sub get_facility {
    my ($facility) = @_;

    return $facility if ( !defined($facility) );

    $facility = $facmap{$facility} if ( $facmap{$facility} );
    my $facval;
    if ( $facility ne "*" ) {
        $facval = ( $FACILITY_VALS{$facility} >> 3 )
          if ( defined( $FACILITY_VALS{$facility} ) );
    }

    return $facval;
}

sub get_severity {
    my ($severity) = @_;

    return $severity if ( !defined($severity) );

    $severity = $SEVERITY_VALS{$severity};

    return $severity;
}

sub get_hostname {
    my ($hostname) = @_;

    $hostname =~ s/[:\.]/_/g;

    return $hostname;
}

sub build_actions {
    my ( $config, $class ) = @_;

    my $out        = "";
    my @outactions = ();
    my $actions    = $config->{$class};

    my $facility = get_facility( $actions->{'set-facility'} );
    push @outactions, "set \$!facility = $facility;" if ( defined($facility) );

    my $severity = get_severity( $actions->{'set-severity'} );
    push @outactions, "set \$!severity = $severity;" if ( defined($severity) );

    push @outactions, "call setpri"
      if ( defined($facility) or defined($severity) );

    foreach my $setflag ( @{ $actions->{'set-flag'} } ) {
        push @outactions, "set \$.flag.$setflag = 1;";
    }

    foreach my $clearflag ( @{ $actions->{'clear-flag'} } ) {
        push @outactions, "set \$.flag.$clearflag = 0;";
    }

    push @outactions, "set \$!indicator = \"$actions->{'set-indicator'}\";"
      if ( defined( $actions->{'set-indicator'} ) );

    foreach my $file ( @{ $actions->{'file'} } ) {
        push @outactions, "call fileaction_$file";
    }

    foreach my $host ( @{ $actions->{'host'} } ) {
        push @outactions, "call hostaction_$host";
    }

    foreach my $user ( @{ $actions->{'user'} } ) {
        if ( $user eq '*' ) {
            push @outactions, "call allusersaction";
        } else {
            push @outactions, "call useraction_$user";
        }
    }

    push @outactions, "call consoleaction"
      if ( exists( $actions->{'console'} ) );

    push @outactions, "stop" if ( exists( $actions->{'discard'} ) );

    $out = join "\n", @outactions;

    $out = "continue" if ( $out eq '' );

    return $out;
}

sub build_match {
    my ( $config, $thenactions, $otherwiseactions ) = @_;

    my $out       = "";
    my @selectors = ();

    my $matches = $config->{'match'};

    my $facility = build_facility($matches);
    push @selectors, $facility if ( $facility ne "" );

    my $severity = build_severity($matches);
    push @selectors, $severity if ( $severity ne "" );

    my $flag = build_flag($matches);
    push @selectors, $flag if ( $flag ne "" );

    my $regexes = build_regexes( $matches, 'posix-match' );
    push @selectors, $regexes if ( $regexes ne "" );

    $out = join ' and ', @selectors;
    $out = "(1 == 1)" if ( $out eq "" );

    $out = "if ($out) then {\n $thenactions\n} else {\n$otherwiseactions\n}\n";
    return $out;
}

sub build_rule {
    my ($config) = @_;
    my $out      = "";
    my $num      = $config->{'rule-number'};

    return $out if ( exists( $config->{'disable'} ) );

    my $thenactions      = build_actions( $config, 'then' );
    my $otherwiseactions = build_actions( $config, 'otherwise' );

    if ( defined( $config->{'match'} ) ) {
        $out = build_match( $config, $thenactions, $otherwiseactions );
    } elsif ( defined( $config->{'rate-limit'} ) ) {
        $out = build_ratelimit( $config, $thenactions, $otherwiseactions );
    } else {
        $out = $thenactions;
    }

    return $out;
}

sub build_tls_certificates {
    my ($config) = @_;

    # TODO: Omfwd does not support per action certificates.
    my $cert_locations = '';
    my @ca;
    my $sys    = get_node( $config, 'system' );
    my $syslog = get_node( $sys,    'syslog-enhanced' );
    my $gen_ca_list = sub {
        my ($ca) = @_;
        return "${DEFAULT_AUTH_LOCATION}/$ca->{file}";
    };

    my $encrypt_params = $syslog->{tls};
    if ( defined( $encrypt_params ) ) {
        my $ca_params = $encrypt_params->{'certificate-authority'};
        my $cert_params = $encrypt_params->{'local-certificate'};
        if ( !defined($ca_params) || !defined($cert_params) ) {
            print "Error: TLS configured without proper Certificates.\n";
            return;
        }
        @ca = map { $gen_ca_list->($_) } @{$ca_params}
          if defined $ca_params;
        $cert_locations = <<"END";
global(
    DefaultNetstreamDriverCAFile="$ca[0]"
    DefaultNetstreamDriverCertFile="${DEFAULT_AUTH_LOCATION}/$cert_params->{certificate}"
    DefaultNetstreamDriverKeyFile="${DEFAULT_AUTH_LOCATION}/$cert_params->{key}"
)
END
    }

    return $cert_locations;
}

sub build_journal_input_rate_limit {
    my ($config) = @_;
    my $out = "";

    get_rate_limit_parms($config->{'system'}->{'syslog-enhanced'}->{'input'}->{'journal'});

    open my $fh, '>>', \$out;
    print_rate_limit_settings($fh);
    close $fh;

    return $out;
}

sub build_rules {
    my ($config) = @_;
    my $out = "";

    my $sys    = get_node( $config, 'system' );
    my $syslog = get_node( $sys,    'syslog-enhanced' );
    my $rules  = get_node( $syslog, 'rule' );

    foreach my $rule ( @{$rules} ) {
        my $rl = build_rule($rule);
        $out .= "\n$rl\n" if ( $rl ne "" );
    }

    return $out;
}

sub build_targets {
    my ($config) = @_;
    my $out      = "";
    my %users    = ();

    my $sys    = get_node( $config, 'system' );
    my $syslog = get_node( $sys,    'syslog-enhanced' );
    my $files  = $syslog->{'file'};
    my $hosts  = $syslog->{'host'};

    my @targets = ();

    foreach my $file ( @{$files} ) {
        my $name      = $file->{'filename'};
        my $fileentry = $file->{'entry'};

        my $archive = $file->{'archive'};
        my $files   = $archive->{'files'};
        my $size    = $archive->{'size'};

        write_log_rotation_file( $name, $files, $size );

        $size = ( $size + 5 ) * 1024;
        my $filetarget = "";
        $filetarget = <<"END";

\$outchannel file_${fileentry},/var/log/user/${name},${size},/usr/sbin/logrotate ${LOGROTATE_CFG_DIR}/file_${name}
set \$.send.file.${fileentry} = 1;

ruleset(name="fileaction_${fileentry}") {
    if (\$.send.file.${fileentry} == 1) then {
        :omfile:\$file_${fileentry}
        set \$.send.file.${fileentry} = 0;
    }
}
END

        push @targets, $filetarget;
    }

    foreach my $host ( @{$hosts} ) {
        my $action =
          get_action( "", $config, $host->{'routing-instance'}, $host );
        my $hostentry = $host->{'entry'};

        my $hosttarget = "";
        $hosttarget = <<"END";

set \$.send.host.${hostentry} = 1;

ruleset(name="hostaction_${hostentry}") {
    if (\$.send.host.${hostentry} == 1) then {
        ${action}
        set \$.send.host.${hostentry} = 0;
    }
}
END
        push @targets, $hosttarget;
    }

    my $rules = $syslog->{'rule'};
    my $console;
    foreach my $rule ( @{$rules} ) {
        my $then = $rule->{'then'};

        if ( defined($then) ) {
            $console = 1 if ( exists( $then->{'console'} ) );
            my $usr = $then->{'user'};

            foreach my $usertarget ( @{$usr} ) {
                $users{$usertarget} = $usertarget;
            }
        }
        my $otherwise = $rule->{'otherwise'};
        if ( defined($otherwise) ) {
            $console = 1 if ( exists( $otherwise->{'console'} ) );
            my $usr = $then->{'user'};

            foreach my $usertarget ( @{$usr} ) {
                $users{$usertarget} = $usertarget;
            }
        }
    }

    for my $user ( keys %users ) {
        my $usertarget = "";

        if ( $user eq '*' ) {
            $usertarget = <<"END"

set \$.send.allusers = 1;

ruleset(name="allusersaction") {
    if (\$.send.allusers == 1) then {
        action(type="omusrmsg" users="*" template="WallIndicatorTemplate")
        set \$.send.allusers = 0;
    }
}
END
        } else {
            $usertarget = <<"END"

set \$.send.user.${user} = 1;

ruleset(name="useraction_${user}") {
    if (\$.send.user.${user} == 1) then {
        action(type="omusrmsg" users="${user}" template="StdUsrMsgIndicatorTemplate")
        set \$.send.user.${user} = 0;
    }
}
END
        }

        push @targets, $usertarget;
    }

    if ( defined($console) ) {
        my $consoletarget = <<"END";

set \$.send.console = 1;

ruleset(name="consoleaction") {
    if (\$.send.console == 1) then {
	action(type="omfile" file="/dev/console" Template="StdUsrMsgIndicatorTemplate")
        set \$.send.console = 0;
    }
}
END

        push @targets, $consoletarget;
    }

    $out = join "\n", @targets;

    return $out;
}

# This builds a data structure that maps from target
# to selector list for that target
sub read_config {
    my ( $config, $target ) = @_;

    my $facilitylist = get_node( $config, 'facility' );
    my $msgprop      = get_node( $config, 'msg' );
    my $msgregexlist = $msgprop->{'regex'};

    if ( !defined($facilitylist) && !defined($msgregexlist) ) {
        warn
"WARNING: At least one syslog facility or message regex should be configured per target!\n";
        return;
    }

    foreach my $element ( @{$facilitylist} ) {
        my $facility = $element->{tagnode};
        my $loglevel = $element->{'level'};

        $facility = $facmap{$facility} if ( $facmap{$facility} );
        $loglevel = '*' if ( $loglevel eq 'all' );

        $entries{$target} = {} unless $entries{$target};
        add_target_selector( $facility . '.' . $loglevel, $target );
    }

    foreach my $regex ( @{$msgregexlist} ) {
        $entries{$target} = {} unless $entries{$target};
        add_target_msgregex( $regex, $target );
    }

    # This is a file target so we set size and files
    if ( $target =~ m:^/var/log/: ) {
        set_target_param( $config, $target, 'size' );
        set_target_param( $config, $target, 'files' );
    }
    return;
}

sub print_outchannel {
    my ( $fh, $channel, $target, $size ) = @_;

    # Verify there is something to print
    return
      unless ( $entries{$target}{selector} || $entries{$target}{msgregex} );

# Force outchannel size to be 1k more than logrotate config to guarantee rotation
    $size = ( $size + 5 ) * 1024;
    print $fh
"\$outchannel $channel,$target,$size,/usr/sbin/logrotate ${LOGROTATE_CFG_DIR}/$channel\n";
    if ( $entries{$target}{selector} ) {
        print $fh join( ';', @{ $entries{$target}{selector} } ),
          " :omfile:\$$channel\n";
    }
    if ( $entries{$target}{msgregex} ) {
        foreach my $regex ( @{ $entries{$target}{msgregex} } ) {
            print $fh ":msg, ereregex, \"${regex}\" :omfile:\$$channel\n";
        }
    }
    return;
}

# rsyslog seems to support template names up to 127 characters (see
# doNameLine in runtime/conf.c).
#
# So that leaves 114 characters for host:
# - IPv6 addresses are 39 characters max
# - IPV4 addresses are 15 characters max
# - Linux limits host names to 64 (RFC1123 section 2: MUST)
# - POSIX limits host names to 255 characters (RFC1123 section 2: SHOULD).
#
# We'll just use as much of the host specifiacation as
# possible. Should be sufficient in almost all cases (i.e., only very
# long host names will get truncated).
sub get_override_template_name {
    my ( $host, $severity ) = @_;
    return substr( "vyatta_FOR_${severity}_${host}", 0, 127 );
}

#
# Process the facility override configuration
#
sub add_override_facility_targets {
    my ( $config, $host, $facility_override ) = @_;

    # Needed for print_templates
    $facility_override = $facmap{$facility_override}
      if ( $facmap{$facility_override} );
    $fac_override{$host} = $facility_override;

    my $facilitylist = get_node( $config, 'facility' );

    return unless defined($facilitylist);

    foreach my $element ( @{$facilitylist} ) {
        my $facility = $element->{tagnode};
        my $loglevel = $element->{'level'};

        $facility = $facmap{$facility} if ( $facmap{$facility} );

        for ( my $sev = $SEVERITY_VALS{$loglevel} ; $sev >= 0 ; --$sev ) {
            my $target =
              "\@${host};" . get_override_template_name( $host, $sev );
            $entries{$target} = {} unless $entries{$target};
            add_target_selector( $facility . '.=' . $SEVERITY_NAMES[$sev],
                $target );
        }
    }
    return;
}

#
# Print out command to input for log socket and
# rate limiting parameters
#
sub print_rate_limit_settings {
    my ($out) = @_;

    if ( defined($rl_interval) ) {
        print $out <<"END";
\$imjournalRateLimitInterval $rl_interval
\$imjournalRateLimitBurst $rl_burst
END
    }
    return;
}

sub print_discard_rules {
    my ($out) = @_;

    return if !@discard_regexs;

    foreach my $regex (@discard_regexs) {
        print $out ":msg, ereregex, \"${regex}\" stop\n";
    }
    return;
}

#
# Print out configured facility override templates
#
sub print_override_templates {
    my ($fh) = @_;

# Use _SYSTEMD_UNIT with SYSLOG_IDENTIFIER so that full unit name is printed,
# eg: sshd@blue.service - this is structured data from imjournal, so the properties
# are case-sensitive
    my $fmt =
'<%pri%>1 %timestamp:::date-rfc3339% %$!_HOSTNAME% %$!_SYSTEMD_UNIT:1:32% %syslogtag:1:32% %msgid% %structured-data%%msg:::sp-if-no-1st-sp%%msg%';
    foreach my $host ( keys %fac_override ) {
        for ( my $sev = 0 ; $sev < 8 ; ++$sev ) {
            my $prival = $FACILITY_VALS{ $fac_override{$host} } | $sev;
            print $fh '$template '
              . get_override_template_name( $host, $sev )
              . ",\"<${prival}>${fmt}\",casesensitive\n";
        }
    }
    return;
}

#
# Get a config node
#
sub get_node {
    my ( $config, $tag ) = @_;
    if ( ref($config) eq "HASH" ) {
        return $config->{$tag}
          if ( ref( $config->{$tag} ) eq "ARRAY"
            || ref( $config->{$tag} ) eq "HASH" );
    }
    return;
}

#
# Process the global logging destination configuration
#
sub get_global_logging_config {
    my ($config) = @_;

    my $globalcfg = get_node( $config, 'global' );
    read_config( $globalcfg, $MESSAGES )
      if ( defined($globalcfg) );
    return;
}

#
# process console logging destination configuration
#
sub get_console_logging_config {
    my ($config) = @_;

    my $consolecfg = get_node( $config, 'console' );
    read_config( $consolecfg, $CONSOLE )
      if ( defined($consolecfg) );
    return;
}

#
# Process source interface for remote hosts configuration
#
sub get_src_intf {
    my ($config) = @_;
    return unless defined $config;
    my $src_intf;
    $src_intf = $config->{'source-interface'}
      if defined $config->{'source-interface'};
    return $src_intf;
}

sub get_static_host_ip {
    my ( $config, $host ) = @_;

    return unless defined( $config->{'static_hosts'} );

    foreach my $ele ( @{ $config->{'static_hosts'} } ) {
        return $ele->{inet} if ( $ele->{tagnode} eq $host );
    }
    return;
}

#
# Get active config's IP address
# Expects Vyatta Statistics format
# {
#   "interfaces": {
#     "statistics": {
#       "interface": []
#     }
#   }
# }
#
sub get_active_ip {
    my ( $config, $dev, $host, $host_cfg ) = @_;
    return unless defined $dev;
    return unless defined $config->{interfaces}->{statistics}->{interface};

    my @arr;
    @arr = @{ $config->{host} } if defined $config->{host};
    my $index;
    if ( !defined($host_cfg) ) {
        foreach my $i ( 0 .. $#arr ) {
            my ( $TARGET, $port ) =
              get_target_port( $config->{host}[$i]->{tagnode} );
            if ( $TARGET eq $host ) {
                $index = $i;
                last;
            }
        }
    }
    my @active_interfaces =
      @{ $config->{interfaces}->{statistics}->{interface} };
    my $address;
    foreach my $active_intf (@active_interfaces) {
        if (   $active_intf->{name} eq $dev
            && $active_intf->{'admin-status'} eq "up" )
        {

            my ( $TARGET, $port );
            if ( defined($host_cfg) ) {
                $TARGET = $host_cfg->{'hostname'};
                $port   = $host_cfg->{'port'};
            } else {
                my $nm = $config->{host}[$index]->{tagnode};

                # Pick first AFINET matching address found
                ( $TARGET, $port ) = get_target_port($nm);
            }

            my $thost;
            $thost = get_static_host_ip( $config, $TARGET );
            $thost = $TARGET if not defined $thost;

            my $taddr = NetAddr::IP->new($thost);

            # $afinet is 4 when we fail to resolv $thost
            # This is a problematic corner case where address
            # isn't resolvabe now but may become resolvable
            # later.
            my $afinet = 4;
            if ( defined($taddr) ) {
                my ($tip) = Net::IP::ip_splitprefix($taddr);
                $afinet = Net::IP::ip_is_ipv6($tip) ? 6 : 4;
            }
            foreach my $active_ip ( @{ $active_intf->{addresses} } ) {
                my $if_addr     = NetAddr::IP->new( $active_ip->{address} );
                my ($ACTIVE_IP) = Net::IP::ip_splitprefix($if_addr);
                my $if_afinet   = Net::IP::ip_is_ipv6($ACTIVE_IP) ? 6 : 4;

                next if ( $afinet != $if_afinet );
                $address = $active_ip->{address};
                last;
            }

            openlog( "syslog", "", LOG_USER );
            my %afinet_map = ( 4 => "inet", 6 => "inet6" );
            my $addr;
            $addr = ( split( '/', $address ) )[0] if defined $address;
            if ( $afinet == 4 ) {
                if ( defined($address) ) {
                    $si_list .= "$dev $afinet_map{$afinet} $addr\n";
                    syslog( LOG_INFO,
                        "Logging to IPv4 hosts enabled using source address "
                          . "$address on interface $dev\n" );
                } else {
                    $si_list .= "$dev $afinet_map{$afinet}\n";
                    syslog( LOG_WARNING,
                            "Logging to IPv4 hosts disabled until $dev has an "
                          . "IPv4 address and is up" );
                    warn
"Warning: Logging to IPv4 hosts disabled until $dev has an "
                      . "IPv4 address and is up\n";
                }
            } elsif ( $afinet == 6 ) {
                if ( defined($address) ) {
                    $si_list .= "$dev $afinet_map{$afinet} $addr\n";
                    syslog( LOG_INFO,
                        "Logging to IPv6 hosts enabled using source address "
                          . "$address on interface $dev\n" );
                } else {
                    $si_list .= "$dev $afinet_map{$afinet}\n";
                    syslog( LOG_WARNING,
                            "Logging to IPv6 hosts disabled until $dev has an "
                          . "IPv6 address and is up" );
                    warn
"Warning: Logging to IPv6 hosts disabled until $dev has an "
                      . "IPv6 address and is up\n";

                }
            }
            closelog();

            # Trim netmask
            $address =~ s/\/.*// if defined $address;
            last;
        }
    }
    return $address;
}

#
# Process remote host logging destination configuration
#
sub get_host_logging_config {
    my ($config) = @_;

    my $hostlist = get_node( $config, 'host' );
    if ( defined($hostlist) ) {
        foreach my $element ( @{$hostlist} ) {
            my $host     = $element->{tagnode};
            my $hostcfg  = $element;
            my $override = $hostcfg->{'facility-override'};
            if ( defined($override) ) {
                add_override_facility_targets( $hostcfg, $host, $override );
            } else {
                read_config( $hostcfg, $host );
            }
        }
    }
    return;
}

#
# process a user defined file logging destination configuration
#
sub get_file_logging_config {
    my ($config) = @_;

    my $filelist = get_node( $config, 'file' );
    if ( defined($filelist) ) {
        foreach my $element ( @{$filelist} ) {
            my $file   = $element->{tagnode};
            my $target = '/var/log/user/' . $file;
            read_config( $element, $target );
        }
    }
    return;
}

#
# process a "user" logging destination
#
sub get_user_logging_config {
    my ($config) = @_;

    my $userlist = get_node( $config, 'user' );
    if ( defined($userlist) ) {
        foreach my $element ( @{$userlist} ) {
            my $user        = $element->{tagnode};
            my $user_target = $user;
            $user_target = '*' if ( $user eq 'all' );
            read_config( $element, ':omusrmsg:' . $user_target );
        }
    }
    return;
}

sub get_target_port {
    my ($host) = @_;

    my $target = $host;
    my $port   = $SYSLOG_PORT;

    # Target examples: 1.1.1.1, 1.1.1.1:514, [1::1], [1::1]:514
    my @hostandport = split( /:([^:\]]+)$/, $target );
    if ( defined( $hostandport[1] ) ) {
        $target = $hostandport[0];
        $port   = $hostandport[1];
    }
    $target =~ s/[\[\]]//g;

    return ( $target, $port );
}

#
# Get target and template from facility-override host:
# Host format: @<hostip>;<template>
#
sub get_override_target_template {
    my ($host) = @_;

    $host =~ s/^@//g;
    return split( /;/, $host );
}

#
# Return the action statement appropriate for the VRF implementation and source
# address
#
sub get_action {
    my ( $host, $config, $vrf, $host_cfg ) = @_;
    my ( $TARGET, $PORT );
    my @fwd_actions;
    my ( $dev, $ADDRESS );

   # Use SYSTEMD_UNIT with SYSLOG_INDENTIFIER so that full unit name is printed,
   # eg: sshd@blue.service
    my $template_str = ' Template="SystemdUnitTemplate"';

    if ( defined($host_cfg) ) {
        $TARGET = $host_cfg->{'hostname'};
        $PORT   = $host_cfg->{'port'};
        my $dev = get_src_intf($host_cfg);
        $ADDRESS = get_active_ip( $config, $dev, $TARGET, $host_cfg );
    } else {

        # Extract TARGET & PORT from host string
        if ( $host =~ /^:/ ) {

            # Target is a user terminal of the form :omusrmsg:<user>
            $TARGET = $host;
            return "\t$TARGET\n";
        } elsif ( $host =~ m/^@/ ) {
            my ( $ohost, $template ) = get_override_target_template($host);
            if ( defined($ohost) ) {
                ( $TARGET, $PORT ) = get_target_port($ohost);
                $template_str = " Template=\"$template\""
                  if ( defined($template) );
            } else {
                $TARGET = $host;
                $PORT   = $SYSLOG_PORT;
            }
        } else {
            ( $TARGET, $PORT ) = get_target_port($host);
        }

        $dev = get_src_intf($config);
        $ADDRESS = get_active_ip( $config, $dev, $TARGET );
    }

    if ( defined($dev) && !defined($ADDRESS) ) {
        $si_list .= "$dev\n";
        return;
    }

    # MAP functions follow
    #
    my $fetch_from_server = sub {
        die("ERROR: fetch-from-server not yet implemented");
    };
    my $gen_cipher_suite = sub {
        my ($config) = @_;
        return "" unless defined $config->{'cipher-suite'};
        my @ciphers;
        foreach my $parent ( @{ $config->{'cipher-suite'} } ) {
            push @ciphers, $parent->{cipher};
        }
        return "cipherstring=" . join( ":", @ciphers );
    };
    my $gen_peer_list = sub {
        my ($p) = @_;
        return $fetch_from_server->($_) if defined $p->{'fetch-from-server'};
        return $p->{fingerprint}        if defined $p->{fingerprint};
        return $p->{peer}               if defined $p->{peer};
    };
    my $gen_ca_list = sub {
        my ($ca) = @_;
        return "${DEFAULT_AUTH_LOCATION}/$ca->{file}";
    };
    my $gen_cert_list = sub {
        my ($cert) = @_;
        return "${DEFAULT_AUTH_LOCATION}/$cert->{certificate}";
    };
    my $gen_key_list = sub {
        my ($cert) = @_;
        return "${DEFAULT_AUTH_LOCATION}/$cert->{key}";
    };

    # Main
    #
    my $target_static_ip = get_static_host_ip( $config, $TARGET );
    $TARGET = $target_static_ip if $target_static_ip;

    my $gen_action_map = sub {
        my ($c)            = @_;
        my $encrypt_params = $c->{tls};
        my $auth_params    = $encrypt_params->{authentication};
        my $ca_params      = $encrypt_params->{'certificate-authority'};
        my $cert_params    = $encrypt_params->{'local-certificate'};

        # What action are we building?
        my $act_config;
        my $tls_config;
        $c->{protocol} = 'udp' unless defined $c->{protocol};
        $c->{protocol} = 'udp' if ( $TARGET =~ /console/ );
        $c->{'ip-port'} = '514';
        $c->{'ip-port'} = $PORT if defined $PORT;
        if ( $c->{protocol} eq 'tcp' ) {
            if (%$encrypt_params) {
                $tls_config = {
                    "tls-version" => $encrypt_params->{'tls-version'},
                    "gnutlsPriorityString" =>
                      $gen_cipher_suite->($encrypt_params),
                    "StreamDriver"               => "ossl",
                    "StreamDriverAuthMode"       => $auth_params->{mode},
                    "StreamDriverPermittedPeers" => [
                        map { $gen_peer_list->($_) } @{ $auth_params->{peers} }
                    ]
                };
            }
            $act_config = {
                "type"     => 'omfwd',
                "address"  => $ADDRESS,
                "protocol" => $c->{protocol},
                "ip-port"  => $c->{'ip-port'},
                "target"   => $TARGET,
                "template" => $template_str,
                "tls"      => $tls_config
            };
        } elsif ( $c->{protocol} eq 'udp' ) {
            $act_config = {
                "type"     => 'omfwd',
                "address"  => $ADDRESS,
                "protocol" => $c->{protocol},
                "ip-port"  => $c->{'ip-port'},
                "target"   => $TARGET,
                "template" => $template_str,
            };
        } else {
            die(
"ERROR: Couldn't find suitable protocol config for host $c->{tagnode}.\n"
            );
        }
        $act_config->{device} = "vrf$vrf" if defined $vrf;

        return $act_config;
    };

    #
    # Generate forwarding actions
    #

    my $cert_locations = '';
    #
    # TODO: Convert the vyatta-action.template to populate the full action line
    # including syslog selectors
    if ( defined($host_cfg) ) {
        push @fwd_actions, map { $gen_action_map->($_) } $host_cfg;
    } else {
        my $index = 0;
        my @arr;
        @arr = @{ $config->{host} } if defined $config->{host};
        if ( $TARGET =~ /console/ ) {
            $config->{host}[0]->{tagnode} = $TARGET;
        }
        foreach my $i ( 0 .. $#arr ) {
            if ( $config->{host}[$i]->{tagnode} eq $TARGET ) {
                $index = $i;
            }
        }
        #
        # TODO: Omfwd does not support per action certificates.
        my @ca;
        if ( defined( $config->{host}[$index]->{tls} ) ) {
            my $encrypt_params = $config->{host}[$index]->{tls};
            my $ca_params      = $encrypt_params->{'certificate-authority'};
            my $cert_params    = $encrypt_params->{'local-certificate'};
            if ( !defined($ca_params) || !defined($cert_params) ) {
                print
"Error: TLS configured for host $config->{host}[$index]->{tagnode}
	        without proper Certificates.\n";
                return;
            }
            @ca = map { $gen_ca_list->($_) } @{$ca_params}
              if defined $ca_params;
            $cert_locations = <<"END";
global(
    DefaultNetstreamDriverCAFile="$ca[0]"
    DefaultNetstreamDriverCertFile="${DEFAULT_AUTH_LOCATION}/$cert_params->{certificate}"
    DefaultNetstreamDriverKeyFile="${DEFAULT_AUTH_LOCATION}/$cert_params->{key}"
)
END
        }

        push @fwd_actions,
          map { $gen_action_map->($_) } $config->{host}[$index];
    }

    open( my $fh, '<', "$ACTION_TEMPLATE" )
      or die "Could not find vyatta-action.template";
    my $tt = Template->new();
    my %tree_in = ( 'actions' => \@fwd_actions );
    my $finished_template;
    $tt->process( $fh, \%tree_in, \$finished_template )
      or die "Could not fill out rsyslog action template.\n";
    close($fh);

    # Clean up a little
    $finished_template =~ s/\s+/ /g;
    $finished_template =~ s/ $//g;

    $finished_template = $finished_template . "\n";
    $finished_template = $finished_template . $cert_locations
      if ( $TARGET !~ /console/ );

    return $finished_template;
}

sub write_log_rotation_file {
    system("/opt/vyatta/sbin/vyatta_update_logrotate.pl @_ 1") == 0
      or die "Can't genrate global log rotation config: $!";
    return;
}

#
# Generate VRF specifc (instances) Syslog actions
#
sub generate_instance_actions {
    my ( $config, $vrf ) = @_;

    my $instance_actions;
    open my $out, '>', \$instance_actions;

    print_rate_limit_settings($out);
    print_discard_rules($out);
    print_override_templates($out);

    #
    # TODO: Allow multiple Certificate Authorities
    my $strike = 0;
    foreach my $h ( @{ $config->{host} } ) {
        if ( $strike == 1 && defined $h->{tls} ) {
            print "Error: Only one remote host connection is configurable
	      with TLS.\n";
            return;
        }
        $strike = 1 if defined $h->{tls};
    }

    my $files;
    my $size;
    foreach my $target ( keys %entries ) {
        if ( $target eq $MESSAGES ) {
            $size  = get_target_param( $target, 'size' );
            $files = get_target_param( $target, 'files' );
            print_outchannel( $out, 'global', $target, $size );
            write_log_rotation_file( $files, $size );
        } elsif ( $target =~ m:^/var/log/user/: ) {
            my $file = basename($target);
            $size  = get_target_param( $target, 'size' );
            $files = get_target_param( $target, 'files' );
            print_outchannel( $out, 'file_' . $file, $target, $size );
            write_log_rotation_file( $file, $files, $size );
        } else {
            if ( $entries{$target}{selector} ) {
                my $action = get_action( $target, $config, $vrf );
                print $out join( ';', @{ $entries{$target}{selector} } ),
                  $action
                  if defined $action;
            }
            if ( $entries{$target}{msgregex} ) {
                foreach my $regex ( @{ $entries{$target}{msgregex} } ) {
                    my $action = get_action( $target, $config, $vrf );
                    print $out ":msg, ereregex, \"${regex}\"", $action
                      if defined $action;
                }
            }
        }
    }
    close $out;

    return split /^/, $instance_actions if defined $instance_actions;
}

#
# Setup the configuration file for a local
# log destinations
#
sub update_rsyslog_config {
    my $ret;
    my $config;
    my $client = Vyatta::Configd::Client->new();

    # Default VRF (or non vrf) syslog config
    my $partial_config;
    $partial_config = $client->tree_get_hash("system syslog")
      if $client->node_exists( $Vyatta::Configd::Client::AUTO,
        "system syslog" );
    $config->{system} = $partial_config;

    # VRF specific syslog config
    $partial_config = $client->tree_get_hash("routing routing-instance")
      if $client->node_exists( $Vyatta::Configd::Client::AUTO,
        "routing routing-instance" );
    $config->{routing} = $partial_config;

    # Get active state if source-interface is configured
    my $statistics;
    foreach
      my $instance ( $config, @{ $config->{routing}->{'routing-instance'} } )
    {
        if ( defined( $instance->{system}->{syslog}->{'source-interface'} ) ) {
            $statistics = $client->tree_get_full_hash("interfaces statistics");
            last;
        }
    }

    my @actions;
    my $vrf;
    my $static_hosts;
    foreach
      my $pconfig ( $config, @{ $config->{routing}->{'routing-instance'} } )
    {
      # TODO: remove use globals and do direct translation between Vyatta Config
      # hash to Syslog config file.
        undef %entries;
        undef %fac_override;

        $vrf = $pconfig->{'instance-name'};
        $static_hosts =
          $pconfig->{'system'}->{'static-host-mapping'}->{'host-name'};
        $pconfig = $pconfig->{'system'}->{'syslog'}
          if defined $pconfig->{system}->{syslog};
        $pconfig->{interfaces} = $statistics if defined $statistics;
        next unless defined $pconfig;
        $pconfig->{'static_hosts'} = $static_hosts if defined $static_hosts;

        get_global_logging_config($pconfig);
        get_console_logging_config($pconfig);
        get_file_logging_config($pconfig);
        get_user_logging_config($pconfig);
        get_host_logging_config($pconfig);
        get_rate_limit_parms($pconfig);
        get_discard_regexs($pconfig);
        my @action = generate_instance_actions( $pconfig, $vrf );
        push @actions, @action if ( $action[0] ne '' );
    }

    my $econfig;
    my $partial_econfig;
    $partial_econfig = $client->tree_get_hash("system syslog-enhanced")
      if $client->node_exists( $Vyatta::Configd::Client::AUTO,
        "system syslog-enhanced" );

    if ( defined($partial_econfig) ) {
        push @actions, "set \$.tnow = \$\$UPTIME;\n";
        push @actions, "set \$!severity = \$syslogseverity;\n";
        push @actions, "set \$!facility = \$syslogfacility;\n";
        push @actions, "ruleset(name=\"setpri\") {\n";
        push @actions, "set \$!priority = (\$!facility * 8) + \$!severity;\n";
        push @actions, "}\n";
    }
    $econfig->{system} = $partial_econfig;

    # VRF specific syslog config
    $partial_econfig = $client->tree_get_hash("routing routing-instance")
      if $client->node_exists( $Vyatta::Configd::Client::AUTO,
        "routing routing-instance" );
    $econfig->{routing} = $partial_econfig;

    $statistics = $client->tree_get_full_hash("interfaces statistics")
      if $client->node_exists( $Vyatta::Configd::Client::AUTO, "interfaces" );

    $econfig->{interfaces} = $statistics if defined $statistics;

    $static_hosts =
      $econfig->{'system'}->{'static-host-mapping'}->{'host-name'};
    $econfig->{'static_hosts'} = $static_hosts if defined $static_hosts;

    my $certs = build_tls_certificates($econfig);
    my $files = build_targets($econfig);
    my $rls   = build_rules($econfig);
    my $journal_rate_limit = build_journal_input_rate_limit($econfig);

    push @actions, $journal_rate_limit;
    push @actions, $certs;
    push @actions, $files;
    push @actions, $rls;

    #
    # Don't run rsyslog if not configured
    if ( !@actions ) {
        unlink $SYSLOG_CONF;
        unlink $SOURCE_INTERFACE_FILE;
        #
        # Restart service
        system("systemctl reset-failed rsyslog");
        system("service rsyslog restart");
        #
        # Success
        return 0;
    }

    if ( open( my $si_fh, '>', $SI_TMP_FILE ) ) {
        print $si_fh $si_list;
        close $si_fh;
        rename( $SI_TMP_FILE, $SOURCE_INTERFACE_FILE );
    }

    #
    # Write final /etc/rsyslog.d/vyatta-log.conf if new config
    # differs.
    my @original_actions;
    if ( -r $SYSLOG_CONF ) {
        open my $original, '<', $SYSLOG_CONF;
        @original_actions = <$original>;
        close $original;
    }

    if ( array_diff( @actions, @original_actions ) ) {
        my $dirname = dirname($SYSLOG_CONF);
        mkdir $dirname, 600 unless ( -d $dirname );
        open( my $fh, '>', $SYSLOG_CONF )
          or die "Could not open file '$SYSLOG_CONF' $!";
        print $fh @actions;
        close $fh;
        #
        # Restart service
        system("systemctl reset-failed rsyslog");
        system("service rsyslog restart");
        #
        # Success
        return 0;
    }

    #
    # Success, but no changes made...
    return 0;
}

1;
