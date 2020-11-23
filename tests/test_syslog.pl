#!/usr/bin/env perl

#
# Copyright (c) 2019-2020, AT&T Intellectual Property
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
use strict;
use warnings;
 
use Test2::Bundle::Extended -target => 'Test2::Mock';
use Test::TempDir::Tiny;
use Test::MockModule;
use Test::MockObject;

use lib 'lib';
our $fake_system = sub { return 0; };
use Test::Mock::Cmd 'system' => sub { $fake_system->(@_) };

use File::Slurp;
use JSON::XS qw(decode_json encode_json);

use Text::Diff;

use lib './mock';
use Vyatta::Configd;

use lib '../lib/';
use Vyatta::Syslog qw(update_rsyslog_config $SYSLOG_CONF $ACTION_TEMPLATE $SOURCE_INTERFACE_FILE);

my %cases;
my %input;
our $tmpdir;
BEGIN {
	# Create working dir
	$tmpdir = tempdir('.v-c-s.testing');
}

#
# Mock Vyatta::Syslog env
#
my $module = Test::MockModule->new('Vyatta::Syslog');
$module->mock('write_log_rotation_file', sub { return; });

undef $SYSLOG_CONF;
our $SYSLOG_CONF = "$tmpdir/vyatta-log.conf";
undef $ACTION_TEMPLATE;
our $ACTION_TEMPLATE = "../usr/share/rsyslog-configs/vyatta-action.template";
undef $SOURCE_INTERFACE_FILE;
our $SOURCE_INTERFACE_FILE = "../run/var/rsyslog/source_interface_list";

#
# Vyatta::Configd Mocking
#
sub mock_Configd_tree_get_hash {
	my ($hash) = @_;
	my $json = encode_json \%{$hash};
	write_file("$tmpdir/.tree_get_hash.tmp", { binmode => ':raw' }, $json);
}
sub unmock_Configd_tree_get_hash {
	unlink "$tmpdir/.tree_get_hash.tmp";
}
#
# END

sub read_test_results {
	my $ret = read_file("$tmpdir/vyatta-log.conf", err_mode => 'quiet');
	return "" if !defined $ret;
	return $ret;
}

sub get_test_expected_results {
	my ($test_files_dir) = @_;
	undef %cases;
	opendir(DIR, $test_files_dir) or die "Could not open $test_files_dir\n";
	while (my $filename = readdir(DIR)) {
		next unless -f "${test_files_dir}/$filename";
		my $filepath = "${test_files_dir}/$filename";
		$cases{$filename} = read_file($filepath);
	}
	closedir(DIR);
}

sub get_test_inputs {
	my ($test_files_dir) = @_;
	undef %input;
	opendir(DIR, $test_files_dir) or die "Could not open $test_files_dir\n";
	while (my $filename = readdir(DIR)) {
		print "Reading $filename input file\n";
		next unless -f "${test_files_dir}/$filename";
		my $filepath = "${test_files_dir}/$filename";
		my $json = read_file($filepath, { binmode => ':raw' });
		my %config = %{ decode_json $json };
		$input{$filename} = \%config;
	}
	closedir(DIR);
}

get_test_expected_results('fixture/syslog/good-rsyslog.d');
get_test_inputs('fixture/syslog/json-input');
#
# Test Vyatta Config Json to Syslog Config file conversion
foreach my $test (keys %input) {
	print "Testing [$test]\n";
	# Generate function output to test...
	#
	mock_Configd_tree_get_hash($input{$test});

	# Save STDERR
	#
	open(STDERR, '>' ,"/tmp/stderr.log");

	# RUN PROGRAM
	#
	update_rsyslog_config();
	#
	# END

	# Check if stderr is empty as well
	#
	my $filter = `cat "fixture/syslog/good-rsyslog.d/${test}.stderrfilter" 2>/dev/null`;
	my $in = `cat /tmp/stderr.log`;
	if ($in ne $filter) {
		is ($in, '', "$test");
	}
	unlink '/tmp/stderr.log';

	#
	#
	unmock_Configd_tree_get_hash();

	my $diff = diff(\$cases{$test}, \read_test_results());
	if ($diff ne q{}) {
		print $diff;
	}
	ok ($diff eq q{}, "$test");

}

# TODO: define test plan...
done_testing;
