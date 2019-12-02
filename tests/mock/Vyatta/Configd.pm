#
# Copyright (c) 2019, AT&T Intellectual Property
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
package Vyatta::Configd;
package Vyatta::Configd::Client;

use File::Slurp;
use JSON::XS qw(decode_json encode_json);

use warnings;
use strict;

sub new {
	my $self = { };
	bless $self => __PACKAGE__;
	return $self;
}

sub get_root {
	my ($config, $path) = @_;
	my @keys = split( /\s+/, $path );
	my $found = 0;
	for my $key (@keys) {
		$found = 0;
		$found = 1 if defined $config->{$key};
		# Need to preserve the last key in the path
		last if ($keys[-1] eq $key);
		$config = $config->{$key} if defined $config->{$key};
	}
	return %{$config} if ($found == 1);
}

sub tree_get_hash {
	my ($self, $path) = @_;
	my $json = read_file("$::tmpdir/.tree_get_hash.tmp", { binmode => ':raw' });
	my %config = %{ decode_json $json };
	%config = get_root(\%config, $path);
	return \%config;
}

sub tree_get_full_hash {
	return tree_get_hash(@_);
}

sub node_exists {
	my ($self, $db, $path) = @_;
	my $json = read_file("$::tmpdir/.tree_get_hash.tmp", { binmode => ':raw' });
	my %config = %{ decode_json $json };
	if(get_root(\%config, $path)) {
		return 1;
	}
	return;
}

1;
