#!/usr/bin/env perl

use strict;
use warnings;
use IO::File;
use Data::Dumper;

use lib './lib';

use Data::Password::Permutation;

my $pxChk = new Data::Password::Permutation( 
	{
		required_complexity => 3 * 10**14, # approx 8 characters - upper,lower,digit,special
		debug => 0,
	}
);

my @pwAry = (
	'this^Misatest',
	'thisisatest',
	'j%4x!wpx',
	'Tj%4x!wpxH',
	'Us3AllCharacter%Types'
);


foreach my $i ( 0..$#pwAry ) {

	$pxChk->{password} = $pwAry[$i];

	print "=============== $i ===============\n";
	print "=============== $pwAry[$i] ===============\n";

	my $r = $pxChk->validatePassword;

	print qq {

   r: $r

   required complexity: $pxChk->{required_complexity}
            complexity: $pxChk->{complexity}

	};
};



