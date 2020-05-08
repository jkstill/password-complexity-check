#!/usr/bin/env perl

use strict;
use warnings;
use IO::File;
use Data::Dumper;
use Data::Password::Permutation;

my $pxChk = new Data::Password::Permutation( 
	{
		#required_complexity => 3 * 10**14, # approx 8 characters - upper,lower,digit,special
		#required_complexity => 5 * 10**26, # complexity required to exclude 'antidisestablishmentarianism'
		required_complexity => 1.3 * 10**44, # complexity required to exclude 'Antidisestablishmentarianism'
		debug => 0,
	}
);

my @pwAry = (
	'this^Misatest',
	'thisisatest',
	'j%4x!wpx',
	'Tj%4x!wpxH',
	'Us3AllCharacter%Types',
	'antidisestablishmentarianism',
	'antidisestablishmentarianisM',
	'Antidisestablishment4rianism',
	'Antidisestabl%shment4rianism',
);


foreach my $i ( 0..$#pwAry ) {

	$pxChk->{password} = $pwAry[$i];

	print "=== $i ==== $pwAry[$i] ====\n";

	my $r = $pxChk->validatePassword;

	#print  "        r: $r\n";
	print  "   Result: " . ( $r ? 'OK' : 'Fail' ) . "\n";
	printf "   required complexity: %12e\n", $pxChk->{required_complexity};
	printf "            complexity: %12e\n", $pxChk->{complexity};

};



