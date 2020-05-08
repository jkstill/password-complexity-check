#!/usr/bin/env perl

use strict;
use warnings;
use verbose;
use IO::File;
use Data::Dumper;
use Data::Password::Permutation;

my $pxChk = new Data::Password::Permutation( 
	{
		#required_complexity => 1 * 10**14, # approx 8 characters - upper,lower,digit,special
		required_complexity => 5 * 10**26, #
		debug => 0,
	}
);

my $file = '/home/jkstill/security/SecLists/Passwords/Common-Credentials/10k-most-common.txt';

my $fh = IO::File->new;

$fh->open($file,'<') or die "could not open $file - $!\n";

my $validPwdCount=0;
my $totalPwdCount=0;

while (<$fh>) {
	chomp;
	$pxChk->{password} = $_;

	$totalPwdCount++;

	my $r = $pxChk->validatePassword;

	if ($r) {
		$validPwdCount++;
		$pxChk->debug("password: $pxChk->{password}", 
			[
				"required complexity: $pxChk->{required_complexity}",
				"         complexity: $pxChk->{complexity}",
			]
			,1
		);

	}

}

print qq {

validPwdCount: $validPwdCount
totalPwdCount: $totalPwdCount

};


