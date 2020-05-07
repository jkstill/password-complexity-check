#!/usr/bin/env perl

use strict;
use warnings;
use verbose;
use IO::File;
use Data::Dumper;

my $v = verbose->new(
	{
		VERBOSITY=>0,
		LABELS=>1,
		TIMESTAMP=>0,
		HANDLE=>*STDERR
	}
);


my $pxChk = new PwdCPX( 
	{
		#required_complexity => 1 * 10**20,
		required_complexity => 1 * 10**14, # approx 8 characters - upper,lower,digit,special
	}
);

my @pwAry = (
	'this^Misatest',
	'thisisatest',
	'Us3AllCharacter%Types'
);


=begin comment 

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

=end comment
=cut


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
		#print qq {
		#
		#r: $r
		#
		#required complexity: $pxChk->{required_complexity}
		#complexity: $pxChk->{complexity}
		#
		#};
	}

}

print qq {

validPwdCount: $validPwdCount
totalPwdCount: $totalPwdCount

};


package PwdCPX;

use Data::Dumper;
use strict;
use warnings;

my $complexityLevel = 1;  # just a placeholder for now

sub new {
	my ($class, $args) = @_;

	#my $self = {
	#password => $args->{password},
	#};
	my $self={};
	foreach my $key ( keys %{$args} ) {
		$self->{$key} = "$args->{$key}";
	}

	return bless $self, $class;
}

sub validateCharacters {
	my $self = shift;

	# no characters below 32
	# no characters above 127
	

	if ( $self->{password} =~ /( [\x00-\x1f] | [\x7f-\xff] )/ ) {
		return 0;
	} else {
		return 1;
	}
}

sub validatePassword {
	my $self = shift;

	my $r = $self->validateCharacters;
	if ($r == 0) {
		return 0;
	}

	$self->getComplexity;

	#print "self: ", Dumper($self);

	if ( $self->{complexity} < $self->{required_complexity} ) {
		return 0;
	}


	return 1;

}

sub factorial {
	my $max = shift;

	my $f=1;
	my $i=1;
	$f *= ++$i while $i < $max;
	return $f;
}

sub getComplexity {
	my $self = shift;

	my $charHash =  $self->getCharClasses;

	$v->print(2, '$charHash{}:  ', [ Dumper($charHash) ] );

	my $keySpace;
	foreach my $class ( keys %{$charHash} ) {
		$keySpace += $charHash->{$class};
	}

	my $pwLen = length($self->{password});

	# combination 
	my $n = factorial($keySpace);
	my $r = factorial($keySpace - $pwLen);
	$self->{complexity} = $n / $r;

	$v->print(2, 'complexity{}:  ', [ 'n: ' => $n, 'r: ' => $r, 'complexity: ' => $self->{complexity} ] );

	return;

}


sub getCharClasses {
	my $self = shift;
	my $classHash = {};

	my $password = $self->{password};

	$v->print(1, "Password: ",  [$password]);

	$v->print(1, "checking for character classes ",  []);

	# return a hash with the number of characters per class

	# upper case?
	if ( $password =~ /[A-Z]/ ) {
		$classHash->{upper} = 26;
	}

	# lower case?
	if ( $password =~ /[a-z]/ ) {
		$classHash->{lower} = 26;
	}

	# digits?
	if ( $password =~ /[0-9]/ ) {
		$classHash->{digits} = 10;
	}
	
	# special characters?
	if ( 
		$password =~ /( [\x21-\x2f] 
			| [\x3a-\x40] 
			| [\x5b-\x60] 
			| [\x7b-\x7e] 
		)/gox 
	) {
		$classHash->{special} = 33;
	}


	return $classHash;
}



