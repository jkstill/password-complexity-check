#!/usr/bin/env perl

use strict;
use warnings;
use IO::File;
use Data::Dumper;
$Data::Dumper::Indent=2; # 1= more compact indentation, 2=default
$Data::Dumper::Sortkeys=1; # sorted hash keys handier for consistency
$Data::Dumper::Maxrecurse=3;
$Data::Dumper::Maxdepth=3;
$Data::Dumper::Terse=0;

use Getopt::Long;
use Data::Password::Permutation;

my $dictFile = '';
my $passwordFile = '';
my $complexity = 1.3 * 10**44;
my $singletonPassword=0;
my $csvOutput=0;
my ($showFail, $showPass)=(1,0);
my $help=0;


GetOptions (
	"dict-file=s" => \$dictFile,
	"password-file=s" => \$passwordFile,
	"password!" => \$singletonPassword,
	"show-fail!" => \$showFail,
	"show-pass!" => \$showPass,
	"use-csv!" => \$csvOutput,
	"complexity=s" => \$complexity,
	"h|help!" => \$help,
) or die usage(1);

$complexity = sprintf("%12e",eval{$complexity});
#print "Complexity: $complexity\n";

if ($help) {
	usage();
	exit;
}

if ($singletonPassword and $passwordFile) {
	usage();
	warn "too many options\n";
	die;	
}

if (! ( $singletonPassword or $passwordFile ) ) {
	usage();
	warn "not enough options\n";
	die;
}


my $pwdFH;
my $usePwdFile=0;
if ($passwordFile) {

	$pwdFH = IO::File->new;
	$pwdFH->open($passwordFile,'<') or die "could not open $passwordFile - $!\n";
	$usePwdFile=1;
} elsif ($singletonPassword) {
	# nothing to do here other than check for existence of option
} else {
	warn "Not sure what you want me to do ...\n";
	die;
}

my $dictFH;
my $useDict=0;
my %dictWords=();
if ( $dictFile ) {
	$dictFH = IO::File->new;
	$dictFH->open($dictFile,'<') or die "could not open $dictFile - $!\n";
	$useDict=1;
}

if ($useDict) {
	warn "\nLoading Dictionary...\n";

	while(my $word = <$dictFH>) {
		# dunno ahead of time if DOS or Unix file
		#chomp $word;	
		$word =~ s/\r?\n//;
		$dictWords{$word}=0;
	}
}

warn "Checking Passwords...\n";


my $pxChk = new Data::Password::Permutation( 
	required_complexity => $complexity,
	#required_complexity => 5 * 10**26, # complexity required to exclude 'antidisestablishmentarianism'
	#required_complexity => 1.3 * 10**44, # complexity required to exclude 'Antidisestablishmentarianism'
	debug => 0,
	show_fail => $showFail,
	show_pass => $showPass,
	dictionary => \%dictWords,
);

# check the single password and exit
if ( ! $usePwdFile ) {

	# get the password from stdin
	print "Please Enter Password: ";
	my $password=<STDIN>;
	chomp $password;
	print "\n";
	$pxChk->{password} = $password;
	my $r = $pxChk->validatePassword;

	if ( $csvOutput ) {
		$pxChk->outputCSV(':');
	} else {
		$pxChk->output();
	}

	exit;
}

foreach my $password (<$pwdFH>) {
	# dunno ahead of time if DOS or Unix file
	$password =~ s/\r?\n//;

	next unless $password; # could be blank lines

	$pxChk->{password} = $password;

	my $r = $pxChk->validatePassword;

	if ( $csvOutput ) {
		$pxChk->outputCSV(':');
	} else {
		$pxChk->output();
	}

};



sub usage {

	use File::Basename;
	my $basename = basename($0);

	print qq {

$basename

usage: $basename 

  --dict-file      the file used to check if password is a dictionary word
                   this file is user supplied
                   no dictionary check is performed if the file is not provided

  --password-file  a file containing passwords to check

  --password       get password from stdin

  --complexity     the complexity required for a password to pass the check
                   default is 1.3 * 10**44
                   the value may be passed as an integer or as scientific notation
                   for instance, the following values work
                   105, 42, 10e45, 1000000000

  --show-fail      show passwords that failed - default is true

  --show-pass      show passwords that passed - default is false
                   use --no-show-pass to disable

  --use-csv        use CSV output

};


}

