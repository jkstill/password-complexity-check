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

use Pod::Usage;

use Getopt::Long;
use Data::Password::Permutation qw( STD CSV);



my $dictFile = '';
my $passwordFile = '';
my $complexity = 1.3 * 10**44;
my $singletonPassword=0;
my $outputFormat=STD;
my $requestedFormat='STD';
my ($showFail, $showPass)=(1,0);
my $fieldSeparator=',';


GetOptions (
	"dict-file=s" => \$dictFile,
	"password-file=s" => \$passwordFile,
	"password!" => \$singletonPassword,
	"show-fail!" => \$showFail,
	"show-pass!" => \$showPass,
	"format=s" => \$requestedFormat,
	"complexity=s" => \$complexity,
	"h|help!" => sub { pod2usage( -verbose => 1 ) },
	"man!" => sub { pod2usage( -verbose => 2 ) },
) or pod2usage(2);

$requestedFormat = uc($requestedFormat);

if ($requestedFormat eq 'STD' ) { $outputFormat = STD }
elsif ($requestedFormat eq 'CSV' ) { $outputFormat = CSV }
else { $outputFormat = STD }

$complexity = sprintf("%12e",eval{$complexity});
#print "Complexity: $complexity\n";

if ($singletonPassword and $passwordFile) {
	pod2usage( -verbose => 1 );
	warn "too many options\n";
	die;	
}

if (! ( $singletonPassword or $passwordFile ) ) {
	pod2usage( -verbose => 1 );
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
		$dictWords{$word}=1;
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
	format => $outputFormat,
	field_separator => $fieldSeparator,
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

	$pxChk->output();

	exit;
}

foreach my $password (<$pwdFH>) {
	# dunno ahead of time if DOS or Unix file
	$password =~ s/\r?\n//;

	next unless $password; # could be blank lines

	$pxChk->{password} = $password;

	my $r = $pxChk->validatePassword;

	$pxChk->output();

};


__END__

=head1 NAME

 
 pwdchk.pl 

=head1 SYNOPSIS

 Get the relative strength of a password via permutation as per the length of the password and the number of characters in the keyspace

 Use a threshold to determine if the strength is sufficient.

 Optionally include a dictionary file to eliminate dictionary words.

  --dict-file
  --password-file  
  --password       
  --complexity     
  --show-fail 
  --show-pass
  --format

=head1 Options

=over 8

=item B<--dict-file>

 the file used to check if password is a dictionary word
 this file is user supplied
 no dictionary check is performed if the file is not provided

=item B<--password-file>

 a file containing passwords to check

=item B<--password>

 get password from stdin

=item B<--complexity>

 the complexity required for a password to pass the check
 default is 1.3 * 10**44
 the value may be passed as an integer or as scientific notation
 for instance, the following values work
 105, 42, 10e45, 1000000000

=item B<--show-fail>

 show passwords that failed - default is true

=item B<--show-pass>

  show passwords that passed - default is false
  use --no-show-pass to disable

=item B<--format>

 STD or  CSV output. default is STD

=back

=head1 Examples

 As run from the dev directory without installing

 Password files from https://github.com/danielmiessler/SecLists

 perl -I lib  pwdchk.pl --password-file xato-net-10-million-passwords-1000000.txt --dict-file dict-words.txt

 perl -I lib  pwdchk.pl --password-file xato-net-10-million-passwords-1000000.txt   --no-show-fail --show-pass  --complexity 10e45

 echo Antidisestabl1shmentarianism | perl -I lib  pwdchk.pl   --password   --show-fail --show-pass  --complexity 1e45


=cut

