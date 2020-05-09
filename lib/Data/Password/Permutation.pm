
package Data::Password::Permutation;

use Data::Dumper;
use strict;
use warnings;
use Carp;

use Exporter qw(import);
our $VERSION=0.1;
our @EXPORT = qw(&factorial &getComplexity);
our @ISA=qw(Exporter);

=head1 new Permutation

 Possible hash parameters

 required_complexity : an integer representing minimum allowable complexity
 debug               : non-zero is debug
 show_pass           : 1 to show entries that pass - 0 to disable
 show_fail           : 1 to show entries that fail - 0 to disable
 fail_reason         : used internally - do not set
 dictionary          : hashref of dictionary words
 outoput_type        : CSV or STD - STD is default
 field_separator     : defaults to ',' for CSV output

=cut


sub new {
	my ($class, %args) = @_;

	my $self = bless \%args, $class;

	if ( ! exists($self->{debug}) ) { $self->{debug} = 0; }
	if ( ! exists($self->{fail_reason}) ) { $self->{fail_reason} = ''; }
	if ( ! exists($self->{show_pass}) ) { $self->{show_pass} = 0; }
	if ( ! exists($self->{show_fail}) ) { $self->{show_fail} = 1; }
	if ( ! exists($self->{output_type}) ) { $self->{output_type} = 'STD'; }

	return $self;
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

	$self->{fail_reason} = '';

	# check dictionary
	if ( $self->{dictionary} ) {
		if (exists( $self->{dictionary}{lc($self->{password})} ) ) {
			$self->{fail_reason} = 'dictword';
			return 0;
		}
	}

	if ( $self->{complexity} < $self->{required_complexity} ) {
		$self->{fail_reason} = 'complexity';
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

	$self->debug('$charHash{}:  ', [ Dumper($charHash) ] );

	my $keySpace;
	foreach my $class ( keys %{$charHash} ) {
		$keySpace += $charHash->{$class};
	}

	my $pwLen = length($self->{password});

	# permutation 
	my $n = factorial($keySpace);
	my $r = factorial($keySpace - $pwLen);

	print "Password: $self->{password}\n" unless $keySpace;
	
	$self->{complexity} = $n / $r;

	$self->debug('complexity{}:  ', [ 'n: ' => $n, 'r: ' => $r, 'complexity: ' => $self->{complexity} ] );

	return;

}


sub getCharClasses {
	my $self = shift;
	my $classHash = {};

	my $password = $self->{password};

	$self->debug("Password: ",  [$password]);

	$self->debug("checking for character classes ",  []);

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

sub output {
	my $self = shift;

	my $FS=',';
	if (defined ( $self->{field_separator} ) ) {
		$FS = $self->{field_separator};
	}

	my $r = $self->{fail_reason} ? 0 : 1;

	my $printit=0;
	if ($r and $self->{show_pass}) {$printit = 1;}
	if (! $r and $self->{show_fail}) {$printit = 1;}

	$self->{output_type} = 'STD' unless defined($self->{output_type});

	my $OT=$self->{output_type};

	if ($printit) {
		if ($OT eq 'CSV') {

			print "$self->{password}${FS}";
			print  ( $r ? 'OK' : 'Fail' ); print "$FS";
			print "$self->{fail_reason}${FS}";
			printf "%12e${FS}", $self->{required_complexity};
			printf "%12e\n", $self->{complexity};

		} elsif ($OT eq 'STD') {

			print "===  $self->{password} ===\n";
			print  "   Result: " . ( $r ? 'OK' : 'Fail' ) . "\n";
			if (! $r ) { 
				print  "   Failed: $self->{fail_reason}\n";
			}
			printf "   required complexity: %12e\n", $self->{required_complexity};
			printf "            complexity: %12e\n", $self->{complexity};

		} else {
			croak "Unknown output type of $OT in output()\n";
		}
	}
}

sub debug {
	my $self = shift;

	my ($txt,$ary,$force) = @_;

	$force = 0 unless $force;

	if (! $force ) {
		return unless $self->{debug};
	}

	my $bchar = '='; # banner character

	print $bchar x 40 . "\n";

	print $bchar x 3  . " $txt\n";
	foreach my $data ( @{$ary} ) {
		print ' ' x 5 . ' ' . "$data\n";
	}

	return;
}


=head1 NAME

Data::Password::Permutation - Determine password complexity based on keyspace and password length

=head1 Data::Password::Permutation

 Validate the complexity of a password based on the length of the password and the keyspace

 Keyspace: the total possible number of characters that a password may be drawn from

 For instance, if the password is 'password' there are only 26 possible letters required to try and break the password.
 
 The keyspace is then 26.

 If the password is 'Password', the keyspace is doubled to 52, as there are now 26 lower case letters and 26 upper case letters that must be used to try and break the password.

 ... finish this with an explanation of how the password complexity is calculated


=cut


