
package Data::Password::Permutation;

use Data::Dumper;
use strict;
use warnings;

use Exporter qw(import);
our $VERSION=0.1;
our @EXPORT = qw(&factorial &getComplexity);
our @ISA=qw(Exporter);

sub new {
	my ($class, %args) = @_;

	my $self = bless \%args, $class;

	if ( ! exists($self->{debug}) ) { $self->{debug} = 0; }
	if ( ! exists($self->{fail_reason}) ) { $self->{fail_reason} = ''; }
	if ( ! exists($self->{show_pass}) ) { $self->{show_pass} = 0; }
	if ( ! exists($self->{show_fail}) ) { $self->{show_fail} = 1; }

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
		if (exists( $self->{dictionary}{$self->{password}} ) ) {
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
	my $r=0;
	$r = 1 if $self->{complexity} >= $self->{required_complexity};

	my $printit=0;
	if ($r and $self->{show_pass}) {$printit = 1;}
	if (! $r and $self->{show_fail}) {$printit = 1;}

	if ($printit) {
		print "===  $self->{password} ===\n";
		print  "   Result: " . ( $r ? 'OK' : 'Fail' ) . "\n";
		if (! $r ) { 
			print  "   Failed: $self->{fail_reason}\n";
		}
		printf "   required complexity: %12e\n", $self->{required_complexity};
		printf "            complexity: %12e\n", $self->{complexity};
	}
}

sub outputCSV {
	my $self = shift;
	my $RS = shift;
	$RS = ',' unless $RS;

	my $r=0;
	$r = 1 if $self->{complexity} >= $self->{required_complexity};

	my $printit=0;
	if ($r and $self->{show_pass}) {$printit = 1;}
	if (! $r and $self->{show_fail}) {$printit = 1;}

	if ($printit) {
		print "$self->{password}${RS}";
		print  ( $r ? 'OK' : 'Fail' ); print "$RS";
		print "$self->{fail_reason}${RS}";
		printf "%12e${RS}", $self->{required_complexity};
		printf "%12e\n", $self->{complexity};
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


