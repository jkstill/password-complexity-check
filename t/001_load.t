# -*- perl -*-

# t/001_load.t - check module loading and create testing directory

use Test::More tests => 2;

BEGIN { use_ok( 'Data::Password::Permutation' ); }

my $object = Data::Password::Permutation->new ( ARG1 => 'arg1', ARG2 => 'arg2'  );
isa_ok ($object, 'Data::Password::Permutation');
