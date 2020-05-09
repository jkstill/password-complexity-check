# -*- perl -*-

# t/001_load.t - check module loading and create testing directory

use Test::More tests => 7;

BEGIN { use_ok( 'Data::Password::Permutation' ); }

my $pxChk = new Data::Password::Permutation( 
		required_complexity => 1e6, # bogus low number for testing
		debug => 0,
);
	
isa_ok ($pxChk, 'Data::Password::Permutation');

$pxChk->{password} = 'thisisatest';
ok($pxChk->validatePassword);

$pxChk->{password} = 'j%4x!wpx';
ok($pxChk->validatePassword);

$pxChk->{password} = 'Tj%4x!wpxH';
ok($pxChk->validatePassword);


$pxChk->{password} = 'Us3AllCharacter%Types';
ok($pxChk->validatePassword);

$pxChk->{password} = 'antidisestablishmentarianisM';
ok($pxChk->validatePassword);


