use strict;
use warnings;
 
use 5.008;
 
use ExtUtils::MakeMaker;
WriteMakefile
(
	NAME          => 'Data::Password::Permutation',
	AUTHOR        => 'Jared Still <jkstill@gmail.com>',
	VERSION_FROM  => 'lib/Data/Password/Permutation.pm',
	ABSTRACT_FROM  => 'lib/Data/Password/Permutation.pm',
	LICENSE       => 'MIT',
	PREREQ_PM     => {
	},
	TEST_REQUIRES => {
		'Test::More' => '0.47'
	},
	BUILD_REQUIRES => {
	},
	EXE_FILES => [
		'pwdchk.pl'
	],
	META_MERGE   => {
		'meta-spec' => { version => 2 },
		resources => {
			repository => {
				type => 'git',
				url  => 'https://github.com/jkstill/password-complexity-check.git',
			},
			bugtracker => {web => 'https://github.com/jkstill/password-complexity-check/issues'},
		},
	},
);
     
