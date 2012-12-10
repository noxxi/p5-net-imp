#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

my @mods;
test: for (
    [ 'Net::IMP' ],
    [ 'Net::IMP::Debug' ],
    [ 'Net::IMP::Base' ],
    [ 'Net::IMP::Pattern' ],
    [ 'Net::IMP::ProtocolPinning' ],
    [ 'Net::IMP::Filter' ],
    [ 'Net::IMP::SessionLog' ],
    [ 'Net::IMP::Cascade' ],
    [ 'Net::IMP::HTTP_AddXFooHeader' => 'Net::Inspect!0.24' ],
#    [ 'Net::IMP::HTTP_AddCSPHeader'  => 'WWW::CSP','Net::Inspect' ],
    ){
    my ($mod,@deps) = @$_;
    for (@deps) {
	my ($dep,$want_version) = split('!');
	if ( ! eval "require $dep" ) {
	    diag("cannot load $dep");
	} elsif ( $want_version ) {
	    no strict 'refs';
	    my $v = ${"${dep}::VERSION"};
	    if ( ! $v or $v < $want_version ) {
		diag("wrong version $dep - have $v want $want_version");
	    }
	}
    }
    push @mods,$mod;
}

plan tests => 0+@mods;
for (@mods) {
    eval "use $_";
    cmp_ok( $@,'eq','', "loading $_" );
}
