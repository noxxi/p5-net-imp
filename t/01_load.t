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
    [ 'Net::IMP::HTTP_AddXFooHeader' => 'Net::Inspect' ],
#    [ 'Net::IMP::HTTP_AddCSPHeader'  => 'WWW::CSP','Net::Inspect' ],
    ){
    my ($mod,@deps) = @$_;
    for (@deps) {
	eval "require $_" and next;
	diag("skip $mod because dependency $_ is missing");
	next test;
    }
    push @mods,$mod;
}

plan tests => 0+@mods;
for (@mods) {
    eval "use $_";
    cmp_ok( $@,'eq','', "loading $_" );
}
