#!/usr/bin/perl
# Test of Net::IMP::ProtocolPinning

use strict;
use warnings;
use Net::IMP::ProtocolPinning;
use Net::IMP;
use Net::IMP::Debug;
use Data::Dumper;
use Test::More;

$DEBUG=0; # enable for extensiv debugging

# if you want to run only selected tests add test numbers to cmdline
my %only = map { $_ =>1 } @ARGV;
my @tests = (
    {
	rules => [[0,4,qr/affe/],[1,4,qr/hund/],[0,2,qr/ok/]],
	in => [
	    [0,'affe'],
	    [1,'hund'],
	    [0,'ok' ]
	],
	rv => [
	    [ IMP_PASS,0,4 ],
	    [ IMP_PASS,1,4 ],
	    [ IMP_PASS,0,IMP_MAXOFFSET ],
	    [ IMP_PASS,1,IMP_MAXOFFSET ],
	],
    },{
	in => [
	    [1,'hund'],
	    [0,'affe'],
	    [0,'ok' ]
	],
	rv => [[IMP_DENY, 1, 'data from wrong side' ]],
    },{
	ignore_order => 1,
	rv => [
	    [ IMP_PASS,1,4 ],
	    [ IMP_PASS,0,4 ],
	    [ IMP_PASS,0,IMP_MAXOFFSET ],
	    [ IMP_PASS,1,IMP_MAXOFFSET ],
	],
    }, {
	rules => [[1,7,qr/SSH-2\.0/]],
	in => [
	    [ 0,'huhu' ],
	    [ 1,"SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1\n" ],
	],
	rv => [
	    [ IMP_PASS,0,IMP_MAXOFFSET ],
	    [ IMP_PASS,1,IMP_MAXOFFSET ],
	],
    }, {
	max_open => [4,], # "huhu" fits in 4 bytes
    }, {
	max_open => [0,],
	rv => [[IMP_DENY, 0, 'too much data outside rules' ]],
    }, {
	max_open => [100,100],
	rules => [[0,5,qr/affe\n/],[1,5,qr/hund\n/]],
	in => [
	    [ 0,'affe' ],[0,"\njuppi"],
	    [ 1,'hu' ],[1,'nd'],[1,"\n"],
	],
	rv => [
	    [ IMP_PASS,0,5 ],
	    [ IMP_PASS,0,IMP_MAXOFFSET ],
	    [ IMP_PASS,1,IMP_MAXOFFSET ],
	],
    }

);

plan tests => @tests - keys(%only);

my (%test,$out);
for(my $i=0;$i<@tests;$i++) {
    %test = ( %test,%{$tests[$i]} ); # redefine parts of previous
    next if %only && ! $only{$i};

    my @rv;
    my $cb = sub {
	debug( "callback: ".Dumper(\@_));
	push @rv,@_
    };

    my $analyzer = Net::IMP::ProtocolPinning->new_factory(
	rules        => $test{rules},
	max_open     => $test{max_open},
	ignore_order => $test{ignore_order},
    )->new_analyzer( cb => [$cb] );

    for( @{$test{in}} ) {
	my ($dir,$data) = @$_;
	debug("send '$data' to $dir");
	$analyzer->data($dir,$data);
    }

    if ( Dumper(\@rv) ne Dumper($test{rv})) {
	fail("protopin[$i]");
	diag( "--- expected---\n".Dumper($test{rv}).
	    "\n--- got ---\n".Dumper(\@rv));
    } else {
	pass("protopin[$i]");
    }
}
