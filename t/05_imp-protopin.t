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
	rules => [
	    { dir => 0, rxlen => 4, rx => qr/affe/ },
	    { dir => 1, rxlen => 4, rx => qr/hund/ },
	    { dir => 0, rxlen => 2, rx => qr/ok/ }
	],
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
	rules => [
	    { dir => 0, rxlen => 4, rx => qr/affe/ },
	    { dir => 1, rxlen => 4, rx => qr/hund/ },
	],
	ignore_order => 1,
	rv => [
	    [ IMP_PASS,1,4 ],
	    [ IMP_PASS,0,IMP_MAXOFFSET ],
	    [ IMP_PASS,1,IMP_MAXOFFSET ],
	],
    }, {
	rules => [
	    { dir => 1, rxlen => 7, rx => qr/SSH-2\.0/ }
	],
	in => [
	    [ 0,'huhu' ],
	    [ 1,"SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1\n" ],
	],
	rv => [
	    [ IMP_PASS,0,IMP_MAXOFFSET ],
	    [ IMP_PASS,1,IMP_MAXOFFSET ],
	],
    }, {
	max_unbound => [4,], # "huhu" fits in 4 bytes
    }, {
	max_unbound => [0,],
	rv => [[IMP_DENY, 0, 'too much data outside rules' ]],
    }, {
	max_unbound => [100,100],
	rules => [
	    { dir => 0, rxlen => 5, rx => qr/affe\n/ },
	    { dir => 1, rxlen => 5, rx => qr/hund\n/ },
	],
	in => [
	    [ 0,'affe' ],[0,"\njuppi"],
	    [ 1,'hu' ],[1,'nd'],[1,"\n"],
	],
	rv => [
	    [ IMP_PASS,0,5 ],
	    [ IMP_PASS,0,IMP_MAXOFFSET ],
	    [ IMP_PASS,1,IMP_MAXOFFSET ],
	],
    }, {
	max_unbound => [0,0],
	rules => [
	    { dir => 0, rxlen => 12, rx => qr/cloud(ella)?(ria)?/ },
	    { dir => 1, rxlen => 1, rx => qr/./ }
	],
	in => [
	    [ 0,'clou' ],
	    [ 0,'de' ],
	    [ 0,'llar' ],
	    [ 0,'iad' ],
	    [ 1,'foo' ],
	],
	rv => [
	    [ IMP_PASS,0,5 ],
	    [ IMP_PASS,0,9 ],
	    [ IMP_PASS,0,12 ],
	    [ IMP_PASS,0,IMP_MAXOFFSET ],
	    [ IMP_PASS,1,IMP_MAXOFFSET ],
	],
    },
    {
	rules => [ { dir => 0, rxlen => 8, rx => qr/(\w\w\w\w)\1/ } ],
	in => [[0,'toortoor']],
	rv => [
	    [ IMP_PASS,0,IMP_MAXOFFSET ],
	    [ IMP_PASS,1,IMP_MAXOFFSET ],
	],
    },
    {
	rules => [ { dir => 0, rxlen => 8, rx => qr/(\w\w\w\w)\1/ } ],
	in => [[0,'toorToor']],
	rv => [[IMP_DENY, 0, 'rule did not match' ]],
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

    my %config = (
	rules        => $test{rules},
	max_unbound  => $test{max_unbound},
	ignore_order => $test{ignore_order},
    );
    if ( my @err = Net::IMP::ProtocolPinning->validate_cfg(%config) ) {
	fail("config[$i] not valid");
	diag("@err");
	next;
    }

    my $analyzer = Net::IMP::ProtocolPinning->new_factory(%config)
	->new_analyzer( cb => [$cb] );

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
