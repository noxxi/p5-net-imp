#!/usr/bin/perl

use strict;
use warnings;
use Getopt::Long qw(:config posix_default bundling);
use Net::Inspect::Debug '%TRACE';
use Net::Inspect::L2::Pcap;
use Net::Inspect::L3::IP;
use Net::Inspect::L4::TCP;
use Net::PcapWriter;
use Net::Pcap qw(:functions);
use Net::IMP;
use Net::IMP::Cascade;
use Net::IMP::Debug;

# rtypes we support in this program
my @rtypes = (
    IMP_PASS,
    IMP_PREPASS,
    IMP_DENY,
    IMP_REPLACE,
    IMP_LOG,
    IMP_ACCTFIELD,
);


sub usage {
    print STDERR <<USAGE;

filter tcp connections from pcap file using Net::IMP analyzers
$0 Options*  -r in.pcap -w out.pcap

Options:
  -h|--help               show usage
  -M|--module mod[=arg]   use Net::IMP module for connections
                          can be given multiple times for cascading modules
  -r|--read  in.pcap      input pcap file
  -w|--write out.pcap     output pcap file
  -d|--debug              debug mode
  -T|--trace T            Net::Inspect traces

USAGE
    exit(2);
}

my (@module,$infile,$outfile);
GetOptions(
    'M|module=s' => \@module,
    'r|read=s'   => \$infile,
    'w|write=s'  => \$outfile,
    'h|help'     => sub { usage() },
    'd|debug'    => \$DEBUG,
    'T|trace=s'  => sub { $TRACE{$_}=1 for split(m/,/,$_[1]) }
);

$Net::Inspect::Debug::DEBUG=$DEBUG;

$infile ||= '/dev/stdin';
my $err;
my $pcap_in = pcap_open_offline($infile,\$err) or die $err;
my $pcap_out = Net::PcapWriter->new( $outfile || \*STDOUT ) or die $!;


my @factory;
for my $module (@module) {
    $module eq '=' and next;
    my ($mod,$args) = $module =~m{^([a-z][\w:]*)(?:=(.*))?$}i
	or die "invalid module $module";
    eval "require $mod" or die "cannot load $module";
    my %args = split(',',$args//'');
    push @factory, $mod->new_factory(%args, rtypes => \@rtypes) 
	or croak("cannot create Net::IMP factory for $mod");
}

my $imp_factory;
if (@factory == 1) {
    $imp_factory = $factory[0];
} elsif (@factory) {
    $imp_factory = Net::IMP::Cascade->new_factory(
	rtypes => \@rtypes, 
	parts => \@factory 
    ) or croak("cannot create factory from Net::IMP::Cascade");
}

my $cw  = ConnWriter->new($pcap_out,$imp_factory);
my $tcp = Net::Inspect::L4::TCP->new($cw);
my $raw = Net::Inspect::L3::IP->new($tcp);
my $pc  = Net::Inspect::L2::Pcap->new($pcap_in,$raw);

my $time;
pcap_loop($pcap_in,-1,sub {
    my (undef,$hdr,$data) = @_;
    if ( ! $time || $hdr->{tv_sec}-$time>10 ) {
        $tcp->expire($time = $hdr->{tv_sec});
    }
    return $pc->pktin($data,$hdr);
},undef);


package ConnWriter;
use base 'Net::IMP::Filter';
use fields qw(expire pcap);

sub new {
    my ($class,$pcap,$imp) = @_;
    my $self;
    if ( UNIVERSAL::can($imp,'set_callback' )) {
	# imp object, not factory
	$self = $class->SUPER::new($imp);
    } else {
	$self = $class->SUPER::new();
	$self->{imp} = $imp
    }
    $self->{pcap} = $pcap;
    return $self;
}

sub new_connection {
    my ($self,$meta) = @_;
    my $imp = $self->{imp} 
	&& $self->{imp}->new_analyzer(meta => $meta);
    my $pcap = $self->{pcap}->tcp_conn(
	$meta->{saddr}, $meta->{sport},
	$meta->{daddr}, $meta->{dport},
    );
    return $self->new($pcap,$imp);
}

sub syn { return 1 }
sub fatal { warn "fatal: $_[1]\n" }
sub in {
    my ($self,$dir,$data,$eof) = @_;
    $self->SUPER::in($dir,$data);
    $self->SUPER::in($dir,'') if $eof and $data ne '';
    return length($data);
}

sub out {
    my ($self,$dir,$data) = @_;
    $self->{pcap}->write($dir,$data) if $data ne '';
}

sub expire {
    my ($self,$expire) = @_;
    return $self->{expire} && $time>$self->{expire};
}
