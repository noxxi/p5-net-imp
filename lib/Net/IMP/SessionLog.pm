use strict;
use warnings;

package Net::IMP::SessionLog;
use base 'Net::IMP::Base';
use fields qw(fh conn);

use Net::IMP; # import IMP_ constants
use Net::IMP::Debug;
use Carp 'croak';
use Time::HiRes 'gettimeofday';
use File::Temp 'tempfile';

# we only use the PREPASS type
sub USED_RTYPES { return (IMP_PREPASS,IMP_ACCTFIELD) };
sub new_factory {
    my ($class,%args) = @_;
    # XXX new_factory might be called in a different root than new_analyzer
    # XXX adjust test for this case
    #   my $dir = $args{dir} or croak "no dir given for session logs";
    #   -d $dir && -w _ or croak "$dir is no writeable dir";
    return $class->SUPER::new_factory(%args);
}

# create new context object
#  - open log file
#  - prepare initial and only results (PREPASS in both directions)
sub new_analyzer {
    my ($class,%args) = @_;

    my $fmt  = $args{format} || 'bin';
    if ( $fmt ne 'bin' ) {
	$fmt eq 'pcap' or croak "format should be bin or pcap";
	eval "require 'Net::PcapWriter'" or croak 
	    "cannot load Net::PcapWriter needed for format pcap";
    }

    my $meta = $args{meta};
    my ($fh,$fname) = tempfile( 
	sprintf("%d-%s.%s-%s.%s-XXXXX", time(), 
	    @{$meta}{qw(caddr cport saddr sport)}),
	SUFFIX => ".$fmt",
	DIR => $args{dir}
    ) or croak("cannot create tmpfile: $!");
    $DEBUG && debug("new context with filename $fname");

    binmode($fh);
    $fh->autoflush(1);

    my $conn = $fmt eq 'pcap'
	&& Net::PcapWriter->new($fh)
	->tcp_conn( @{$meta}{qw(caddr cport saddr sport)} );

    my $self = $class->SUPER::new_analyzer(
	meta => $args{meta},
	cb => $args{cb}, 
	fh => $fh,
	conn => $conn,
    );

    # only results for both directions + acct
    $self->add_results(
	[ IMP_ACCTFIELD,'logfile',$fname ],
	[ IMP_PREPASS,0,IMP_MAXOFFSET ],
	[ IMP_PREPASS,1,IMP_MAXOFFSET ]
    );

    return $self;
}

sub data {
    my ($self,$dir,$data) = @_;
    if ( my $c = $self->{conn} ) {
	# pcap format
	$c->write($dir,$data,[gettimeofday()]);
    } else {
	# bin format
	print {$self->{fh}} pack("NNcN/a*",gettimeofday(),$dir,$data);
    }
    $self->run_callback;
}

1;	

__END__

=head1 NAME

Net::IMP::SessionLog - analyzer which only logs data

=head1 SYNOPSIS

    my $factory = Net::IMP::SessionLog->new_factory(
	dir => '/path/where/the/logs/should/be/stored/',
	format => 'pcap',
    );

=head1 DESCRIPTION

C<Net::IMP::SessionLog> implements an analyzer which logs the session data into a
file. To be less burden to the connection it will initially return IMP_PREPASS
with IMP_MAXOFFSET for both directions, which will cause all data to be
forwarded before they get send to the session logger.

For constructing the file name of the session log it needs the following data
given within C<new_factory> or C<new_analyzer>:

=over 4

=item dir DIR

C<dir> will specify the path, where the session log should be created.

=item meta HASH

From C<meta> are needed C<caddr> for client ip, C<cport> for client port,
C<saddr> for server ip and C<sport> for destination port.

=item format 'bin'|'pcap'

Specifies the format to use for the logfile.

Default is 'bin', which prefixes each entry in the log file with time and
direction, e.g. data can be extracted from the log like this:

    open( my $fh,'<',$logfile );
    while (read($fh,my $buf,13)) {
	my ($time_s,$time_us,$dir,$len) = unpack('NNcN',$buf);
	read($fh,$buf,$len) or die $!;
	print localtime($time_s).".$time_us dir=$dir <<<<\n",
	    $buf,
	    "\n>>>>>\n",
    }

If the format is 'pcap' it will create data readable with tcpdump, wireshark
etc. In this case it needs the L<Net::PcapWriter> module.

=back

