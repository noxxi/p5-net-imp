use strict;
use warnings;

###############################################################################
# First we need to define the connection and request objects which are then
# used later.
# We use Net::Inspect HTTP handling and derive our connection object from the
# Net::Inspect::L7::HTTP connection object. This will create new HTTPRequest
# objects which are derived from Net::Inspect::L7::HTTP::Request::Simple. These
# give us access to the interna of the request and let us manipulate the
# respone header.
###############################################################################

package Net::IMP::HTTP_AddXFooHeader::HTTPConnection;
use base 'Net::Inspect::L7::HTTP';
use Net::IMP::Debug;
use fields 'imp';

sub new {
    my ($class) = @_;
    $Net::Inspect::Debug::DEBUG = $DEBUG;
    return $class->SUPER::new(
	# whenever we have a new request sub new_request
	# is called on this object
	Net::IMP::HTTP_AddXFooHeader::HTTPRequest->new
    );
}

sub new_connection {
    my Net::IMP::HTTP_AddXFooHeader::HTTPConnection $self = shift;
    my ($meta,$imp) = @_;

    my Net::IMP::HTTP_AddXFooHeader::HTTPConnection $obj =
	$self->SUPER::new_connection($meta);
    $obj->{imp} = $imp;
    return $obj;
}

package Net::IMP::HTTP_AddXFooHeader::HTTPRequest;
use base 'Net::Inspect::L7::HTTP::Request::Simple';
use Net::IMP;

# This is the only real action we do in this module:
# add an X-Foo: bar header at the end of the response header
sub in_response_header {
    my Net::IMP::HTTP_AddXFooHeader::HTTPRequest $self = shift;
    my ($hdr,$time) = @_;

    # add header
    $hdr =~s{(\r?\n)\1}{$1X-Foo: bar$1$1}
	or die "could not add header";

    # return the result with the replaced header
    my Net::IMP::HTTP_AddXFooHeader::HTTPConnection $conn = $self->{conn};
    $conn->{imp}->run_callback([
	IMP_REPLACE,
	1,
	$conn->offset(1),
	$hdr
    ]);
}

# in is called for all other data, e.g. only the response header got a special
# handling. We just accept the data unmodified here.
sub in {
    my Net::IMP::HTTP_AddXFooHeader::HTTPRequest $self = shift;
    my ($dir,$data,$eof,$time) = @_;
    my Net::IMP::HTTP_AddXFooHeader::HTTPConnection $conn = $self->{conn};

    $conn->{imp}->run_callback([
	IMP_PREPASS,
	$dir,
	$conn->offset($dir),
    ]);
}

sub fatal {
    my Net::IMP::HTTP_AddXFooHeader::HTTPRequest $self = shift;
    my ($reason,$dir,$time) = @_;
    $self->{conn}{imp}->run_callback([IMP_DENY,$dir||0,$reason]);
}


###############################################################################
# Net::IMP::HTTP_AddXFooHeader
# this is the analyzer class
###############################################################################

package Net::IMP::HTTP_AddXFooHeader;
use base 'Net::IMP::Base';
use fields (
    # everything is done inside a closures in new_analyzer
    # dataf is the pointer this closure to make it accessible for sub data
    'dataf'
);

use Net::IMP; # import IMP_ constants
use Carp 'croak';
use Scalar::Util 'weaken';

sub USED_RTYPES {
    return (
	# we use PREPASS to make sure, that we get all data to maintain
	# internal state, because we don't support gaps yet
	IMP_PREPASS,  # pass
	IMP_REPLACE,  # replace, insert header
	IMP_DENY,     # on error
    );
}


# Create a new object for the analysis context (e.g. HTTP connection).
# It consists mainly of a closure stored in $self->{dataf} which forwards
# incoming data to the HTTP connection object, which then creates HTTP request
# objects - from there the callback with the analysis results will call back
sub new_analyzer {
    my ($class,%args) = @_;

    my Net::IMP::HTTP_AddXFooHeader $self =
	$class->SUPER::new_analyzer( %args,
	dataf => undef, # set below
    );

    my @buf    = ('',''); # data which are not forwarded yet
    my @offset = (0,0);   # offset of buf[0] in stream
    my @eof    = (0,0);   # flag if eof on direction

    # the connection needs self to call back
    # to avoid circular references we need to give a weak reference
    weaken( my $weak_self = $self );
    my Net::IMP::HTTP_AddXFooHeader::HTTPConnection $analyzer =
	Net::IMP::HTTP_AddXFooHeader::HTTPConnection->new_connection(
	    {},         # we have no meta data
	    $weak_self
    );

    $self->{dataf} = sub {
	my ($dir,$data,$offset) = @_;
	$offset and die "gaps($offset) not yet supported";

	my $eof = 0;
	if ( $data eq '' ) {
	    $eof[$dir] = 1;
	    $eof = $eof[0] + $eof[1];
	} else {
	    $buf[$dir] .= $data;
	}

	# analyzer will give the results by throwing callbacks
	my $n = $analyzer->in($dir,$buf[$dir],$eof,0);
	croak("analyzer::in returned undef") if ! defined $n;

	# strip all data the analyzer accepted from buf
	substr( $buf[$dir],0,$n,'' ) if $n;
    };

    return $self;
}

# just call the closure in dataf
sub data {
    my Net::IMP::HTTP_AddXFooHeader $self = shift;
    return $self->{dataf}(@_)
}



1;
__END__

=head1 NAME

Net::IMP::HTTP_AddXFooHeader - adds X-Foo header to HTTP response

=head1 DESCRIPTION

This module analyses HTTP streams and adds an X-Foo header add the end of each
HTTP response header it finds in the stream.
This module is not very useful by its own.
It is only used to show, how these kind of manipulations can be done.

=head1 AUTHOR

Steffen Ullrich <sullr@cpan.org>

=head1 COPYRIGHT

Copyright by Steffen Ullrich.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.
