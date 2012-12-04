use strict;
use warnings;

package Net::IMP::HTTP_AddCSPHeader;
use base 'Net::IMP::Base';
use fields qw(dataf);

use Net::IMP; # import IMP_ constants
use Carp 'croak';
use WWW::CSP;

use Net::IMP::Debug;
WWW::CSP::Debug->extern( \$DEBUG,\&debug);

sub USED_RTYPES {
    return (
	# we use PREPASS to make sure, that we get all data to maintain
	# internal state in cased we cannot do gaps. In simple cases
	# we use PASS
	IMP_PREPASS,  # pass first, but inspect
	IMP_PASS,     # pass w/o inspection
	IMP_REPLACE,  # replace, insert header
	IMP_DENY,     # on error
	IMP_TOSENDER, # send fake response for CSP report
    );
}

# create CSP backend only once
sub new_factory {
    my ($self,%args) = @_;
    my $csp_backend = WWW::CSP->new( db => delete $args{csp_backend} );
    return $self->SUPER::new_factory( %args, csp_backend => $csp_backend );
}

# create new context object
sub new_analyzer {
    my ($class,%args) = @_;

    my $csp_backend = delete $args{csp_backend};
    my $self = $class->SUPER::new_analyzer( %args,
	dataf => undef, # set below
    );

    my @buf    = ('',''); # data which are not forwarded yet
    my @offset = (0,0);   # offset of buf[0] in stream
    my @eof    = (0,0);   # flag if eof on direction

    my $analyzer = Net::IMP::HTTP_AddCSPHeader::HTTPConnection
	->new_connection({},$self,$csp_backend);

    $self->{dataf} = sub {
	my ($dir,$data,$offset) = @_;
	my $n;
	if ( $offset ) {
	    $n = $offset - $offset[$dir];
	    $n<=0 and return;
	    $analyzer->in($dir,[ gap => $n ],0,0 );

	} else {
	    my $eof = 0;
	    if ( $data eq '' ) {
		$eof[$dir] = 1;
		$eof = $eof[0] + $eof[1];
	    } else {
		$buf[$dir] .= $data;
	    }

	    # analyzer will throw callbacks
	    $n = $analyzer->in($dir,$buf[$dir],$eof,0);
	    croak("analyzer::in returned undef") if ! defined $n;
	}

	# remove analyzed data from buffer
	if ($n) {
	    substr( $buf[$dir],0,$n,'' );
	    $offset[$dir] += $n
	}
    };

    return $self;
}

# everything done within closure
sub data {
    my $self = shift;
    return $self->{dataf}(@_)
}



package Net::IMP::HTTP_AddCSPHeader::HTTPConnection;
use base 'Net::Inspect::L7::HTTP';
use fields qw(imp csp);
use Scalar::Util 'weaken';

sub new {
    my ($class) = @_;
    $Net::Inspect::Debug::DEBUG = $Utils::DEBUG;
    return $class->SUPER::new(
	Net::IMP::HTTP_AddCSPHeader::HTTPRequest->new);
}

sub new_connection {
    my ($self,$meta,$imp,$csp) = @_;
    my $obj = $self->SUPER::new_connection($meta);
    $obj->{csp} = $csp;

    # need weak reference so that we don't get circular references
    # (imp <-> conn)
    weaken( $obj->{imp} = $imp );
    return $obj;
}

package Net::IMP::HTTP_AddCSPHeader::HTTPRequest;
use base 'Net::Inspect::L7::HTTP::Request::Simple';
use fields qw(policy report);
use Net::IMP;
use Net::IMP::Debug;
use Scalar::Util 'weaken';
use Carp 'croak';

sub in_request_header {
    my ($self,$hdr,$time) = @_;
    my $conn = $self->{conn};
    my $p = $self->{policy} = $conn->{csp}->new_policy;
    my $newhdr = $p->request_header($hdr);
    if ( $p->is_csp_report ) {
	# CSP report, collect body and don't forward
	$self->{report} = [ $hdr,'' ];
	$conn->{imp}->run_callback([
	    IMP_REPLACE,
	    0,
	    $conn->offset(0),
	    '',
	]);
	return;
    }

    my $risk = $p->risk;
    $DEBUG && debug("risk is ".$risk->value." because of ".$risk->string);
    if ( $risk->value == 1 ) {
	# 100% risk, no need to go further
	$conn->{imp}->run_callback([
	    IMP_DENY,
	    0,
	    $risk->string,
	]);

    } elsif ( $newhdr ) {
	# replace request header, but pass body if any
	my $rqclen = $newhdr =~m{^Content-length:\s*(\d+)}mi && $1 ||0;
	$conn->{imp}->run_callback(
	    [ IMP_REPLACE, 0, $conn->offset(0), $newhdr ],
	    $rqclen ? ([ IMP_PASS,0,$conn->offset(0) + $rqclen ]):()
	);

    } else {
	# we don't look at the body, so it can be passed too
	my $rqclen = $hdr =~m{^Content-length:\s*(\d+)}mi && $1 ||0;
	$conn->{imp}->run_callback([
	    IMP_PASS,
	    0,
	    $conn->offset(0) + $rqclen,
	]);
    }
}

sub in_response_header {
    my ($self,$hdr,$time) = @_;
    if ( $self->{report} ) {
	# this is the fake 204 response to reports generated locally
	# ignore, we already used IMP_TOSENDER as we got the request
	return;
    }

    my $newhdr = $self->{policy}->response_header($hdr);
    my $conn = $self->{conn};

    # simple body, FIXME: support chunks and body-til-eof
    my $rpclen = $hdr =~m{^Content-length:\s*(\d+)}mi && $1 ||0;

    if ($newhdr) {
	$conn->{imp}->run_callback(
	    [IMP_REPLACE,1,$conn->offset(1),$newhdr]);
	# pass body uninspected
	$conn->{imp}->run_callback(
	    [IMP_PASS,1,$conn->offset(1)+$rpclen,$newhdr])
	    if $rpclen;
    } else {
	# pass incl body w/o further inspection
	$conn->{imp}->run_callback(
	    [IMP_PASS,1,$conn->offset(1)+$rpclen,$newhdr])
    }
}

sub in_request_body {
    my ($self,$data,$eof,$time) = @_;
    if (ref($data)) {
	croak "cannot use gaps with eof" if $eof;
	return; # skip data
    }
    return $self->in(0,$data,$eof,$time);
}

sub in_response_body {
    my ($self,$data,$eof,$time) = @_;
    if (ref($data)) {
	croak "cannot use gaps with eof" if $eof;
	return; # skip data
    }
    return $self->in(1,$data,$eof,$time);
}

sub in {
    my ($self,$dir,$data,$eof,$time) = @_;
    my $conn = $self->{conn};

    if ( $self->{report} ) {
	if ( !$dir) {
	    # add to report
	    $self->{report}[1] .= $data;

	    # don't forward
	    $conn->{imp}->run_callback([
		IMP_REPLACE,
		$dir,
		$conn->offset($dir),
		'',
	    ]);

	    if ( $eof ) {
		# add report to CSP manager so it can adjust policy
		$conn->{csp}->add_csp_report($self->{report}[1]);

		# send our response back
		my $response = "HTTP/1.1 204 NC\r\n\r\n";
		$conn->{imp}->run_callback([
		    IMP_TOSENDER,
		    $dir,
		    $response
		]);

		# XXX get into the internals of Net::Inspect::L7::HTTP
		# XXX fake response from server so that the state fits
		# XXX make sure we don't add this to the offset
		$conn->{offset}[1] -= length($response);
		$conn->in(1,$response,0,$time);
	    }
	}
	return;
    }

    $conn->{imp}->run_callback([
	IMP_PREPASS,
	$dir,
	$conn->offset($dir),
    ]);
}

sub fatal {
    my ($self,$reason,$dir,$time) = @_;
    my $conn = $self->{conn};
    $conn->{imp}->run_callback([IMP_DENY,$dir||0,$reason]);
}

1;

__END__

=head1 NAME

Net::IMP::HTTP_AddCSPHeader - adds Content Security Policy header and more

=head1 DESCRIPTION

This module uses the (not yet publically released) L<WWW::CSP>module to
extract information from HTTP requests and responses and to automatically create
Content Security Policies.
It will:

=over 4

=item *

inject restrictive but report-only CSP header into HTTP response if none exists

=item *

intercept CSP violation reports and extend CSP policy accordingly

=item *

track (and maybe check) referers from HTTP requests

=back

it interacts with the L<WWW::CSP> module by

=over 4

=item *

specifying the backend to use, using the parameter C<csp_backend> in
C<new_factory> or C<new_analyzer>

=item *

creating a new policy object when receiving a request with
C<< $policy = $csp->policy_from_request_header >>

=item *

determining if a request is a violation report using C<$policy->is_report>. In
this case call C<$csp->add_report>, so that the CSP can be adjusted according to
the report.

=item *

checking the requests Referer header using  C<$policy->valid_referer>.
The policy can cause the request to be blocked.

=item *

calling C<$policy->change_response_header> on the response header to let the CSP
module add the appropriate CSP header.

=back

=head1 AUTHOR

Steffen Ullrich <sullr@cpan.org>

=head1 COPYRIGHT

Copyright by Steffen Ullrich.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.
