use strict;
use warnings;

package Net::IMP::Example::LogServerCertificate;
use base 'Net::IMP::Base';
use fields (
    'done',    # done or no SSL
    'sbuf',    # buffer on server side
);

use Net::IMP qw(:log :DEFAULT); # import IMP_ constants
use Net::IMP::Debug;
use Carp 'croak';

sub INTERFACE {
    return ([
	IMP_DATA_STREAM,
	[ IMP_PASS, IMP_PREPASS, IMP_LOG ]
    ])
}


# create new analyzer object
sub new_analyzer {
    my ($factory,%args) = @_;
    my $self = $factory->SUPER::new_analyzer(%args);

    $self->run_callback(
	# we are not interested in data from client
	[ IMP_PASS, 0, IMP_MAXOFFSET ],
	# and we will not change data from server, only inspect
	[ IMP_PREPASS, 1, IMP_MAXOFFSET ],
    );

    $self->{sbuf} = '';
    return $self;
}

sub data {
    my ($self,$dir,$data) = @_;
    return if $dir == 0; # should not happen
    return if $self->{done}; # done or no SSL
    return if $data eq ''; # eof from server

    my $buf = $self->{sbuf} .= $data;

    if ( _read_ssl_handshake($self,\$buf,2)                  # Server Hello
	and my $certs = _read_ssl_handshake($self,\$buf,11)  # Certificates
    ) {
	$self->{done} = 1;

	# find OID 2.5.4.3 (coommon name) the quick and dirty way
	if ( $certs =~m{\x06\x03\x55\x04\x03.}g
	    and my $name = _get_asn1_string(substr($certs,pos($certs)))) {
	    $self->run_callback([ IMP_LOG,1,0,0,IMP_LOG_INFO,"cn=$name" ]);
	}
    }

    $self->run_callback([ IMP_PASS,1,IMP_MAXOFFSET ])
	if $self->{done};
}

sub _read_ssl_handshake {
    my ($self,$buf,$expect_htype) = @_;
    return if length($$buf) < 22; # need way more data

    my ($ctype,$version,$len,$htype) = unpack('CnnC',$$buf);
    if ($ctype != 22) {
	debug("no SSL >=3.0 handshake record");
	goto bad;
    } elsif ( $len > 2**14 ) {
	debug("length looks way too big - assuming no ssl");
	goto bad;
    } elsif ( $htype != $expect_htype ) {
	debug("unexpected handshake type $htype - assuming no ssl");
	goto bad;
    }

    length($$buf)-5 >= $len or return; # need more data
    substr($$buf,0,5,'');
    debug("got handshake type $htype length $len");
    return substr($$buf,0,$len,'');

    bad:
    $self->{done} = 1;
    return;
}

sub _get_asn1_string {
    my $buf = shift;
    my $len = unpack('C',substr($buf,0,1,''));
    if ( $len & 0x80 ) {
	# long string, get number of length bytes
	$len &= 0x7f;
	my @len = unpack("C$len",substr($buf,0,$len,''));
	$len = shift(@len);
	$len = $len * 0x100 + shift(@len) while (@len);
	$len > length($buf) and return; # invalid length
    }
    return substr($buf,0,$len);
}

# debugging stuff
sub _hexdump {
    my ($buf,$len) = @_;
    $buf = substr($buf,0,$len) if $len;
    my @hx = map { sprintf("%02x",$_) } unpack('C*',$buf);
    my $t = '';
    while (@hx) {
	$t .= join(' ',splice(@hx,0,16))."\n";
    }
    return $t;
}


1;

__END__

=head1 NAME

Net::IMP::Example::LogServerCertificate - Proof Of Concept IMP plugin for
logging server certificate of SSL connections

=head1 SYNOPSIS

    my $factory = Net::IMP::Example::LogServerCertificate->new_factory;

=head1 DESCRIPTION

C<Net::IMP::Example::LogServerCertificate> implements an analyzer, which expects
an SSL Server Hello on the server side, extracts the certificates and logs their
common name.
There are no further arguments.

=head1 BUGS

Sessions might be re-stablished with a session-id common between client and
server. In this case no certificates need to be exchanged and thus certificate
infos will not be tracked.
To work around it one might track session-ids and implement caching.

=head1 AUTHOR

Steffen Ullrich <sullr@cpan.org>

=head1 COPYRIGHT

Copyright by Steffen Ullrich.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.
