use strict;
use warnings;

package Net::IMP;

our $VERSION = 0.46;

use Carp 'croak';
use Scalar::Util 'dualvar';

# map set_debug into local namespace for convinience, so that one
# can call Net::IMP->set_debug instead of Net::IMP::Debug->set_debug
use Net::IMP::Debug 'set_debug';

use Exporter 'import';
our @EXPORT = qw(
    IMP_PASS
    IMP_PASS_PATTERN
    IMP_PREPASS
    IMP_DENY
    IMP_DROP
    IMP_TOSENDER
    IMP_REPLACE
    IMP_LOG
    IMP_PORT_OPEN
    IMP_PORT_CLOSE
    IMP_ACCTFIELD
    IMP_MAXOFFSET
);

my @log_levels = qw(
    IMP_LOG_DEBUG
    IMP_LOG_INFO
    IMP_LOG_NOTICE
    IMP_LOG_WARNING
    IMP_LOG_ERR
    IMP_LOG_CRIT
    IMP_LOG_ALERT
    IMP_LOG_EMERG
);
our @EXPORT_OK = @log_levels;
our %EXPORT_TAGS = ( log => \@log_levels );

# the numerical order of the constants describes priority when
# cascading modules, e.g. replacement has a higher value then
# pass and gets thus forwarded as the cause for the data

### information only
use constant IMP_LOG          => dualvar(0x0000,"log");
use constant IMP_PORT_OPEN    => dualvar(0x0001,"port_open");
use constant IMP_PORT_CLOSE   => dualvar(0x0002,"port_close");
use constant IMP_ACCTFIELD    => dualvar(0x0003,"acctfield");
### keep data
use constant IMP_PASS         => dualvar(0x1001,"pass");
use constant IMP_PASS_PATTERN => dualvar(0x1002,"pass_pattern");
use constant IMP_PREPASS      => dualvar(0x1003,"prepass");
### change data
use constant IMP_TOSENDER     => dualvar(0x1010,"tosender");
use constant IMP_REPLACE      => dualvar(0x1011,"replace");
### affect whole connection
use constant IMP_DENY         => dualvar(0x1100,"deny");
use constant IMP_DROP         => dualvar(0x1101,"drop");

use constant IMP_MAXOFFSET    => -1;

# log levels for IMP_LOG
# these are modeled analog to syslog levels
use constant IMP_LOG_DEBUG    => dualvar(1,'debug');
use constant IMP_LOG_INFO     => dualvar(2,'info');
use constant IMP_LOG_NOTICE   => dualvar(3,'notice');
use constant IMP_LOG_WARNING  => dualvar(4,'warning');
use constant IMP_LOG_ERR      => dualvar(5,'error');
use constant IMP_LOG_CRIT     => dualvar(6,'critical');
use constant IMP_LOG_ALERT    => dualvar(7,'alert');
use constant IMP_LOG_EMERG    => dualvar(8,'emergency');


# no response types in default implementation
# override this with @list of response types implemented by the class
sub USED_RTYPES {}
sub new_factory {
    my ($class,%args) = @_;
    # if caller supports only limited set on response types make sure
    # that class only uses these
    if ( my $rt = delete $args{rtypes} ) {
	my %rt = map { $_ => 1 } @$rt;
	if ( my @miss = grep { !$rt{$_} } $class->USED_RTYPES(%args) ) {
	    croak("response types @miss need to be supported for use of $class")
	}
    }
    return bless [ $class, \%args ], 'Net::IMP::Factory';
}


{
    package Net::IMP::Factory;
    sub class { return shift->[0] }
    sub USED_RTYPES {
	my ($self,%args) = @_;
	my ($class,$fargs) = @$self;
	return $class->USED_RTYPES(%$fargs,%args);
    }
    sub new_analyzer {
	my ($self,%args) = @_;
	my ($class,$fargs) = @$self;
	return $class->new_analyzer(%$fargs,%args);
    }
}

1;

__END__

=head1 NAME

Net::IMP - Inspection and Modification Protocol

=head1 SYNOPSIS

    package mySessionLog;
    use base 'Net::IMP::Base';
    use Net::IMP;

    # creates factory object
    sub new_factory {
	my ($class,%args) = @_;
	... create factory object ...
	... $factory->new_analyzer calls later $class->new_analyzer ...
    }

    # creates new analyzer object, gets %args from factory
    sub new_analyzer {
	my ($class,%args) = @_;
	... handle private %args ...
	my $self = $class->SUPER::new_analyzer( %args );
	# prepass everything forever in both directions
	$self->add_results(
	    [ IMP_PREPASS, 0, IMP_MAXOFFSET ],  # for dir client->server
	    [ IMP_PREPASS, 1, IMP_MAXOFFSET ];  # for dir server->client
	);
	return $self;
    }

    # new data for analysis, $offset should only be set if there are gaps
    # (e.g. when we PASSed data with offset in the future)
    sub data {
	my ($self,$dir,$data,$offset) = @_;
	... log data ...
    }

    package main;
    if (my @err = mySessionLog->validate_cfg(%config)) {
	die "@err"
    }
    my $factory = mySessionLog->new_factory(%config);
    # calls mySessionLog->new_analyzer
    my $analyzer = $factory->new_analyzer(...);
    $analyzer->set_callback(\&imp_cb);

    $analyzer->data(0,'data from dir 0');
    .... will call imp_cb as soon as results are there ...
    $analyzer->data(0,''); # eof from dir 0

    # callback for results
    sub imp_cb {
	for my $rv (@_) {
	    my $rtype = shift(@$rv);
	    if ( $rtype == IMP_PASS ) ...
	    ...
	}
    }

=head1 DESCRIPTION

IMP is a protocol for inspection, modification and rejection of data between
two sides (client and server) using an analyzer implementing this interface.

=head2 Basics

IMP is an asynchronous protocol, usually used together with callbacks.

=over 4

=item *

Using the C<data> method, data from the input stream gets put into the
analyzer.

=item *

The analyzer processes the data and generates results.
It might be possible, that it needs more data before generating a result or
that it can only results for part of the data and needs more data for more
results.

Each result contains a result type.
Most results also contain direction of the input stream which caused the result
and the offset of this stream.
The offset is the position in the input stream, up to which data got used in
generating the result, e.g. a result of IMP_PASS means that data up to the
offset got used in the result and thus data up to this offset can be passed.

=item *

The results get usually propagated with a callback set with C<set_callback>.
If no callback is set, results can be polled with the C<poll_results> method.

=back

=head2 Usage of Terms

=over 4

=item Factory

The factory object is used to create analyzers within a specific context.

=item Context

The context is the environment where the analyzer executes.
E.g. when analyzing TCP connections, a new context is created for each TCP
connection.

=item Analyzer

The analyzer is the object which does the analysis of the data within a
specific context.
It will be created by the factory for a given context.

=back

=head2 Methods

The following API is defined.

=over 4

=item $class->new_factory(%args) => $factory

This creates a new factory object which is later used to create the context.
In the default implementation, an argument C<< rtypes => [qw(pass prepass..)] >>
can be given where the caller can specify the response types it supports.
This will be checked against the list returned by C<< $class->USED_RTYPES() >>
and if the class uses response types not implemented by the caller it will
croak.

=item $factory->new_analyzer(%args) => $self|undef

Creates a new analyzer object.
C<%args> from this call will be merged with C<%args> from the C<new_factory>
call and will be used to create the context for the analysis.
The details for C<%args> depend on the analyzed protocol and the requirements
of the analyzer, but usually these are things like source and destination ip
and port, URL, mime type etc.

With a key of C<cb> the callback can already be set here as
C<<[$code,@args]>> instead of later with C<set_callback>.

The factory might decide based on the given context information, that no
analysis is needed.
In this case it will return C<undef>, otherwise the new analyzer object.

=item $self->set_callback($code,@args)

Sets or changes the callback of the analyzer object.
If results are outstanding, they might be delivered to this callback before
the method returns.

C<$code> is a coderef while C<@args> are additional user specified arguments
which should be used in the callback (typically object reference or similar).
The callback is called with C<< $code->(@args,@results) >> whenever new results
are available.

If $code is undef, an existing callback will be removed.

If no callback is given, the results need to be polled with C<poll_results>.

=item $self->data($dir,$data,$offset)

Forwards new data to the analyzer.
C<$dir> is the direction, e.g. 0 from client and 1 from server.
C<$data> are the data.
C<$data> of undef means end of data.

C<$offset> is the current position (octet) in the data stream.
It must be set after data got omitted as a result of PASS or PASS_PATTERN, so
that the analyzer can resynchronize the internal position value with the
original position in the data stream.
It must not be set in any other case.

Results will be delivered through the callback or via C<poll_results>.

=item $self->poll_results => @results

Returns outstanding results.
If a callback is attached, no results will be delivered this way.

=item Net::IMP->set_debug

This is just a convinient way to call C<< Net::IMP::Debug->set_debug >>.
See L<Net::IMP::Debug> for more information.

=back

=head2 Results

The results returned inside the callback or via C<poll_results> can be of the
following kind:

=over 4

=item [ IMP_PASS, $dir, $offset ]

Accept all data up to C<$offset> in the data stream for direction C<$dir>.

If C<$offset> specifies data which were not yet seen by the analyzer, these data
don't need to be forwarded to analyzer.
If they were still forwarded to the analyzer (because they were already on the
way, unstoppable) the analyzer just throws them away until C<$offset> is
reached.
This feature is useful for ignoring whole subcontexts (like MIME content based
on a C<Content-length> header).

A special case is a C<$offset> of IMP_MAXOFFSET, in this case the analyzer is
not interested in further information about the connection.

=item [ IMP_PASS_PATTERN, $dir, $regex, $len ]

This is the same as IMP_PASS, except a pattern will be given instead of an
offset.
All data up to but not including the pattern don't need to be forwarded to the
analyzer.
Because C<$regex> might be complex the analyzer has to specify how many
octets the C<$regex> might match at most, so that the caller can adjust its
buffer.

Because there might be data already on the way to the analyzer, the analyzer
needs to check all incoming data without explicit offset if they match the
pattern.
If it gets data with explicit offset, that means, that the pattern was matched
inside the client at the specified position.
In this case it should remove all data it got before (even if they included
offset already) and resync at the specified offset.

For better performance the analyzer should check any data it has already in the
buffer if they already contain the pattern.
In this case the issue can be dealt internally and there is no need to send
this reply to the caller.

If the caller receives this reply, it should check all data it has still in the
buffer (e.g. which were not passed) wether they contain the pattern.
If the caller finds the pattern, it should call C<data> with an explicit
offset, so that the analyzer can resynchronize the position in the data
stream.

=item [ IMP_PREPASS, $dir, $offset ]

This is similar to IMP_PASS.
If <$offset> specifies data, which were already forwarded to the analyzer, they
get accepted.
If it specified not yet forwarded data, they get accepted also up to
C<$offset>, but contrary to IMP_PASS they get also forwarded to the analyzer.

Thus data can be forwarded before they get inspected, but they get inspected
nevertheless.
This might be known good data, but inspection is needed to maintain the state
or to log the data.

Or it might be potentially bad data, but a low latency is required and small
amounts of bad data are accepted.
In this case the window for bad data might be set small enough to allow high
latency while limiting impact of malicious data.
This can be done through continues updates of C<$offset>.

=item [ IMP_DENY, $dir, $reason ]

Deny any more data on this context.
If C<$reason> is given, it should be used to construct a message to the client.

Deny results by closing the context in a way visible to the client (e.g. closing
the connection with RST).

=item [ IMP_DROP ]

Deny any more data on this context and close the context.
The preferred way for closing the context is to be not visible to the client
(e.g just drop any more packets of an UDP connection).

=item [ IMP_REPLACE, $dir, $offset, $data ]

Ignore the original data up to $offset, instead send C<$data>.
C<$offset> needs be be in the range of the data the analyzer got through
C<data> method.

=item [ IMP_TOSENDER, $dir, $data ]

Send data back to the sender.
This might be used to reject data, e.g. replace them with nothing and send
an error message back to the sender.
This can be useful to reject single commands in SMTP, FTP...

=item [ IMP_LOG, $dir, $offset, $len, $level, $msg ]

This contains a log message C<$msg> which is about data in direction C<$dir>
starting with C<$offset> and C<$len> octets long.
C<$level> might specify a log level like debug, info, warn... .

The caller should just log the information in this case.

C<$level> is one of LOG_IMP_*, which are similar to syslog levels,
e.g. IMP_LOG_DEBUG, IMP_LOG_INFO,...
These level constants can be imported with C<< use Net::IMP ':log' >>.

=item [ IMP_PORT_OPEN|IMP_PORT_CLOSE, $dir, $offset, ... ]

Some protocols like FTP, SIP, H.323 dynamically allocate ports.
These results detect when port allocation/destruction is done and should provide
enough information for the caller to open/close the ports and track the data
through additional analyzers.

TODO: details will be specified when this feature is needed.

=item [ IMP_ACCTFIELD, $key, $value ]

This specifies a tuple which should be used for accounting (like name of
logfile, URL...)

=back

=head1 TODO

=over 4

=item * sample integration into relayd

=item * optimizing initial setup

Optimizing initial setup, so that IMP_PREPASS IMP_MAXOFFSET could be set w/o
getting data first.

=item * define level in IMP_LOG

=item * specify IMP_PORT_*

Specify IMP_PORT_* and have sample implementation which uses it.

=item * behavior on EOF

There is currently no way for the analyzer to issue a IMP_REPLACE on
read-shutdown on one side, because the IMP client will forward the shutdown
once all buffers are empty.
It might be possible solution to require the analyzer to explicitly acknowledge
the processing of the shutdown by sending an IMP_PASS with an offset after the
connection end.

=back

=head1 AUTHOR

Steffen Ullrich <sullr@cpan.org>

Thanks to everybody who helped with time, ideas, reviews or bug reports,
notably Alexander Bluhm and others at genua.de.

=head1 COPYRIGHT

Copyright by Steffen Ullrich.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.
