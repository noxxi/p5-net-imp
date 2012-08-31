use strict;
use warnings;

package Net::IMP::Base;
use base 'Net::IMP';
use Carp 'croak';
use fields (
    'meta', # hash with meta data given in new_analyzer
    'cb',   # callback, set from new_analyzer or with set_callback
    'rv'    # collected results for polling or callback, set from add_results
);

sub new_analyzer {
    my ($class,%args) = @_;
    my Net::IMP::Base $self = fields::new($class);
    %$self = %args;
    $self->{rv} ||= [];
    return $self;
}

sub add_results {
    my Net::IMP::Base $self = shift;
    push @{$self->{rv}},@_;
}

sub set_callback {
    my Net::IMP::Base $self = shift;
    my ($sub,@args) = @_;
    $self->{cb} = $sub ? [ $sub,@args ]:undef;
    $self->run_callback;
}

sub poll_results {
    my Net::IMP::Base $self = shift;
    my $rv = $self->{rv};
    $self->{rv} = [];
    return @$rv;
}


sub run_callback {
    my Net::IMP::Base $self = shift;
    my $rv = $self->{rv}; # get collected results
    push @$rv,@_ if @_;   # add more results
    if ( my $cb = $self->{cb} ) {
	my ($sub,@args) = @$cb;
	$self->{rv} = [];                # reset self.rv
	$sub->(@args,@$rv); # and call back
    }
}


# make string from hash config, using URL encoding to escape special chars
sub cfg2str {
    my Net::IMP::Base $self = shift;
    my %cfg = @_;
    return join('&', map {
	my $v = $cfg{$_};
	# only encode really necessary stuff
	s{([=&%\x00-\x20\x7f-\xff])}{ sprintf("%%%02X",ord($1)) }eg; # key
	$v =~s{([&%\x00-\x20\x7f-\xff])}{ sprintf("%%%02X",ord($1)) }eg; # value
	"$_=$v"
    } sort keys %cfg);
}

# make has config from string created by cfg2str
sub str2cfg {
    my Net::IMP::Base $self = shift;
    my $str = shift;
    my %cfg;
    for my $kv (split('&',$str)) {
	my ($k,$v) = split('=',$kv,2);
	s{%([\dA-F][\dA-F]])}{ chr(hex($1)) }ieg for ($k,$v);
	exists $cfg{$k} and croak "duplicate definition for key $k";
	$cfg{$k} = $v;
    }
    return %cfg;
}

1;
__END__

=head1 NAME

Net::IMP::Base - base class for Net::IMP analyzers

=head1 SYNOPSIS

    package mySessionLog;
    use base 'Net::IMP::Base';
    use fields qw(... local fields ...);

    sub new_analyzer {
	my ($class,%args) = @_;
	... handle local %args ...
	my $self = $class->SUPER::new_analyzer(%args);
	...
	return $self
    }

    sub data {
	my ($self,$dir,$data,$offset) = @_;
	... analyse data ...
	... propagate results with $self->run_callback ...
    }

=head1 DESCRIPTION

C<Net::IMP::Base> is a class to make it easier to write IMP analyzers.
It can not be used on its own but should be used as a base class in new
analyzers.

It provides the following interface:

=over 4

=item $class->new_analyzer(%args)

Called from C<<$factory->new_analyzer(%fargs)>> for creating the analyzer for a
new pair of data streams.
The arguments will be a combination of the C<%fargs> given when creating
the factory with C<new_factory> and C<%args> given when using the factory
with C<new_analyzer>.

Derived classes should handle (and remove) all local settings from C<%args>
and then call C<<$class->SUPER::new_analyzer(%rest_args)>> to construct
C<$self>.

This method might generate results already.
This might be the case, if it needs to analyze only one direction (e.g. issue
IMP_PASS with IMP_MAXOFFSET for the other direction) or if it needs to only
intercept data but not deny or modify based on the data (e.g. issue IMP_PREPASS
with IMP_MAXOFFSET).

C<Net::IMP::Base> supports only two elements in C<%args>, any other elements
will cause an error:

=over 8

=item meta

This will be stored in C<$self->{meta}>.
Usually used for storing context specific information from the application.
Some modules (like L<Net::IMP::SessionLog>) depend on C<meta> providing a hash
reference with specific entries.

=item cb

This is the callback and will be stored in C<$self->{cb}>.
Callback should be specified as an array reference with C<[$sub,@args]>.
See C<set_callback> method for more information.

If you set the callback this way, you have to be prepared to handle calls to
the callback immediatly, even if C<new_analyzer> did not return yet.
If you don't want this, use C<set_callback> after creating the analyzer
instead.

=item rv

A list of initial results can be given.
This is usually not a good idea.

=back

=item $self->data($dir,$data,$offset)

Will be called from the user of the analyzer whenever new data (or eof) are
available.
C<$dir> is the direction (0|1), C<$data> are the data (C<''> to mark eof) and
C<$offset> is the position in the input stream where C<$data> start.

C<$offset> must only be given from the caller if there were gaps in the input
stream (which are allowed for IMP_PASS results with an offset in the future).

This method will contain the analyzer specific processing.
Results from the analyzer will be propagated to the caller using
C<run_callback>.

=item $self->run_callback(@results)

This method should be called from the analyzer object from within the C<data>
method to propagate results using the callback provided by the user of the
analyzer.
It will propagate all spooled results and new results given to this method.

Each result is an array reference, see L<Net::IMP> for details.

=item $self->add_results(@results)

This method adds new results to the list of collected results, but will not
call any callbacks.
It will usually be used in the analyzer from within the C<data> method.

=item $self->set_callback($sub,@args)

This will set the callback (C<$self->{cb}>).
This method will be called from the user of the analyzer.
The callback will be used within C<run_callback> and called with
C<< $sub->(@args,@results) >>.

If there are already collected results, the callback will be executed
immediately.
If you don't want this, remove these results upfront with C<poll_results>.

=item $self->poll_results

This will return the current C<@results> and remove them from collected
results.
It will only be used from the caller of the analyzer if no callback is set.

=back

Additionally the following methods are defined to aid in using configuration
from a single string:

=over 4

=item $class->cfg2str(%config) -> $string

Creates a string from a (configuration) hash.
The output is similar to encoded query parameters in URLs.

=item $class->str2cfg($string) -> %config

Parses a configuration string generated by C<cfg2str> and restores the
configuration hash.

=back

=head1 AUTHOR

Steffen Ullrich <sullr@cpan.org>

=head1 COPYRIGHT

Copyright by Steffen Ullrich.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.
