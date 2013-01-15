use strict;
use warnings;

package Net::IMP::Base;
use Net::IMP;
use Carp 'croak';
use fields (
    'factory_args', # arguments given to new_factory
    'meta',         # hash with meta data given to new_analyzer
    'analyzer_cb',  # callback, set from new_analyzer or with set_callback
    'analyzer_rv',  # collected results for polling or callback, set from add_results
);

use Net::IMP::Debug;


############################################################################
# API plugin methods
############################################################################

# creates new factory
sub new_factory {
    my ($class,%args) = @_;
    my Net::IMP::Base $factory = fields::new($class);
    $factory->{factory_args} = \%args;
    return $factory;
}

# make string from hash config, using URL encoding to escape special chars
sub cfg2str {
    my (undef,%cfg) = @_;
    return join('&', map {
	my $v = $cfg{$_};
	# only encode really necessary stuff
	s{([=&%\x00-\x20\x7f-\xff])}{ sprintf("%%%02X",ord($1)) }eg; # key
	if ( defined $v ) { # value
	    $v =~s{([&%\x00-\x20\x7f-\xff])}{ sprintf("%%%02X",ord($1)) }eg;
	    "$_=$v"
	} else {
	    "$_"
	}
    } sort keys %cfg);
}

# make has config from string created by cfg2str
sub str2cfg {
    my (undef,$str) = @_;
    my %cfg;
    for my $kv (split('&',$str)) {
	my ($k,$v) = $kv =~m{^([^=]+)(?:=(.*))?};
	$k =~s{%([\dA-F][\dA-F])}{ chr(hex($1)) }ieg;
	exists $cfg{$k} and croak "duplicate definition for key $k";
	$v =~s{%([\dA-F][\dA-F])}{ chr(hex($1)) }ieg if defined $v;
	$cfg{$k} = $v;
    }
    return %cfg;
}

# validate config, return list of errors
sub validate_cfg {
    my (undef,%cfg) = @_;
    return %cfg ? "unexpected config keys ".join(', ',keys %cfg) : ();
}

############################################################################
# API factory methods
############################################################################

# create new analyzer
sub new_analyzer {
    my Net::IMP::Base $factory = shift;
    my %args = @_;
    my $cb = delete $args{cb};

    my $analyzer = fields::new(ref($factory));
    %$analyzer = ( 
	%$factory,          # common properties of all analyzers
	%args,              # properties of this analyzer
	analyzer_rv => [],  # reset queued return values
    );
    $analyzer->set_callback(@$cb) if $cb;
    return $analyzer;
}

# get available interfaces
# returns factory for the given interface
# might be a new one or same as called on
sub set_interface {
    my Net::IMP::Base $factory = shift;
    my $want = shift;
    my ($if) = $factory->get_interface($want) or return;
    if ( my $adaptor = $if->[2] ) {
	# use adaptor
	return $adaptor->new_factory(factory => $factory)
    } else {
	return $factory
    }
}

# returns list of available [ if, adaptor_class ], restricted by given  @if
sub INTERFACE { die "needs to be implemented" }
sub get_interface {
    my Net::IMP::Base $factory = shift;
    my @local = $factory->INTERFACE;

    # return all supported interfaces if none are given
    return @local if ! @_; 

    # find matching interfaces
    my @match;
    for my $if (@_) {
	my ($in,$out) = @$if;
	for my $lif (@local) {
	    my ($lin,$lout,$adaptor) = @$lif;
	    if ( $lin and $lin != $in ) {
		# no match data type/proto
		debug("data type mismatch: want $in have $lin");
		next;
	    }

	    if ( ! $out || ! @$out ) {
		# caller will accept any return types
	    } else {
		# any local return types from not in out?
		my %lout = map { $_ => 1 } @$lout;
		delete @lout{@$out};
		if ( %lout ) {
		    # caller does not support all return types
		    debug("no support for return types ".join(' ',keys %lout));
		    next;
		}
	    }
		
	    if ( $adaptor ) {
		# make sure adaptor class exists
		if ( ! eval "require $adaptor" ) {
		    debug("failed to load $adaptor: $@");
		    next;
		}
	    }

	    # matches
	    push @match, [ $in,$out,$adaptor ];
	    last;
	}
    }

    return @match;
}

############################################################################
# API analyzer methods
############################################################################

# set callback
sub set_callback {
    my Net::IMP::Base $analyzer = shift;
    my ($sub,@args) = @_;
    $analyzer->{analyzer_cb} = $sub ? [ $sub,@args ]:undef;
    $analyzer->run_callback;
}

# return queued results
sub poll_results {
    my Net::IMP::Base $analyzer = shift;
    my $rv = $analyzer->{analyzer_rv};
    $analyzer->{analyzer_rv} = [];
    return @$rv;
}

sub data { die "needs to be implemented" }
    

############################################################################
# internal analyzer methods
############################################################################

sub add_results {
    my Net::IMP::Base $analyzer = shift;
    push @{$analyzer->{analyzer_rv}},@_;
}

sub run_callback {
    my Net::IMP::Base $analyzer = shift;
    my $rv = $analyzer->{analyzer_rv}; # get collected results
    push @$rv,@_ if @_;   # add more results
    if ( my $cb = $analyzer->{analyzer_cb} ) {
	my ($sub,@args) = @$cb;
	$analyzer->{analyzer_rv} = []; # reset
	$sub->(@args,@$rv); # and call back
    }
}


1;
__END__

=head1 NAME

Net::IMP::Base - base class to make writing of Net::IMP analyzers easier

=head1 SYNOPSIS

    package myPlugin;
    use base 'Net::IMP::Base';
    use fields qw(... local fields ...);

    # plugin methods
    # sub new_factory ...  - has default implementation
    # sub cfg2str ...      - has default implementation
    # sub str2cfg ...      - has default implementation
    sub validate_cfg ...   - needs to be implemented

    # factory methods
    sub INTERFACE ...      - needs to be implemented
    # sub get_interface .. - has default implementation using sub INTERFACE
    # sub set_interface .. - has default implementation using sub INTERFACE
    # sub new_analyzer ... - has default implementation

    # analyzer methods
    sub data ...           - needs to be implemented
    # sub poll_results ... - has default implementation
    # sub set_callback ... - has default implementation

=head1 DESCRIPTION

C<Net::IMP::Base> is a class to make it easier to write IMP analyzers.
It can not be used on its own but should be used as a base class in new
analyzers.

It provides the following interface for the global plugin API as required for
all L<Net::IMP> plugins.

=over 4

=item cfg2str|str2cfg

These functions convert a C<%config> to or from a C<$string>.
In this implementation the <$string> is a single line, encoded similar to the
query_string in HTTP URLs.

There is no need to re-implement this function unless you want to serialize the
config into a different format.

=item $class->validate_cfg(%config)

This function verifies the config and thus should be reimplemented in each
sub-package.

The implementation in this package just complains, if there are any data left
in C<%config> and thus should be called with any config data not handled by
your own validation function.

=item $class->new_factory(%args)

This will create a new factory class. 
C<%args> will be saved into C<$factory->{factory_args}> and later used when
creating the analyzer.
There is no need to re-implement this method.

=back

The following methods are implemented on factory objects as required by
L<Net::IMP>:

=over 4

=item $factory->get_interface(@caller_if) => @plugin_if

This method provides an implementation of the C<get_interface> API function. 
This implementation requires the implementation of a function C<INTERFACE> like
this:

  sub INTERFACE { return (
    [ 
      # require HTTP data types
      IMP_DATA_HTTP,          # input data types/protocols
      [ IMP_PASS, IMP_LOG ]   # output return types
    ],[
      # we can handle stream data too if we use a suitable adaptor
      IMP_DATA_STREAM, 
      [ IMP_PASS, IMP_LOG ],
      'Net::IMP::Adaptor::STREAM2HTTP',
    ]
  )}

There is no need to re-implement method C<get_interface>, but C<INTERFACE>
should be implemented. 
If your plugin can handle any data types you can set the type to C<undef>
in the interface description.

=item $factory->set_interface($want_if) => $new_factory

This method provides an implementation of the C<set_interface> API function. 
This implementation requires the implementation of C<INTERFACE> like described
for C<get_interface>.
There is no need to re-implement method C<set_interface>, but C<INTERFACE>
should be implemented. 

=item $factory->new_analyzer(%args)

This method is called from C<<$factory->new_analyzer(%fargs)>> for creating the
analyzer for a new pair of data streams.

This implementation will create a new analyzer object based on the factory
object, e.g. it will use %args for the fields in the analyzer but also provide
access to the args given when creating the factory within field C<factory_args>.

If the interface required an adaptor it will wrap the newly created analyzer
into the adaptor with C<< $analyzer = $adaptor_class->new($analyzer) >>.

Derived classes should handle (and remove) all local settings from C<%args>
and then call C<<$class->SUPER::new_analyzer(%rest_args)>> to construct
C<$analyzer>.

This method might generate results already.
This might be the case, if it needs to analyze only one direction (e.g. issue
IMP_PASS with IMP_MAXOFFSET for the other direction) or if it needs to only
intercept data but not deny or modify based on the data (e.g. issue IMP_PREPASS
with IMP_MAXOFFSET).

C<Net::IMP::Base> supports only two elements in C<%args>, any other elements
will cause an error:

=over 8

=item meta

This will be stored in C<$analyzer->{meta}>.
Usually used for storing context specific information from the application.
Some modules (like L<Net::IMP::SessionLog>) depend on C<meta> providing a hash
reference with specific entries.

=item cb

This is the callback and will be stored in C<$analyzer->{analyzer_cb}>.
Callback should be specified as an array reference with C<[$sub,@args]>.
See C<set_callback> method for more information.

If you set the callback this way, you have to be prepared to handle calls to
the callback immediatly, even if C<new_analyzer> did not return yet.
If you don't want this, use C<set_callback> after creating the analyzer
instead.

=back

The following methods are implemented on analyzer objects as required by
L<Net::IMP>:

=over 4 

=item $analyzer->set_callback($sub,@args)

This will set the callback (C<$analyzer->{analyzer_cb}>).
This method will be called from the user of the analyzer.
The callback will be used within C<run_callback> and called with
C<< $sub->(@args,@results) >>.

If there are already collected results, the callback will be executed
immediately.
If you don't want this, remove these results upfront with C<poll_results>.

=item $analyzer->poll_results

This will return the current C<@results> and remove them from collected
results.
It will only be used from the caller of the analyzer if no callback is set.

=item $analyzer->data($dir,$data,$offset,$dtype)

This method should be defined for all analyzers.
The implementation in this package will just croak.

=back

Also the following methods are defined for analyzers and can be used inside
your own analyzer.

=over 4

=item $analyzer->add_results(@results)

This method adds new results to the list of collected results.
Each result is an array reference, see L<Net::IMP> for details.

It will usually be used in the analyzer from within the C<data> method.

=item $analyzer->run_callback(@results)

Like C<add_results> this will add new results to the list of collected results.
Additionally it will propagate the results using the callback provided by the
user of the analyzer.
It will propagate all spooled results and new results given to this method.

=back


=head1 AUTHOR

Steffen Ullrich <sullr@cpan.org>

=head1 COPYRIGHT

Copyright by Steffen Ullrich.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.
