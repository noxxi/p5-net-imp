use strict;
use warnings;

package Net::IMP::ProtocolPinning;
use base 'Net::IMP::Base';
use fields (
    'buf',            # buffered data for each direction
    'off_buf0',       # position of buf[dir][0] in input stream
    'off_not_fwd',    # offset up to which not yet forwarded
    'rules',          # rules from config
    'ignore_order',   # ignore_order from config
    'max_unbound',    # max_unbound from config
);

use Net::IMP; # import IMP_ constants
use Net::IMP::Debug;
use Carp 'croak';

sub USED_RTYPES { (IMP_PASS,IMP_DENY) }

sub validate_cfg {
    my ($class,%args) = @_;

    my @err;
    if ( my $r = delete $args{rules} ) {
	# make sure that no rule matches empty string
	for (my $i=0;$i<@$r;$i++) {
	    push @err,"rule$i.dir must be 0|1" unless
		defined $r->[$i]{dir} and
		$r->[$i]{dir} ~~ [0,1];
	    push @err,"rule$i.rxlen must be >0" unless
		$r->[$i]{rxlen} and
		$r->[$i]{rxlen} =~m{^\d+$} and
		$r->[$i]{rxlen}>0;
	    push @err,"rule$i.rx should be regex"
		if ref($r->[$i]{rx}) ne 'Regexp';
	    push @err,"rule$i.rx should not match empty string"
		if '' =~ $r->[$i]{rx};
	}
    } else {
	push @err,"rules need to be given";
    }

    if ( my $max_unbound  = delete $args{max_unbound} ) {
	push @err,"max_unbound should be [max0,max1]" if @$max_unbound>2;
	for (0,1) {
	    defined $max_unbound->[$_] or next;
	    push @err, "max_unbound[$_] should be number >=0"
		if $max_unbound->[$_] !~m{^\d+$};
	}
    }

    delete $args{ignore_order}; # boolean, no further checks

    push @err,$class->SUPER::validate_cfg(%args);
    return @err;
}

# create new analyzer object
sub new_analyzer {
    my ($class,%args) = @_;

    my $rules = delete $args{rules} or croak("no rules given");
    my @rules = @$rules; # copy because they get modified inside

    # set buf to '' for dir where we have rules, else leave undef
    my @buf;
    $buf[$_->{dir}] = '' for (@rules);

    my $ignore_order = delete $args{ignore_order};
    my $max_unbound  = delete $args{max_unbound} // [];
    my Net::IMP::ProtocolPinning $self = $class->SUPER::new_analyzer(
	%args,

	# -- internal tracking ---
	# buffer per direction
	buf => \@buf,
	# offset for buffer per direction
	off_buf0 => [0,0],
	# amount of data not yet forwarded
	off_not_fwd => [0,0],

	# -- configuration ------
	# array of rules, rule is hash with dir,rxlen,rx
	rules => \@rules,
	# if true server can send even if we except client data first etc
	ignore_order => $ignore_order,,
	# maximum number of data after all rules for direction are done (e.g
	# data which cannot be bound to rule)
	max_unbound => $max_unbound,
    );

    return $self;
}

sub data {
    my Net::IMP::ProtocolPinning $self = shift;
    my ($dir,$data) = @_;

    $self->{buf} or return; # we gave already the final reply

    if ( ! defined $self->{buf}[$dir] ) {
	# no rules for $dir, so we don't buffer, but track off_not_fwd
	# issue DENY when we have too much data open
	my $open = $self->{off_not_fwd}[$dir] += length($data);
	if ( defined( my $max = $self->{max_unbound}[$dir])) {
	    if ( $open>$max ) {
		$self->{buf} = undef;
		$self->run_callback(
		    [IMP_DENY,$dir,"too much data outside rules"]);
	    }
	}
	return;
    }

    # add data to buf
    my $buf = $self->{buf}[$dir] .= $data;
    $self->{off_not_fwd}[$dir] += length($data);
    $DEBUG && debug("got %d bytes on %d, bufsz=%d",
	length($data),$dir,length($buf));


    # will cause IMP_PASS if rule matched
    my $pass;

    my $rules = $self->{rules};
    RULE: while ( @$rules and $buf ne '' ) {
	my ($rdir,$rxlen,$rx) = @{$rules->[0]}{qw(dir rxlen rx)};

	if ( $rdir != $dir ) {
	    if ( ! $self->{ignore_order} ) {
		# we got data from the wrong side first
		$self->{buf} = undef;
		$self->run_callback([ IMP_DENY,$dir,'data from wrong side' ]);
		return;
	    }

	    # if we have a rule for $dir bring it to front of @$rules and retry
	    for ( my $i=0;$i<@$rules;$i++ ) {
		if ( $rules->[$i]{dir} == $dir ) {
		    unshift @$rules, splice( @$rules,$i,1 );
		    redo RULE;
		}
	    }

	    # no more rules for $rdir
	    # our internal buffer is no longer needed (no rules), so set to
	    # undef, to indicate, that we don't buffer
	    $self->{buf}[$dir] = undef;

	    # but we cannot release the data inside the caller using IMP_PASS,
	    # because first all other rules have to be matched
	    last;
	}

	# and try to match regex
	# The regex should be constructed, so that the matched string cannot be
	# longer than rxlen, e.g. instead of \d+ you should use the more
	# specific \d{3,10} or so - in any case it will be checked only against
	# a maximum of rxlen bytes.
	# The regex should also not match too early.
	# E.g. if the buffer contains less than rxlen bytes it should not match,
	# because it might match a longer string later when it gets more bytes.
	# So instead of a simple \d{3,10} you should be more specific:
	# \d{3,9}(?=\D)|\d{10}

	my $blen = length($buf);
	if ( substr($buf,0,$rxlen) =~ m{\A($rx)} ) {
	    # rule matched
	    my $mlen = length($1);
	    $DEBUG && debug("'%s' matched with len=%d, bufsz %d->%d: ok",
		$rx,$mlen,$blen,$blen-$mlen);
	    substr($buf,0,$mlen,'');               # remove match from buf
	    $self->{buf}[$dir] = $buf;
	    $self->{off_buf0}[$dir] += $mlen;      # add removed to off_buf0
	    $self->{off_not_fwd}[$dir] -= $mlen;   # remove from off_not_fwd
	    $pass = $self->{off_buf0}[$dir];       # set pass after match
	    shift(@$rules);                        # rules passed -> remove
	    next;                                  # try next rule

	} elsif ( $blen>=$rxlen ) {
	    # pattern did not match although we had enough data in buffer
	    $DEBUG && debug("'%s' did not match buflen(%d)>=rxlen(%d): fail",
		$rx,$blen,$rxlen);
	    $self->{buf} = undef;
	    $self->run_callback([ IMP_DENY,$dir,'rule did not match' ]);
	    return;

	} else {
	    # pattern did not match, but buflen<rxlen: wait for more data
	    $DEBUG && debug("'%s' did not match in 0..%d<=rxlen(%d): ".
		"need more data", $rx,$blen,$rxlen);
	    last;
	}
    }

    if ( ! @$rules ) {
	# all rules passed - let everything through
	$self->{buf} = undef;
	$self->run_callback(
	    [ IMP_PASS,0,IMP_MAXOFFSET ],
	    [ IMP_PASS,1,IMP_MAXOFFSET ],
	);
    } else {
	$DEBUG && debug("need more data from ".$rules->[0]{dir});
	if ( $pass ) {
	    # release data from matched rules
	    $self->run_callback([ IMP_PASS,$dir,$pass ]);
	}
    }
}

# cfg2str and str2cfg are redefined because our config hash is deeper
# nested due to rules and max_unbound
sub cfg2str {
    my Net::IMP::ProtocolPinning $self = shift;
    my %cfg = @_;

    my $rules = delete $cfg{rules} or croak("no rules defined");
    # re-insert [[dir,rxlen,rx],... ] as dir0,rxlen0,rx0,dir1,...
    for (my $i=0;$i<@$rules;$i++) {
	@cfg{ "dir$i","rxlen$i","rx$i" } = @{ $rules->[$i] }{qw( dir rxlen rx)};
    }
    if ( my $max_unbound = delete $cfg{max_unbound} ) {
	# re-insert [mo0,mo1] as max_unbound0,max_unbound1
	@cfg{ 'max_unbound0', 'max_unbound1' } = @$max_unbound;
    }
    return $self->SUPER::cfg2str(%cfg);
}

sub str2cfg {
    my Net::IMP::ProtocolPinning $self = shift;
    my %cfg = $self->SUPER::str2cfg(@_);
    my $rules = $cfg{rules} = [];
    for ( my $i=0;1;$i++ ) {
	defined( my $dir = delete $cfg{"dir$i"} ) or last;
	defined( my $rxlen = delete $cfg{"rxlen$i"} )
	    or croak("no rxlen$i defined but dir$i");
	defined( my $rx = delete $cfg{"rx$i"} )
	    or croak("no rx$i defined but dir$i");
	$rx = eval { qr/$rx/ } or croak("invalid regex rx$i");
	push @$rules, { dir => $dir, rxlen => $rxlen, rx => $rx };


    }
    @$rules or croak("no rules defined");
    my $max_unbound = $cfg{max_unbound} = [];
    for (0,1) {
	$max_unbound->[$_] = delete $cfg{"max_unbound$_"}
	    if exists $cfg{"max_unbound$_"};
    }

    # sanity check
    my %scfg = %cfg;
    delete @scfg{'rules','max_unbound','ignore_order'};
    %scfg and croak("unhandled config keys: ".join(' ',sort keys %scfg));

    return %cfg;
}


1;

__END__

=head1 NAME

Net::IMP::ProtocolPinning - IMP plugin for simple protocol matching

=head1 SYNOPSIS

    my $factory = Net::IMP::ProtocolPinning->new_factory( rules => [
	# HTTP request from client (dir=0)
	[ 0,9,qr{(GET|POST|OPTIONS) \S} ],
    ]);

    my $factory = Net::IMP::ProtocolPinning->new_factory( rules => [
	# SSHv2 prompt from server
	[ 1,6,qr{SSH-2\.} ],
    ]);

    my $factory = Net::IMP::ProtocolPinning->new_factory(
	rules => [
	    # SMTP initial handshake
	    # greeting line from server
	    { dir => 1, rxlen => 512, rx => qr{220 [^\n]*\n} },
	    # HELO|EHLO from client
	    { dir => 0, rxlen => 512, rx => qr{(HELO|EHLO)[^\n]*\n}i },
	    # response to helo|ehlo
	    { dir => 1, rxlen => 512, rx => qr{250-?[^\n]*\n} },
	],
	# some clients send w/o initially waiting for server
	ignore_order => 1,
	max_unbound => [ 1024,0 ],
    );

=head1 DESCRIPTION

C<Net::IMP::ProtocolPinning> implements an analyzer for very simple protocol
verification using rules with regular expressions.
The idea is to only check the first data in the connection for protocol
conformance and then let the rest through without further checks.

Calls to C<new_factory> or C<new_analyzer> can contain the following arguments
specific to this module:

=over 4

=item rules ARRAY

Specifies the rules to use for protocol verification. Rules are an array
of direction specific rules, e.g. each rule consists of C<[dir,rxlen,rx]> with

=over 8

=item dir

the direction, e.g. 0 for data from client and 1 for data from server

=item rxlen

the length of data the regular expression might match

=item rx

the regular expression itself

=back

=item ignore_order BOOLEAN

If true, it will take the first rule for direction, when data for connection
arrive.
If false, it will cause DENY if data arrive from one direction, but the current
rule is for the other direction.

=item max_unbound [SIZE0,SIZE1]

If there are no more active rules for direction, and ignore_order is true, then
the application needs to buffer data, until all remaining rules for the other
direction are matched.
Using this parameter the amount of buffered data which cannot be bound to a rule
will be limited per direction.

If not set a default of unlimited will be used!

=back

=head2 Process of Matching Input Against Rules

=over 4

=item *

When new data arrive from direction and C<ignore_order> is false, it will take
the first active rule and compare the direction of the data with the direction
of the rule.
If they don't match it will be considered a protocol violation and a DENY will
be issued.

When new data arrive from direction, but C<ignore_order> is true, it will pick
the first active rule for this direction.

=item *

If no rule is found for direction, no action will be taken.
This causes the data to be buffered in the application and they will only be
released, once all rules have been processed.

To limit the amount of buffered data in this case C<max_unbound> should be set.
Buffering more data than C<max_unbound> for this direction will cause a DENY.

=item *

A rule was found.
It will add the new data to the local buffer for the direction and then
try to match the first C<rxlen> bytes of the buffer against the rule.

=item *

If the rule matched, it will

=over 8

=item * remove the rule from the list of active rules

=item * remove the matched data from the local buffer

=item * issue a PASS for the matched data

=item * continue with the next active rule (if any)

=back

=item *

If the rule did not match, but the length of the local buffer is greater than
or equal to C<< rxlen >>, it will consider the rule failed and issue a DENY.

If the rule did not match, but the buffer is smaller than rxlen, it will wait
for more data and then try the match again.

=item *

If all rules matched (e.g. no more active rules), it will issue a PASS into the
future until the end of the connection, causing all data to get forwarded
without further analysis.

=back

=head2 Rules for Writing the Regular Expressions

Because the match will be tried whenever new data come in (e.g. the buffer might
have a size of less than, equal to or greater than C<rxlen>), care should be
taken, when constructing the regular expression and determining C<rxlen>:

=over 4

=item *

It should not match data longer than C<rxlen>, e.g. instead of specifying
C<\d+> one should specify a fixed size with C<\d{1,10}>.

=item *

It should not match too early, e.g. if the match should be up to 10 digits, one
should specify C<\d{1,9}(?=\D)|\d{10}> instead of C<\d{1,10}> because the latter
one matches already if the buffered data have length 5, all being digits.
This might be a problem if there is another rule for the direction, which
expected the previous rule to "eat" all digits.

=back

=head1 AUTHOR

Steffen Ullrich <sullr@cpan.org>

=head1 COPYRIGHT

Copyright by Steffen Ullrich.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.
