use strict;
use warnings;

package Net::IMP::Pattern;
use base 'Net::IMP::Base';
use fields (
    'rx',       # Regexp from args rx|string
    'rxlen',    # max size rx can match
    'rxdir',    # only check this direction
    'action',   # deny|reject|replace
    'actdata',  # data for action
    'buf',      # locally buffered data to match rx, <rxlen and per dir
    'offset',   # buf[dir][0] is at offset in input stream dir
);

use Net::IMP; # import IMP_ constants
use Net::IMP::Debug;
use Carp 'croak';

sub USED_RTYPES {
    my ($self,%args) = @_;
    my @rv = IMP_PASS;
    push @rv,
	$args{action} eq 'deny'    ? IMP_DENY :
	$args{action} eq 'reject'  ? (IMP_REPLACE, IMP_TOSENDER) :
	$args{action} eq 'replace' ? IMP_REPLACE :
	! $args{action}            ? IMP_DENY :
	croak("invalid action $args{action}");
    return @rv;
};

# create new analyzer object
sub new_analyzer {
    my ($class,%args) = @_;

    my ($rx,$rxlen);
    if ( $rx = delete $args{rx} ) {
	defined $args{string} and croak(
	    "only rx or string can be specified, not both");
	$rxlen = delete $args{rxlen} or croak(
	    "need to know the maximum length the pattern could match");
	$rxlen>0 or croak("rxlen must be >0");
	$rx = eval { qr/$rx/ } or croak("'$rx' is no valid regex: $@")
	    if ! ref $rx;
	ref($rx) eq 'Regexp' or croak("rx must be regex");

	# make sure that rx does not match empty string
	'' =~ $rx and croak("rx should not match empty string");

    } elsif ( ( $rx = delete $args{string} ) ne '' ) {
	$rxlen = length($rx);
	$rx = qr/\Q$rx/;
    } else {
	croak("rx+rxlen or string need to be given for pattern");
    }

    $args{action} ~~ [qw(deny reject replace)] or croak(
	"action can only be deny|reject|replace");

    my Net::IMP::Pattern $self = $class->SUPER::new_analyzer(
	%args, # rxdir, actdata, action, cb, meta
	rx => $rx,
	rxlen => $rxlen,
	buf => ['',''],  # per direction
	offset => [0,0], # per direction
    );

    if ( defined $self->{rxdir} ) {
	# if rx is specified only for one direction immediatly issue PASS until
	# end for the other direction
	$self->run_callback([
	    IMP_PASS,
	    $self->{rxdir} ? 0:1,
	    IMP_MAXOFFSET,
	]);
    }

    return $self;
}

sub data {
    my Net::IMP::Pattern $self = shift;
    my ($dir,$data) = @_;

    # if this is the wrong dir return, we already issued PASS
    return if defined $self->{rxdir} and $dir != $self->{rxdir};

    my $buf = $self->{buf}[$dir] .= $data;
    $DEBUG && debug("got %d bytes on %d, bufsz=%d, rxlen=%d",
	length($data),$dir,length($buf),$self->{rxlen});

    my @rv;
    while (1) {
	if ( my ($good,$match) = $buf =~m{\A(.*?)($self->{rx})}s ) {
	    # rx matched:
	    # - strip up to end of rx from buf
	    # - issue IMP_PASS for all data in front of rx
	    # - handle rx according to action
	    # - continue with buf after rx (e.g. redo loop)

	    if ( length($match)> $self->{rxlen} ) {
		# user specified a rx, which could match more than rxlen, e.g.
		# something like qr{\d+}. make sure we only match rxlen bytes
		if ( substr($match,0,$self->{rxlen}) =~m{\A($self->{rx})} ) {
		    $match = $1;
		} else {
		    # no match possible in rxlen bytes, reset match
		    # and add one char from original match to $good
		    # so that we don't try to match here again
		    $good .= substr($match,0,1);
		    $match = '';
		}
	    } else {
		# we checked in new_analyzer already that rx does not match
		# empty string, so we should be save here that rxlen>=match>0
	    }

	    # remove up to end of matched data from buf
	    substr($buf,0,length($good)+length($match),'');

	    if ( $good ne '' ) {
		$DEBUG && debug("pass %d bytes in front of match",
		    length($good));
		# pass everything before the match and advance offset
		push @rv, [
		    IMP_PASS,
		    $dir,
		    $self->{offset}[$dir]+=length($good)
		]
	    }

	    if ( $match eq '' ) {
		# match got resetted if >rxlen -> no action

	    # handle the matched pattern according to action
	    } elsif ( $self->{action} eq 'deny' ) {
		# deny everything after
		push @rv,[ IMP_DENY,$dir,$self->{actdata}//'' ];
		last; # deny is final

	    } elsif ( $self->{action} eq 'reject' ) {
		# forward nothing, send smthg back to sender
		push @rv,[
		    IMP_REPLACE,
		    $dir,
		    $self->{offset}[$dir] += length($match),
		    ''
		];
		push @rv,[ IMP_TOSENDER,$dir,$self->{actdata} ]
		    if $self->{actdata} ne '';

	    } elsif ( $self->{action} eq 'replace' ) {
		# forward something else
		push @rv,[
		    IMP_REPLACE,
		    $dir,
		    $self->{offset}[$dir] += length($match),
		    $self->{actdata}//''
		];

	    } else {
		# should not happen, because action was already checked
		die "invalid action $self->{action}";
	    }

	    last if $buf eq ''; # need more data

	} elsif ( (my $d = length($buf) - $self->{rxlen} + 1) > 0 ) {
	    # rx did not match, but >=rxlen bytes in buf:
	    # we can IMP_PASS some, but rxlen-1 data needs to be kept in buffer
	    # so that we retry rx when new data come in
	    $DEBUG && debug("can pass %d of %d bytes",$d,length($buf));
	    push @rv, [ IMP_PASS, $dir, $self->{offset}[$dir] += $d ];
	    substr($buf,0,$d,'');

	    last; # need more data

	} elsif ( $data eq '' ) {
	    # rx did not match, but eof:
	    # no more data will come which can match rx so we can pass the rest
	    $DEBUG && debug("pass rest of data on eof");
	    if ( $buf ne '' ) {
		push @rv,[ IMP_PASS,$dir,$self->{offset}[$dir]+=length($buf)];
		$buf = '';
	    }

	    last; # there will be no more matches because of no data

	} else {
	    # rx did not match, but no eof:
	    last; # need more data
	}
    }

    if ( @rv ) {
	$self->{buf}[$dir] = $buf; # $buf got changed, put back
	$self->run_callback(@rv);
    } else {
	$DEBUG && debug("need more data");
    }
}


1;

__END__

=head1 NAME

Net::IMP::Pattern - IMP plugin for matching pattern and blocking, replacing...

=head1 SYNOPSIS

    my $factory = Net::IMP::Pattern->new_factory(
	rx       => qr/this|that/, # pattern
	rxlen    => 7,             # maximum length regex can match
	action   => 'replace',     # 'deny','reject'..
	actdata  => 'newdata',     # replace with newdata
    );

=head1 DESCRIPTION

C<Net::IMP::Pattern> implements an analyzer to match regular expressions and
replace or reject the data or cause a deny.
The behavior is specified in the arguments given to C<new_factory> or
C<new_analyzer>.

=over 4

=item rx Regex

The regular expression, either as Regexp or as a string which will be
interpreted as a regular expression.

C<rx> should only match up to the number of bytes specified by C<rxlen>, e.g.
regular expressions like C</\d+/> should be avoided, better use C</\d{1,10}/>.
Although it will do its best to only match C<rxlen> in that case, these
kind of broad regular expressions are a sign, that the user does not really
know what should be matched.

Regular expressions which can match the empty buffer, like C</\d*/>, are not
allowed at all and it will croak when trying to use such a regular expression.

=item rxlen Integer

The maximum number of bytes the regex could match or is allowed to match.
This argument is necessary together with C<rx> because there is no way to
determine how many bytes an arbitrary regular expression might match.

=item string String

Instead of giving the regular expression C<rx> together with C<rxlen>, a fixed
string can be given.

=item rxdir 0|1

With this optional argument one can restrict the direction where C<rx> or
C<string> will be applied.
Data in the other direction will pass directly.

=item action String

The following actions are supported

=over 8

=item 'deny'

Causes a deny (e.g. close) of the connection, with the deny message specified in
C<actdata>

=item 'reject'

Rejects the data, e.g. replaces the data with C<''> and sends the string given
in C<actdata> back to the sender.

=item 'replace'

Replaces the data with the string given in C<actdata>

=back

=item actdata String

Meaning depends on C<action>. See there.

=back