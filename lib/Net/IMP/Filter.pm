use strict;
use warnings;
package Net::IMP::Filter;
use fields qw(imp buf passed topass prepass skipped eof);
use Net::IMP;
use Net::IMP::Debug;


############################################################################
#  these need to be redefined in subclass
############################################################################
# analyzed data output
sub out {
    my ($self,$dir,$data) = @_;
    return;
}

sub deny {
    my ($self,$msg,$dir) = @_;
    $DEBUG && debug("deny $msg");
    return;
}

sub log {
    my ($self,$level,$msg,$dir,$offset,$len) = @_;
    $DEBUG && debug("log [$level] $msg");
    return;
}

sub acctfld {
    my ($self,$key,$value) = @_;
    $DEBUG && debug("acctfld $key=$value");
    return;
}

############################################################################
#  Implementation
############################################################################
sub new {
    my ($class,$imp) = @_;
    my $self = fields::new($class);
    %$self = (
	imp   => $imp,
	buf     => ['',''],
	passed  => [0,0], # offset of buf in input stream
	topass  => [0,0], # may pass up to this offset
	prepass => [0,0], # flag if topass means prepass, not pass
	skipped => [0,0], # flag if last data got not send to analyzer
			  # because of pass into future
	eof     => 0,     # bitmask set inside output
    );
    $imp->set_callback(\&_imp_cb,$self) if $imp;
    return $self;
}

# data into analyzer
sub in {
    my ($self,$dir,$data) = @_;
    return _out($self,$dir,$data) if ! $self->{imp};

    $DEBUG && debug("in($dir) %d bytes",length($data));

    # (pre)pass w/o analyzing (first)
    my $diff = $self->{topass}[$dir]-$self->{passed}[$dir];
    if ( $diff>0 ) {
	$DEBUG && debug("can (pre)pass w/o analyzing (first) diff=$diff ".
	    "topass=$self->{topass}[$dir] passed=$self->{passed}[$dir] l=".
	    length($data));
	# (pre)pass in future
	$self->{buf}[$dir] eq '' or die "buf should be empty";
	my $out = substr($data,0,$diff,'');
	$self->{passed}[$dir] += length($out);
	_out($self,$dir,$out);
	if ( $self->{prepass}[$dir] ) {
	    $self->{imp}->data($dir,$out)
	} elsif ( $out ne '' ) {
	    $self->{skipped}[$dir] = 1;
	}
	return if $data eq ''; # everything passed
    }

    # forward data or eof
    $self->{buf}[$dir] .= $data;
    if ( $self->{skipped}[$dir] ) {
	$DEBUG && debug("fwd($dir) %d bytes offset=%d",
	    length($data),$self->{passed}[$dir]);
	$self->{imp}->data($dir,$data,$self->{passed}[$dir]);
    } else {
	$DEBUG && debug("fwd($dir) %d bytes",length($data));
	$self->{imp}->data($dir,$data);
    }
}

# callback from analyzer
sub _imp_cb {
    my $self = shift;

    for my $rv (@_) {
	my $rtype = shift(@$rv);
	$DEBUG && debug("$rtype ".join(" ",map { "'$_'" } @$rv));

	if ( $rtype == IMP_DENY ) {
	    my ($dir,$msg) = @$rv;
	    $self->deny($msg,$dir);
	    return;

	} elsif ( $rtype == IMP_LOG ) {
	    my ($dir,$offset,$len,$level,$msg) = @$rv;
	    $self->log($level,$msg,$dir,$offset,$len);

	} elsif ( $rtype == IMP_ACCTFIELD ) {
	    my ($key,$value) = @$rv;
	    $self->acctfld($key,$value);

	} elsif ( $rtype ~~ [ IMP_PASS, IMP_PREPASS, IMP_REPLACE ] ) {
	    my ($dir,$offset,$newdata) = @$rv;
	    $DEBUG && debug("got %s %d|%d passed=%d inbuf=%d",
		$rtype,$dir,$offset,$self->{passed}[$dir],
		length($self->{buf}[$dir]));

	    my $diff = $offset - $self->{passed}[$dir];
	    if ( $diff<0 ) {
		$DEBUG && debug("diff=$diff - $rtype for already passed data");
		# already passed
		die "cannot replace already passed data"
		    if $rtype == IMP_REPLACE;
		next;
	    }

	    my $rl = length($self->{buf}[$dir]);
	    my $l = $rl>$diff ? $diff: $rl;
	    $DEBUG && debug("need to $rtype $l bytes");

	    $self->{passed}[$dir]  += $l;
	    $self->{topass}[$dir]  = $offset;
	    $self->{prepass}[$dir] = ($rtype == IMP_PREPASS);

	    if ( $rtype == IMP_REPLACE ) {
		die "cannot replace not yet received data" if $rl<$diff;
		$DEBUG && debug("buf='%s' [0,$l]->'%s'",
		    substr($self->{buf}[$dir],0,$l),$newdata);
		substr($self->{buf}[$dir],0,$l,$newdata);
		$l = length($newdata);
	    }

	    # output accepted data
	    _out($self,$dir,substr($self->{buf}[$dir],0,$l,'')) if $l;

	} else {
	    die "cannot handle Net::IMP rtype $rtype";
	}
    }
}

sub _out {
    my ($self,$dir,$data) = @_;
    if ( $data eq '' and  3 == ($self->{eof} |= $dir ? 1:2)
	and $self->{imp}) {
	# finished connection, remove circular dependencies
	$self->{imp}->set_callback(undef);
	$self->{imp} = undef;
    }
    $self->out($dir,$data);
}

1;
__END__

=head1 NAME

Net::IMP::Filter - simple data filter using Net::IMP analyzers

=head1 SYNOPSIS

    package myFilter;
    use base 'Net::IMP::Filter';
    sub out {
	my ($self,$dir,$data) = @_;
	print "[$dir] $data\n";
    }

    package main;
    use Net::IMP::Pattern;
    my $factory = Net::IMP::Pattern->new_factory...;
    my $f = myFilter->new( $factory->new_analyzer );
    ..
    $f->in(0,$data0);
    $f->in(1,$data1);
    ..

=head1 DESCRIPTION

C<Net::IMP::Filter> is a class which can be used for simple filters (e.g. data in,
data out) using Net::IMP analyzers, thus hiding the complexity but also useful
features of the Net::IMP interface for simple use cases.
To create such a filter subclass from C<Net::IMP::Filter> and implement any of the
following methods (which by default do nothing)

=over 4

=item out($self,$dir,$data)

this gets called for output of data

=item deny($self,$msg,$dir)

this gets called on IMP_DENY

=item log($self,$level,$msg,$dir,$offset,$len)

this gets called on IMP_LOG

=item acctfld($self,$key,$value)

this gets called on IMP_ACCTFIELD

=back

=head1 AUTHOR

Steffen Ullrich <sullr@cpan.org>

=head1 COPYRIGHT

Copyright by Steffen Ullrich.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.
