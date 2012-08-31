use strict;
use warnings;
package Net::IMP::Cascade;
use base 'Net::IMP::Base';
use fields (
    # we do everything with closures inside new_analyzer here, so that the
    # object has only fields for accessing some closures from subs
    'dataf',    # called from sub data
    'closef',   # called from DESTROY
);

use Net::IMP; # constants
use Carp 'croak';
use Scalar::Util 'weaken';
use Hash::Util 'lock_keys';
use Net::IMP::Debug;
use Data::Dumper;

{
    my @implemented_myself = (
	IMP_PASS,
	IMP_PREPASS,
	IMP_REPLACE,
	IMP_DENY,
	IMP_DROP,
	#IMP_TOSENDER, # not supported yet
	IMP_LOG,
	IMP_ACCTFIELD,
    );

    # combine all rtypes from the parts
    # check, if we support each of the rtypes
    # then return the combination of all needed rtypes
    sub USED_RTYPES {
	my ($self,%args) = @_;
	my %used;
	for my $p ( @{$args{parts}} ) {
	    my %u = map { $_ => 1 } $p->USED_RTYPES;
	    %used = (%used,%u);
	    delete @u{@implemented_myself};
	    croak "module ".$p->class." needs types ".join(' ',keys(%u)) if %u;
	}
	return keys(%used);
    }
}

sub new_analyzer {
    my ($class,%args) = @_;

    my $p     = delete $args{parts};
    my $self  = $class->SUPER::new_analyzer(%args);
    my @imp = map { $_->new_analyzer(%args) } @$p;

    # $parts[$dir][$pi] is the part for direction $dir, analyzer $pi
    my @parts;

    # each entry in parts consists of
    # bufs - list of data buffers together with their state of processing
    #   each entry in bufs consists of a hash with
    #   - data: the data
    #   - endpos: position of end of data, relativ to input stream of part
    #   - type: type which caused data, eg IMP_PASS, IMP_REPLACE...
    #     initially 0 (e.g. no type)
    #   - eof: true if last buf in stream
    #   because replacements might add/delete bytes we need to track these
    #   adjustments for a chunk thru all parts. Unfortunatly this is fairly
    #   complex. Example: if we replace 10 bytes with 3 bytes the local
    #   adjustment will be -7. This adjustment will affect the adjustments
    #   of all following data and will effect the final adjustment of this
    #   data chunk in the cascade. But adjustments from later data should
    #   not effect the adjustments for the current data..
    #   - badjust: adjustment done in this [b]uffer, e.g. only caused by
    #     replacements of data in this buffer in the current part
    #   - gbadjust: like badjust, but accumulated over all parts ([g]lobal])
    #   - padjust: accumulated adjustments relativ to input into this [p]art,
    #     e.g. sum of badjust of this and all previous buf in this part
    #   - gpadjust: like padjust, but over all parts ([g]lobal)
    # fwapos - up to which position related to input stream data got
    #   forwarded to analyzer (or passed w/o needing analyzer)
    #   meaning: [pos]ition up to which it got [f]or[w]arded to [a]nalyzer
    # gap    - flag, set if we recently skipped data due to IMP_PASS,
    #   reset, when we send data to the analyzer.
    #   If set the data will be forwarded to the analyzer with offset given
    # lppos  - offset from [l]ast [p]ass|pre[p]ass reply (related to input
    #   stream)
    # lptype - type of reply which updated lppos (pass|prepass)

    # initialize @parts
    for( my $i=0;$i<@imp;$i++ ) {

	# data from client
	$parts[0][$i] = my $h = {
	    bufs   => [ Net::IMP::Cascade::_Buf->new ],
	    fwapos => 0,
	    gap    => 0,
	    lppos  => 0,
	    lptype => IMP_PASS,
	};
	lock_keys(%$h);

	# data from server get processed in the other direction
	#  [CLIENT] --> 00 -> 11 -> .. [SERVER] .. --> 11 -> 00 ->
	$parts[1][$i] = $h = {
	    bufs   => [ Net::IMP::Cascade::_Buf->new ],
	    fwapos => 0,
	    gap    => 0,
	    lppos  => 0,
	    lptype => IMP_PASS,
	};
	lock_keys(%$h);
    }

    # global lastpass
    # if all analyzers in cascade issue a pass/prepass into the future
    # we can propagate the minimum offset into future early
    # $global_lastpass[$dir] -> [$lppos,$lptype]
    my @global_lastpass = (
	{ pos => 0, type => 0 },
	{ pos => 0, type => 0 }
    );

    # to make sure we don't leak due to cross-references
    weaken( my $wself = $self );

    # returns dump of parts for direction incl. bufs, only used for debugging
    my $_dump_part = sub {
	my $dir = shift;
	my $t = '';
	for my $i ( @_ ? @_ : (0..$#imp)) {
	    my $p = $parts[$dir][$i];
	    my $bufs = $p->{bufs};
	    $t.= sprintf("[%d] $imp[$i] fwa(%d) lp=%s(%d) gap(%d)\n",
		$i,$p->{fwapos},$p->{lptype},$p->{lppos},$p->{gap});
	    for my $buf (@$bufs) {
		$t .= sprintf(" - %s(%s) Badj(%d) Padj(%d) Gadj(%d) %s'%s'\n",
		    $buf->{type},
		    length($buf->{data})
			? ($buf->{endpos}-length($buf->{data})+1)
			    ."..$buf->{endpos}"
			: $buf->{endpos},
		    $buf->{badjust},
		    $buf->{padjust},
		    $buf->{gpadjust},
		    $buf->{eof} ? '<eof> ' :'',
		    $buf->{data}
		);
	    }
	}
	return $t;
    };

    # the data function
    # called from sub data on new data and from $process when data are finished
    # in on part and should be transferred into the next part
    #  $pi   - index into parts
    #  $dir  - direction (e.g. target part is $parts[$dir][$pi])
    #  $data - the data
    #  $pos  - offset of $data relativ to input into current part $pi
    #  $type - if called from previous part we get the result type of the data,
    #    e.g. if they are result of replacement, pass....
    #    this needs to be propagated thru the parts and will be used in the
    #    final result type
    #  $eof  - are $data the last data in this direction?
    #  $gbadjust, $gpadjust - fields from buf which was done in previous part
    #    and got transferred into this part. Needed to accumulate adjustments
    #    over all parts.
    my $process;
    my $_dataf = sub {
	my ($pi,$dir,$data,$pos,$type,$eof,$gbadjust,$gpadjust) = @_;
	$pi = @imp+$pi if $pi<0;

	$DEBUG && debug("dataf[$dir][$pi] '$data'/".length($data)." "
	    .(defined $pos ? "pos=$pos":'<nooff>' )." "
	    .( $type||'' )
	    ." adj=$gbadjust/$gpadjust eof=$eof\n"
	    .$_dump_part->($dir,$pi)
	);
	my $p = $parts[$dir][$pi];
	my $bufs = $p->{bufs};
	my $endpos = $bufs->[-1]{endpos};

	# add data to buf:
	# if there is no gap and type of buf matches and no adjustments
	# are used we can add data to an existing buf, otherwise we need to
	# create a new one
	# data from buffers with adjustments can never be merged, because
	# adjustments are considered beeing at the end of the buf, not
	# somewhere in the middle
	if ( defined $pos and $endpos > $pos ) {
	    die "overlapping data ($pos,$endpos)"

	} elsif ( ! defined $pos or $endpos == $pos
	    and ( ! $bufs->[-1]{type} or ($type||0) == $bufs->[-1]{type} )
	    and ! $gbadjust and ! $bufs->[-1]{gbadjust} ) {
	    # append
	    $endpos += length($data);
	    $bufs->[-1]{data} .= $data;
	    $bufs->[-1]{endpos} = $endpos;
	    $bufs->[-1]{eof} = $eof;
	    $bufs->[-1]{type} ||= $type||0;

	} else {
	    # gap, different type or adjustments involved
	    $endpos = $pos + length($data);
	    push @$bufs, Net::IMP::Cascade::_Buf->new(
		data      => $data,
		endpos    => $endpos,
		type      => $type||0,
		eof       => $eof,
		badjust   => 0,
		gbadjust  => $gbadjust,
		# padjust of previous buf is accumulated badjust of all
		# previous bufs together
		padjust   => $bufs->[-1]{padjust},
		gpadjust  => $gpadjust,
	    );
	}

	# if a new buffer was created we can now process the buffers
	$process->($pi,$dir);

    };

    # This is the central part. It processes buffers for $dir in part $pi.
    # It gets called from $_dataf or $_imp_cb whenever:
    # - new data arrived thru $_dataf from outside or previous part
    #   -> send to analyzer if necessary
    # - xor lppos increased due to IMP_(PRE)PASS callback from analyzer
    #   -> check if buffered data can be forwarded to next part
    # - xor replacements got added due to callback from analyzer, only in this
    #   case @fwd will be given and contains buffers, which should be
    #   propagated to next part
    #   -> forward replaced buffers
    $process = sub {
	my ($pi,$dir,@fwd) = @_;

	my $p    = $parts[$dir][$pi];
	my $bufs = $p->{bufs};

	# @fwd contains buffers to forward into next part
	# this is only already set if called from callback on replacement,
	# otherwise we will try to fill it based on bufs in current part

	if ( ! @fwd ) {
	    # new data added or lppos changed
	    # check if we have data in bufs which might be added to @fwd

	    my $endpos = $bufs->[-1]{endpos};
	    die "endpos mismatch" if $endpos < $p->{fwapos};

	    #debug( "bufs[$dir][$pi] fwapos=$p->{fwapos}, endpos=$endpos,".
	    #   " lppos=$p->{lppos} -- " .Dumper($bufs));

	    # up to offset=lppos we can forward w/o sending it to the analyzer
	    # (on IMP_PASS) or send it to the analyzer after forwarding it
	    # (IMP_PREPASS)
	    while ( my $buf = shift(@$bufs) ) {
		my $keep = $buf->{endpos} - $p->{lppos};
		if ( $keep <=0 ) {
		    $DEBUG && debug("fwd complete buf lppos=%d endpos=%d",
			$p->{lppos}, $buf->{endpos});
		    # we don't need to keep anything in the buf, e.g. fwd
		    # complete buf
		    # we might need to adjust the types, e.g. if lptype is
		    # IMP_PASS but buf.type is IMP_PREPASS this will result in
		    # IMP_PREPASS. The types are sorted in Net::IMP by
		    # importance so we can just use the largest
		    $buf->{type} = $p->{lptype} if $p->{lptype}>$buf->{type};

		} elsif ( $keep < length($buf->{data}) ) {
		    # we can forward parts of buf only
		    # split $buf, $keep bytes will be kept in $bufs
		    $DEBUG && debug("fwd part(buf) lppos=%d endpos=%d keep=%d",
			$p->{lppos}, $buf->{endpos}, $keep);
		    my $data = substr($buf->{data},-$keep,$keep,'');

		    # put buf with rest of data back into @$bufs
		    # adjustments will stay in the rest, because they are
		    # considered beeing at the end of the buf
		    unshift @$bufs, Net::IMP::Cascade::_Buf->new(
			data     => $data,
			endpos   => $buf->{endpos},
			badjust  => $buf->{badjust},
			gbadjust => $buf->{gbadjust},
			padjust  => $buf->{padjust},
			gpadjust => $buf->{gpadjust},
			eof      => $buf->{eof},
			type     => $buf->{type},
		    );

		    # adjust endpos of buf we forward
		    $buf->{endpos} -= $keep;
		    # adjust type: the more important wins
		    $buf->{type} = $p->{lptype} if $p->{lptype}>$buf->{type};

		    # adjustments and eof will stay with rest of data in @$bufs
		    # padjust and gpadjust needs to be fixed to not contain any
		    # adjustments which stay in the rest
		    $buf->{padjust}  -= $buf->{badjust};
		    $buf->{gpadjust} -= $buf->{gbadjust};
		    $buf->{badjust}  = 0;
		    $buf->{gbadjust} = 0;
		    $buf->{eof}      = 0;

		} else {
		    # there is nothing we can forward, but buf back into @$bufs
		    # and stop processing @$bufs
		    unshift @$bufs,$buf;
		    last;
		}


		# we have some $buf to forward because lppos allowed us so
		# if lptype is IMP_PREPASS we need to send it to analyzer too,
		# otherwise (IMP_PASS) we can skip the analyzer
		# update part.fwapos and part.gap
		if ( $buf->{endpos} > $p->{fwapos} ) {
		    if ( $p->{lptype} == IMP_PREPASS ) {
			# pass immediately, but also send to analyzer
			my $data = $buf->{data};
			my $keep = $buf->{endpos}-$p->{fwapos};
			if ( $keep >= length($data)) {
			    # forward all in buf
			} else {
			    # we have already send parts of buf to the analyzer
			    # forward only the rest
			    substr($data,-$keep,$keep,'');
			}
			# call analyzer for current part
			# if there was a gap before we need to send the current
			# offset
			$imp[$pi]->data($dir,$data,
			    $p->{gap} ? ($buf->{endpos}):());
		    } else {
			# pass w/o analyzer
			# this causes a gap in the stream to the analyzer
			$p->{gap} = 1;
		    }

		    # update part.fwapos with end of the forwarded buf
		    $p->{fwapos} = $buf->{endpos};
		}

		# propagate eof to analyzer
		# for lptype of IMP_PASS this needs to be done only if lppos !=
		# IMP_MAXOFFSET, otherwise the analyzer was not interested in
		# the end of data at all
		if ( $buf->{eof} ) {
		    $imp[$pi]->data($dir,'', $p->{gap} ? ($p->{fwapos}):())
			unless $p->{lptype} == IMP_PASS
			and $p->{lppos} == IMP_MAXOFFSET;
		}

		# now add to @fwd so it gets transferred to next part
		push @fwd,$buf;
		$DEBUG && debug("process[$dir][$pi] fwd %d bytes with %s,".
		    "badjust=%d",
		    length($buf->{data}),$buf->{type},$buf->{badjust});
	    }

	    if ( ! @fwd and @$bufs == 1
		and $bufs->[-1]{data} eq ''
		and $bufs->[-1]{eof} ) {
		# This is the special case, where we did not forward anything
		# but have a single buf in the part which contains no data, but
		# only eof.
		# In this case add this buffer to @fwd so that the eof gets
		# transferred to the next part
		push @fwd, shift(@$bufs)
	    }

	    # if no more bufs are in the part add an empty one so that new data
	    # can get added to it. Does not make much sense if we have eof but
	    # makes code easier
	    if ( ! @$bufs ) {
		push @$bufs, Net::IMP::Cascade::_Buf->new(
		    endpos   => $fwd[-1]{endpos},
		    # cummulated adjustments needs to be copied from the last
		    # buf we have forwarded
		    padjust  => $fwd[-1]{padjust},
		    gpadjust => $fwd[-1]{gpadjust},
		)
	    }
	}

	#debug("$pi ".Dumper([$bufs,'------',\@fwd]));

	# transfer data to next part or propagate to caller
	for my $fw (@fwd) {

	    # skip fw with no useful information, e.g.
	    # no data, no eof or no adjustments (adjustments needs to be
	    # propagated even if we have no data, e.g. it might be that all
	    # data in the chunk got replaced with '')
	    if ( $fw->{data} ne ''   # we have data to transfer
		or $fw->{eof}        # or eof needs to be propagated
		or $fw->{badjust}    # or adjustment must be propagated
	    ) {
		# fine, we have useful information
	    } else {
		$DEBUG && debug("ignoring ".Dumper($fw));
		next;
	    }

	    # check if $pi is the last part in the cascade
	    # for dir 0 this will be $pi = $#imp, while for the opposite dir
	    # this will be 0
	    if ( $pi == ($dir ? 0:$#imp) ) {
		# propagate result up

		if ( ! $fw->{type} ) {
		    # Type 0 should only be in a buffer, which got not analyzed
		    # or did not got passed because of IMP_(PRE)PASS.
		    # In this step in processing we should not have such
		    # type anymore.
		    die "untyped buffer at end of cascade";
		}

		# determine offset for propagation:
		# fw.endpos is the position relativ to input of the last part.
		# For propagating to the upper layer we need the matching
		# position relativ to the the original input.
		# We get this by applying all previously added adjustments
		# back, but ignore adjustments from this part (adjustments are
		# relevant to next part, but here we propagate up instead of
		# transfering to next part).
		my $eob                 # adjusted end of buffer is:
		    = $fw->{endpos}     # endpos relativ to this part
		    - $fw->{gpadjust}   # minus all adjustments so far
		    + $fw->{padjust};   # but ignoring adjustments in this part
		#debug( "up $fw->{type} ".
		#   "eob($eob)=$fw->{endpos}-$fw->{gpadjust}".
		#   "+$fw->{padjust}\n".$_dump_part->($dir));

		$DEBUG && debug("process[$dir][$pi] -> cb($fw->{type},$dir,".
		    "$eob=$fw->{endpos}-adjust");

		if ( $eob < $global_lastpass[$dir]{pos} ) {
		    # we already issued an IMP_(PRE)PASS for this offset
		    # no need to propagate
		} elsif ( $fw->{type} ~~ [ IMP_PASS, IMP_PREPASS ]) {
		    # propagate IMP_(PRE)PASS
		    $wself->run_callback([$fw->{type},$dir,$eob]);
		} elsif ( $fw->{type} == IMP_REPLACE ) {
		    # propagate IMP_REPLACE
		    $wself->run_callback([$fw->{type},$dir,$eob,$fw->{data}]);
		} else {
		    # should not happen if this code is correct
		    die "cannot handle type $fw->{type}"
		}

	    } else {
		# we are not at the last part of the cascade
		# transfer data into next part of cascade

		# to determine the start position in the input stream for the
		# next part we need adjust the end position in the buf by any
		# adjustments so far in this part, then remove the length of
		# the data
		my $start =                # start position is:
		    $fw->{endpos}          # end position
		    + $fw->{padjust}       # skip all data we removed
		    - length($fw->{data}); # minus length of current data

		# call $_dataf with next part
		# index of next part depends on $dir, e.g. if we go up or down
		my $nextpi = $dir ? $pi-1:$pi+1;
		$DEBUG && debug("process[$dir][$pi] -> ".
		    "dataf(%d,pos=%d..",$nextpi,$start);
		$_dataf->(
		    $nextpi,
		    $dir,
		    $fw->{data},
		    $start,
		    $fw->{type},
		    $fw->{eof},
		    $fw->{gbadjust},
		    $fw->{gpadjust},
		);
	    }
	}

	# if we have data in this part which were not send to the analyzer,
	# send them now
	# this includes sending eof to the analyzer

	my $endpos = $bufs->[-1]{endpos};
	if ($endpos >= $p->{fwapos} ) {
	    $DEBUG && debug("process[$dir][$pi] -> endpos=$endpos ".
		"p.fwapos=$p->{fwapos}\n".$_dump_part->($dir));
	    for my $buf (@$bufs) {

		# $needa bytes need to be analyzed
		my $needa = $buf->{endpos} - $p->{fwapos};
		if ( $needa>0 ) {
		    # some real data to analyze

		    my $ld = length($buf->{data});
		    if ( $needa>$ld ) {
			# send everything, but we have a gap of size $needa-$ld
			$DEBUG && debug("process[$dir][$pi] ".
			    "-> data(%d,allbuf<%d>,%d)",
			    $dir,$ld,$buf->{endpos});
			$imp[$pi]->data($dir,$buf->{data},$buf->{endpos}-$ld);
		    } else {
			# the last $needa from buf needs to be analyzed (we
			# skip optimization when $needa == $ld)
			$DEBUG && debug("process[$dir][$pi] ".
			    "-> data(%d,buf<%d,%d>,%s)",
			    $dir,
			    $needa-$ld, $buf->{endpos},
			    $p->{gap} ? $buf->{endpos}-$ld :''
			);
			$imp[$pi]->data(
			    $dir,
			    substr($buf->{data},-$needa,$needa),
			    $p->{gap} ? ($buf->{endpos}-$ld):(),
			);
		    }
		    $p->{fwapos} = $buf->{endpos};
		    $p->{gap} = 0;
		}
	    }

	    # If the last buf contains eof, we need to send this to the
	    # analyzer too, except if we got a free ride with IMP_PASS of
	    # IMP_MAXOFFSET.
	    if ( $bufs->[-1]{eof} ) {
		$imp[$pi]->data($dir,'', $p->{gap} ? ($p->{fwapos}):())
		    unless $p->{lptype} == IMP_PASS
		    and $p->{lppos} == IMP_MAXOFFSET;
	    }
	}
    };

    # This is the callback for the analyzer, e.g. analyzer $imp[$pi] from part
    # $pi calls $_imp_cb->($pi,@results)
    my $_imp_cb = sub {
	my $pi = shift;

	# track if something changed for dir, so that we know if we need to
	# recompute global_lastpass
	my %dir_changed;

	while ( my $rv = shift(@_)) {
	    my $rtype = shift(@$rv);

	    if ( $rtype ~~ [ IMP_DENY,IMP_DROP,IMP_ACCTFIELD ]) {
		# these gets propagated directly up w/o changes
		$DEBUG && debug("impcb[*][$pi] $rtype @$rv");
		$wself->run_callback([$rtype,@$rv]);

	    } elsif ( $rtype == IMP_LOG ) {
		# these gets also propagated directly up
		$DEBUG && debug("impcb[*][$pi] $rtype @$rv");

		# but we need to adjust the offset before so that it reflects
		# the offset in the original input stream
		my ($dir,$offset,$len,$level,$msg) = @$rv;
		my $buf = $parts[$dir][$pi]{bufs}[-1];
		$offset +=                    # adjust by
		    $buf->{gpadjust}          # all adjustments so far
		    - $buf->{padjust};        # but not from this part
		$wself->run_callback([$rtype,$dir,$offset,$len,$level,$msg]);

	    } elsif ( $rtype ~~ [ IMP_PASS,IMP_PREPASS ]) {
		my ($dir,$offset) = @$rv;
		#debug("impcb[$dir][$pi] $rtype off=$offset\n"
		#    .$_dump_part->($dir));

		my $p = $parts[$dir][$pi];
		my $startpos = $p->{bufs}[0]{endpos}
		    - length($p->{bufs}[0]{data});

		if ( $offset <= $startpos ) {
		    # we got an IMP_(PRE)PASS for data we already processed ->
		    # ignore
		    $DEBUG && debug("impcb[$dir][$pi] $rtype ignoring, ".
			"offset($offset)<pos($startpos)");

		} elsif ( $p->{lppos} and $offset < $p->{lppos} ) {
		    # we got an IMP_(PRE)PASS with a higher offset before ->
		    # ignore the new offset
		    $DEBUG && debug("impcb[$dir] $rtype ignoring, ".
			"offset($offset)<lppos($p->{lppos})");

		} else {
		    # set lppos and lptype from result and call process, to
		    # see, if we could forward some more data
		    $DEBUG && debug("impcb[$dir][$pi] $rtype off=$offset, ".
			"lppos: $p->{lppos} -> $offset");

		    $p->{lppos}  = $offset;
		    $p->{lptype} = $rtype;
		    $dir_changed{$dir}++;

		    $process->($pi,$dir);
		}

	    } elsif ( $rtype == IMP_REPLACE ) {
		my ($dir,$offset,$newdata) = @$rv;
		$DEBUG && debug("impcb[%d][%d] %s off=%d '%s'\n%s",
		    $dir,$pi,$rtype,$offset,$newdata,$_dump_part->($dir));
		my $p = $parts[$dir][$pi];
		my $startpos = $p->{bufs}[0]{endpos}
		    - length($p->{bufs}[0]{data});

		if ( $offset <= $startpos ) {
		    # We got a replacement for data, we already handled.
		    # This should never happen (but can, if the analyzer is
		    # bogus).
		    die "cannot replace already processed data";

		} elsif ( $p->{lppos} and $offset < $p->{lppos} ) {
		    # We got a replacement for data which earlier received an
		    # IMP_(PRE)PASS.
		    # This should never happen (but can, if the analyzer is
		    # bogus).
		    die "cannot replace \@$offset because of ".
			"$p->{lptype} \@$p->{lppos}";

		} else {
		    # The replacement consists of two pieces:
		    # - remove all data which should be replaced from bufs
		    # - call process with the data which should be used instead

		    # first remove everything in bufs up to offset with newdata

		    # badjust is the adjustment done in the buffer, e.g. how
		    # much bytes got added (or removed if badjust<0)
		    my $badjust = length($newdata) - ($offset - $startpos);
		    $DEBUG && debug("impcb[%d][%d] %s %d '%s' badjust=%d ".
			$dir,$pi,$rtype,$offset,$newdata,$badjust);

		    # gbadjust is the sum of all existing gbadjust from the
		    # buffers we remove
		    my $gbadjust = 0;

		    my $bufs = $p->{bufs};
		    while (1) {
			my $buf = $bufs->[0];
			if ( $buf->{endpos} <= $offset ) {
			    $DEBUG && debug("remove whole buffer (%s/%d)",
				$buf->{type},$buf->{endpos});

			    # remove whole buffer
			    shift(@$bufs);

			    # add any gbadjust we would remove to the new val
			    # we don't need to do the same with badjust because
			    # badjust is 0 for all unprocessed buffers in a
			    # part
			    $gbadjust += $buf->{gbadjust};

			    # add empty buf and exit loop in case all bufs are
			    # eaten
			    if ( !@$bufs ) {
				push @$bufs, Net::IMP::Cascade::_Buf->new(
				    endpos   => $offset,
				    padjust  => $buf->{padjust},
				    gpadjust => $buf->{gpadjust},
				);
				last;
			    }

			} elsif ( $buf->{endpos} - $offset
			    < length($buf->{data})) {
			    $DEBUG && debug("remove part of buffer (%s/%d)",
				$buf->{type},$buf->{endpos});

			    # Remove only first part of buffer up to $offset.
			    # No need to add to gbadjust because adjustments
			    # are considered at the end of the buffer and we
			    # keep the end.

			    # keep last ($buf->{endpos}- $offset) bytes in buf
			    $buf->{data} = substr($buf->{data},
				$offset-$buf->{endpos});
			    last;

			} else {
			    # nothing to remove
			    last;
			}
		    }

		    if ( $badjust ) {
			$gbadjust += $badjust;

			# Each byte can only be in one buffer, because
			# processed data will be immediately removed from the
			# current part and forwarded to the next part.
			# We need to propagate the adjustment to all data
			# which were not processed yet, e.g. data in @$bufs, in
			# previous parts and future data (this is done by using
			# gpadjust in  _dataf).
			for (@$bufs) {
			    $_->{padjust}  += $badjust;
			    $_->{gpadjust} += $badjust;
			}
			for my $i ( $dir ? ( $pi+1..$#imp ) : ( 0..$pi-1 )) {
			    for (@{$parts[$dir][$i]{bufs}}) {
				$_->{gpadjust} += $badjust;
			    }
			}
		    }

		    # process the new data, forward the replacements
		    $process->($pi,$dir, Net::IMP::Cascade::_Buf->new(
			data      => $newdata,
			endpos    => $offset,
			type      => IMP_REPLACE,
			badjust   => $badjust,
			gbadjust  => $gbadjust,
			padjust   => $bufs->[0]{padjust},
			gpadjust  => $bufs->[0]{gpadjust},
		    ));
		    $dir_changed{$dir}++;
		}

	    } else {
		die "unsupported type $rtype";
	    }
	}

	# if something changed, check if we could update global_lastpass
	for my $dir (keys %dir_changed) {

	    # We traverse all parts for $dir and check the amount of data we
	    # could forward in each part (e.g. check lppos vs. endpos of last
	    # buf in part). The minimum of all these values (lpdiff) is the
	    # number of bytes we could (pre)pass over all parts.
	    # Additionally we need to find the lptype with the most importance
	    # which should be used for this data.

	    my $lpdiff;
	    my $lptype = 0;
	    my $px = $parts[$dir];
	    for my $p (@$px) {
		my $over = $p->{lppos} - $p->{bufs}[-1]{endpos};
		if ( $over <= 0 ) {
		    # nothing can be forwarded
		    $lpdiff = 0;
		    last
		} elsif ( ! $lpdiff || $lpdiff>$over ) {
		    # lpdiff can be forwarded with type lptype
		    $lpdiff =  ($p->{lppos} == IMP_MAXOFFSET)
			? IMP_MAXOFFSET : $over;
		    $lptype = $p->{lptype} if $p->{lptype} > $lptype;
		}
	    }
	    if ( $lptype and $lpdiff > 0 ) {
		my $pos = ($lpdiff == IMP_MAXOFFSET)
		    ? IMP_MAXOFFSET
		    : $px->[-1]{bufs}[-1]{endpos} + $lpdiff;
		if ( $pos > $global_lastpass[$dir]{pos} ) {
		    # we got a higher value for global_lastpass
		    # update and propagate it up
		    $global_lastpass[$dir] = {
			pos  => $pos,
			type => $lptype
		    };
		    $wself->run_callback([$lptype,$dir,$pos]);
		}
	    }
	}
    };

    # While we are in $dataf function we will only spool callbacks and process
    # them at the end. Otherwise $dataf might cause call of callback which then
    # causes call of dataf etc - which makes debugging a nightmare.

    my $collect_callbacks;
    my $dataf = sub {
	$collect_callbacks ||= [];
	$_dataf->(@_);
	while ( my $cb = shift(@$collect_callbacks)) {
	    $_imp_cb->(@$cb);
	}
	$collect_callbacks = undef
    };

    # wrapper which spools callbacks if within dataf
    my $imp_cb = sub {
	if ( $collect_callbacks ) {
	    # only spool and execute later
	    push @$collect_callbacks, [ @_ ];
	    return;
	}
	return $_imp_cb->(@_)
    };

    # setup callbacks
    $imp[$_]->set_callback( $imp_cb,$_ ) for (0..$#imp);

    # make some closures available within methods
    $self->{dataf} = $dataf;
    $self->{closef} = sub {
	$dataf = $process = $imp_cb = undef;
	@parts = ();
    };
    return $self;
}

sub data {
    my ($self,$dir,$data,$offset) = @_;
    $self->{dataf}(
	$dir ? -1:0, # input part
	$dir,
	$data,
	$offset,     # start of $data in input stream
	0,           # type
	$data eq '', # eof
	0,           # gbadjust
	0,           # gpadjust
    );
}

sub DESTROY {
    shift->{closef}();
}

# This package just wraps each buffer in parts[dir][pi]{bufs}.
# The fields got described at the beginning of new_analyzer.

package Net::IMP::Cascade::_Buf;
use fields qw(data endpos type badjust padjust gpadjust gbadjust eof);
sub new {
    my ($class,%args) = @_;
    my $self = fields::new($class);
    %$self = %args;
    $self->{data} //= '';
    $self->{$_} //= 0 for
	(qw(endpos type badjust padjust gpadjust gbadjust eof));
    return $self;
}

1;

__END__

=head1 NAME

Net::IMP::Cascade - manages cascade of IMP filters

=head1 SYNOPSIS

    use Net::IMP::Cascade;
    use Net::IMP::Pattern;
    use Net::IMP::SessionLog;
    ...
    my $imp = Net::IMP::Cascade->new_factory( parts => [
	Net::IMP::Pattern->new_factory..,
	Net::IMP::SessionLog->new_factory..,
    ]);

=head1 DESCRIPTION

C<Net::IMP::Cascade> puts multiple IMP analyzers into a cascade.
Data get analyzed starting with part#0, then part#1... etc for direction 0
(client to server), while for direction 1 (server to client) the data get
analyzed the opposite way, ending in part#0.

The only argument special to C<new_factory> is C<parts>, which is an array
reference of L<Net::IMP> factory objects.
When C<new_analyzer> gets called on the L<Net::IMP::Cascade>> factory,
C<new_analyzer> will be called on the factory objects of the parts too, keeping
all arguments, except C<parts>.

=head1 TODO

Currently IMP_TOSENDER is not supported

=head1 BUGS

Don't know of any, but the feature and thus the code is way more complex than I
originally hoped :(

=head1 AUTHOR

Steffen Ullrich <sullr@cpan.org>

=head1 COPYRIGHT

Copyright by Steffen Ullrich.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.
