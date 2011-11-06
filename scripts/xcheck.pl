#!/usr/bin/env perl 

use strict;
use warnings;

# FILENAME: xcheck.pl
# CREATED: 05/11/11 22:49:53 by Kent Fredric (kentnl) <kentfredric@gmail.com>
# ABSTRACT: HURRP

use IO::Socket::INET;
use IO::Select;
use Time::HiRes qw( gettimeofday tv_interval);
require Net::DNS::Packet;
require Net::DNS::RR;
use Data::Dump qw( pp );
use RRD::Simple;
use Try::Tiny;

sub nameserver {
  my ( $id, $ip ) = @_;
  return $id => {
    label       => $id,
    server_name => 'ns' . $id . '.dnsmadeeasy.com',
    ip          => $ip,
    tcp_times   => 'ns_' . $id . '_tcp_rtime',
    udp_times   => 'ns_' . $id . '_udp_rtime',
    tcp_success => 'ns_' . $id . '_tcp_success',
    udp_success => 'ns_' . $id . '_udp_success',
  };
}

# This is here to avoid nameserver lookup at runtime.
my %nsmap = (
  nameserver( 0, '208.94.148.2', ),
  nameserver( 1, '208.80.124.2', ),
  nameserver( 2, '208.80.126.2', ),
  nameserver( 3, '208.80.125.2', ),
  nameserver( 4, '208.80.127.2', ),
  nameserver( 5, '208.94.148.13', ),
  nameserver( 6, '208.80.124.13', ),
  nameserver( 7, '208.80.126.13', ),
  nameserver( 8, '208.94.149.2', ),
);

my (@protos) = qw( tcp udp );

my (@errors);

*STDOUT->autoflush(1);

my $ns_times_graph = Grapher->new(
  root_dir          => '/tmp/rrd/times',
  image_basename    => 'ns_times',
  rrd_file_basename => 'ns_times',
  fields            => [ map { $_->{tcp_times}, $_->{udp_times} } values %nsmap ],
);

$ns_times_graph->create();

my $ns_success_graph = Grapher->new(
  root_dir          => '/tmp/rrd/success',
  image_basename    => 'ns_success',
  rrd_file_basename => 'ns_success',
  fields            => [ map { $_->{tcp_success}, $_->{udp_success} } values %nsmap ],
);

$ns_success_graph->create();

while (1) {
  print "# Updating Graphs\n";
  $ns_times_graph->render();
  $ns_success_graph->render();

  for my $pass ( 1 .. 5 ) {

    for my $proto (qw( tcp udp )) {

      for my $nameserver ( sort keys %nsmap ) {

        my $nss_key = $nsmap{$nameserver}->{ $proto . '_success' };
        my $nst_key = $nsmap{$nameserver}->{ $proto . '_times' };

        my $ip = $nsmap{$nameserver}->{ip};

        $ns_success_graph->set_value( $nss_key, 0 );

        my $result;
        my (@before) = gettimeofday;
        my $delay;
        for my $answer ( answers_for( $proto, $ip ) ) {
          if ( not $result ) {
            $ns_success_graph->set_value( $nss_key, 1 );
            $delay = tv_interval( \@before, [ gettimeofday ]);
            $ns_times_graph->set_value( $nst_key, $delay );
          }
          $result++;
          print "# $nameserver $proto : $result " . $answer->address . " " . $answer->ttl . " $delay\n";
        }
        if ( not $result ) {
          print "FAIL: $nameserver $proto\n";
        }
      }
    }

    $ns_times_graph->commit();
    $ns_success_graph->commit();
    print "# Sleeping 20s\n";
    sleep 20;

  }
}

BEGIN {

  package Grapher;
  use Moose;

  has '_timestamp' => ( isa => 'Str', is => 'rw', clearer => 'clear_timestamp', predicate => 'has_timestamp' );
  has 'last_dataset' => ( isa => 'HashRef', is => 'rw', clearer => 'clear_dataset', lazy => 1, default => sub { {} } );
  has 'root_dir'       => ( isa => 'Str', is => 'rw', required => 1 );
  has 'image_basename' => ( isa => 'Str', is => 'rw', required => 1 );
  has 'graph_periods'  => (
    isa     => 'ArrayRef',
    is      => 'rw',
    default => sub {
      return [ 'hour', 'day', 'week' ];
    }
  );
  has 'fields' => (
    isa        => 'HashRef',
    is         => 'rw',
    lazy_build => 1,
    init_arg   => undef,
    traits     => [qw( Hash )],
    handles    => { has_field => 'exists', }
  );
  has '_fields' => ( isa => 'ArrayRef', is => 'rw', required => 1, init_arg => 'fields' );

  has 'rrd_file' => ( isa => 'Str', is => 'rw', lazy_build => 1 );
  has 'rrd_file_basename' => ( isa => 'Str', is => 'rw', lazy => 1, default => sub { 'data' } );

  has '_rrd' => ( isa => 'Object', is => 'rw', lazy_build => 1 );

  sub _build_fields {
    my $self = shift;
    return { map { $_, 'GAUGE' } @{ $self->_fields } };
  }

  sub create {
    my $self = shift;
    require Try::Tiny;
    return Try::Tiny::try {
      $self->_rrd->create( 'year', %{ $self->fields } );
    };
  }

  sub _build_rrd_file {
    my $self = shift;
    require Path::Class::Dir;
    return Path::Class::Dir->new( $self->root_dir )->file( $self->rrd_file_basename . '.rrd' )->absolute->stringify;
  }

  sub _build__rrd {
    my $self = shift;
    require RRD::Simple;
    return RRD::Simple->new( file => $self->rrd_file );
  }

  sub set_value {
    my ( $self, $key, $value ) = @_;
    if ( not $self->has_field($key) ) {
      die "Error: tried to set unwanted value $key";
    }
    if ( not $self->has_timestamp ) {
      $self->_timestamp( scalar time );
    }
    $self->last_dataset->{$key} = $value;
  }

  sub commit {
    my ($self) = shift;
    $self->_rrd->update( $self->_timestamp, %{ $self->last_dataset } );
    $self->clear_dataset;
    $self->clear_timestamp;
  }

  sub render {
    my $self = shift;
    my %rtn  = $self->_rrd->graph(
      destination    => $self->root_dir,
      basename       => $self->image_basename,
      periods        => $self->graph_periods,
      line_thickness => 1,
      extended_legend => 1,
      height => 600,
      width => 600,
    );
    return %rtn;
  }

  sub render_pp {
    my $self = shift;
    my (%rtn) = $self->render;
    require Data::Dump;
    my $x = Data::Dump::pp( \%rtn );
    $x =~ s/^/#/gm;
    return $x;
  }
}

sub gen_message {
  my ($proto) = shift;
  my $tail = join q[],
    map { chr( hex($_) ) } qw( 01 00 00 01 00 00 00 00 00 00 0a 64 75 63 6b 64 75 63 6b 67 6f 03 63 6f 6d 00 00 01 00 01 );

  my $randbytes = chr( int( rand() * 128 ) ) . chr( int( rand() * 128 ) ) . $tail;

  # my $package = Net::DNS::Packet->new( 'duckduckgo.com', 'A', 'IN' );
  # $package->data
  return $randbytes if $proto eq 'udp';
  return ( ( pack 'n', length $randbytes ) . $randbytes );
}

sub answers_for {
  my ( $proto, $ip ) = @_;

  my $config = { Blocking => 1, Type => SOCK_DGRAM, PeerPort => 53 };
  $config->{PeerAddr} = $ip;
  $config->{Proto}    = $proto;
  $config->{Type}     = SOCK_STREAM if $proto eq 'tcp';
  $config->{Timeout}  = 1;

  my $con;

  unless ( $con = IO::Socket::INET->new( %{$config} ) ) {
    push @errors, [ [ gettimeofday() ], $@, $!, $?, "$! $?" ];
    return;
  }
  $con->autoflush(1);
  my $message = gen_message($proto);
  $con->send($message);
  my $buf;
  
  # Timeout/Error

  return unless IO::Select->new( $con )->can_read( 1.0 );
  
  $con->recv( $buf, 4096 );
  if ( length $buf < 100 ) {
    push @errors, [ [ gettimeofday() ], $@, $!, $?, "$@ $! $?" ];
    return;
  }
  if ( $proto eq 'tcp' ) {
    substr( $buf, 0, 2, '' );
  }
  return Net::DNS::Packet->new( \$buf )->answer;
}

