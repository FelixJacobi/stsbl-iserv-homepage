#!/usr/bin/perl -CSDAL

use warnings;
use strict;
use IServ::Conf;
use IServ::DB;

my @users = IServ::DB::SelectCol("SELECT act FROM users_priv WHERE privilege = 'hp_from_inet'");
my @groups = IServ::DB::SelectCol("SELECT act FROM groups WHERE deleted IS NULL AND act IN (SELECT act FROM groups_flag WHERE flag = 'hp_from_inet')");

my $UserHomepages = $conf->{UserHomepages};


sub group_config() {
  print "  # Group Homepages which are always allowed via hp_from_inet flag.\n";
  for (my $i = 0; $i < @groups; $i++) {
    # skip www group, it is always reachable
    next unless $groups[$i] ne "www";
    print "  <Directory /group/$groups[$i]/Homepage/>\n";
    print "    Allow from all\n";
    print "  </Directory>\n";
    print "\n";
  }
}

sub user_config() {
  print "  # User Homepages which are always allowed via hp_from_inet privilege.\n";
  for (my $i = 0; $i < @users; $i++) {
    print "  <Directory /home/$users[$i]/Homepage/>\n";
    print "    Allow from all\n";
    print "  </Directory>\n";
    print "\n";
  }
}

group_config() unless @groups < 1 or $UserHomepages == 0;
user_config() unless @users < 1 or $UserHomepages == 0;
