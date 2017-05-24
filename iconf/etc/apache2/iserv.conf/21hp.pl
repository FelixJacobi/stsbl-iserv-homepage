#!/usr/bin/perl -CSDAL

use warnings;
use strict;
use IServ::Conf;
use IServ::DB;

my @users = IServ::DB::SelectCol("SELECT act FROM users_priv WHERE privilege = 'hp_from_inet'");
my @groups = IServ::DB::SelectCol("SELECT act FROM groups WHERE deleted IS NULL AND act IN (SELECT act FROM groups_flag WHERE flag = 'hp_from_inet')");

my $UserHomepages = $conf->{UserHomepages};
my $UserHomepagesLAN = $conf->{UserHomepagesLAN};
my $HomepageExternalAuthAccess = $conf->{HomepageExternalAuthAccess};
my $Servername = $conf->{Servername};
my @LAN = @{$conf->{LAN}};

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

sub external_auth() {
  print "  # Add IServ sessauth\n";
  print "  AddExternalAuth iserv /usr/bin/iservsessauth\n";
  print "  SetExternalAuthMethod iserv pipe\n";
  print "\n";
  print "  # Allow external access to user and group homepages with HTTP Basic Login.\n";
  print "  <Directory /home/*/Homepage/>\n";
  print "    Order allow,deny\n";
  print "    Allow from all\n";
  print "    AuthType Basic\n";
  print "    AuthName \"Please sign-in with your IServ account to access this homepage\"\n";
  print "    AuthBasicProvider external\n";
  print "    AuthExternal iserv\n";
  print "    # Require LAN ip or login\n";
  print "    <RequireAny>\n";
  print "      Require valid-user\n";
  print "      # Allow access to always allowed user homepages\n";
  print "      Require expr %{HTTP_HOST} =~ /(".join("|", @users).").$Servername/\n";
  print "      # Allow access from LAN\n";
  foreach my $iprange (@LAN)
  {
    print "      Require ip $iprange\n";
  }
  print "    </RequireAny>\n";
  print "  </Directory>\n";
  print "\n";
  print "  <Directory /group/*/Homepage/>\n";
  print "    Order allow,deny\n";
  print "    Allow from all\n";
  print "    AuthType Basic\n";
  print "    AuthName \"Please sign-in with your IServ account to access this homepage\"\n";
  print "    AuthBasicProvider external\n";
  print "    AuthExternal iserv\n";
  print "    # Require LAN ip or login\n";
  print "    <RequireAny>\n";
  print "      Require valid-user\n";
  print "      # Allow access to always allowed group homepages\n";
  print "      Require expr %{HTTP_HOST} =~ /(".join("|", @groups).").$Servername/\n";
  print "      # Always allow www homepage\n";
  print "      Require expr %{HTTP_HOST} =~ /www.$Servername/\n";
  print "      Require expr %{HTTP_HOST} =~ /$Servername/\n";
  print "      Require expr %{HTTP_HOST} =~ /iserv.$Servername/\n";
  print "      # Allow access from LAN\n";
  foreach my $iprange (@LAN)
  {
    print "      Require ip $iprange\n";
  }
  print "    </RequireAny>\n";
  print "  </Directory>\n";
  print "\n";
}

group_config() unless @groups < 1 or $UserHomepages == 0;
user_config() unless @users < 1 or $UserHomepages == 0;
external_auth() if $HomepageExternalAuthAccess and $UserHomepages
  and $UserHomepagesLAN;
