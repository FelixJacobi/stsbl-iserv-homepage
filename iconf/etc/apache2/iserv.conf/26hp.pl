#!/usr/bin/perl -CSDAL

use warnings;
use strict;
use IServ::Conf;
use IServ::DB;
use List::MoreUtils qw(uniq);

my @users = IServ::DB::SelectCol("SELECT act FROM users_priv WHERE privilege = 'hp_from_inet'");
my @groups = IServ::DB::SelectCol("SELECT act FROM groups WHERE deleted IS NULL AND act IN (SELECT act FROM groups_flag WHERE flag = 'hp_from_inet')");

my $UserHomepages = $conf->{UserHomepages};
my $UserHomepagesLAN = $conf->{UserHomepagesLAN};
my $HomepageExternalAuthAccess = $conf->{HomepageExternalAuthAccess};
my $Servername = $conf->{Servername};
my @AliasDomains = @{$conf->{AliasDomains}};
my @LAN = @{$conf->{LAN}};

sub group_config() {
  print "  # Group Homepages which are always allowed via hp_from_inet flag.\n";
  for (my $i = 0; $i < @groups; $i++) {
    # skip www group, it is always reachable
    next unless $groups[$i] ne "www";
    print "  <Directory /group/$groups[$i]/Homepage/>\n";
    print "    Require all granted\n";
    print "  </Directory>\n";
    print "\n";
  }
}

sub user_config() {
  print "  # User Homepages which are always allowed via hp_from_inet privilege.\n";
  for (my $i = 0; $i < @users; $i++) {
    print "  <Directory /home/$users[$i]/Homepage/>\n";
    print "    Require all granted\n";
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
  print "    AuthType Basic\n";
  print "    AuthName \"Please sign-in with your IServ account to access this homepage\"\n";
  print "    AuthBasicProvider external\n";
  print "    AuthExternal iserv\n";
  print "    # Require LAN ip or login\n";
  print "    <RequireAny>\n";

  my @ssl_users = uniq(IServ::DB::SelectCol "SELECT act FROM users_priv WHERE privilege = ".
    "'hp_ssl_cert' AND act NOT IN (SELECT act FROM users WHERE deleted IS NULL AND act IN ".
    "(SELECT act FROM users_priv WHERE privilege = ".
    "'hp_from_inet'))");
  if (@ssl_users > 0)
  {
    print "      <RequireAll>\n";
    print "        # only allow group homepages in ssl cert\n";
    print "        Require expr %{HTTP_HOST} =~ /^(".join("|", @ssl_users).").$Servername\$/\n";
    for (@AliasDomains)
    {
      print "        Require expr %{HTTP_HOST} =~ /^(".join("|", @groups).").$_\$/\n";
    }
    print "        Require valid-user\n";
    print "      </RequireAll>\n";
  }

  if (@users > 0) 
  {
    print "      # Allow access to always allowed user homepages\n";
    print "      Require expr %{HTTP_HOST} =~ /^(".join("|", @users).").$Servername\$/\n";
    for (@AliasDomains)
    {
      print "      Require expr %{HTTP_HOST} =~ /^(".join("|", @users).").$_\$/\n";
    }
  }
  print "      # Allow access from LAN\n";
  foreach my $iprange (@LAN)
  {
    print "      Require ip $iprange\n";
  }
  print "    </RequireAny>\n";
  print "  </Directory>\n";
  print "\n";
  print "  <Directory /group/*/Homepage/>\n";
  print "    AuthType Basic\n";
  print "    AuthName \"Please sign-in with your IServ account to access this homepage\"\n";
  print "    AuthBasicProvider external\n";
  print "    AuthExternal iserv\n";
  print "    # Require LAN ip or login\n";
  print "    <RequireAny>\n";
  print "      <RequireAll>\n";
  
  print "        # only allow group homepages in ssl cert\n";
  my @ssl_groups = uniq(IServ::DB::SelectCol "SELECT 'admins' UNION SELECT act FROM group_flag_assign WHERE flag = ".
    "'hp_ssl_cert' AND act NOT IN (SELECT act FROM groups WHERE deleted IS NULL AND act IN ".
    "(SELECT act FROM groups_flag WHERE flag = ".
    "'hp_from_inet'))");

  print "        Require expr %{HTTP_HOST} =~ /^(".join("|", @ssl_groups).").$Servername\$/\n";
  for (@AliasDomains)
  {
    print "        Require expr %{HTTP_HOST} =~ /^(".join("|", @groups).").$_\$/\n";
  }
  print "        Require valid-user\n";
  print "      </RequireAll>\n";
  
  if (@groups > 0)
  {
    print "      # Allow access to always allowed group homepages\n";
    print "      Require expr %{HTTP_HOST} =~ /^(".join("|", @groups).").$Servername\$/\n";
    for (@AliasDomains)
    {
      print "      Require expr %{HTTP_HOST} =~ /^(".join("|", @groups).").$_\$/\n";
    }
  }
  print "      # Always allow www homepage\n";
  print "      Require expr %{HTTP_HOST} =~ /^www.$Servername\$/\n";
  print "      Require expr %{HTTP_HOST} =~ /^$Servername\$/\n";
  print "      Require expr %{HTTP_HOST} =~ /^iserv.$Servername\$/\n";
  for (@AliasDomains)
  {
    print "      Require expr %{HTTP_HOST} =~ /^www.$_\$/\n"; 
    print "      Require expr %{HTTP_HOST} =~ /^$_\$/\n";
    print "      Require expr %{HTTP_HOST} =~ /^iserv.$_\$/\n";
  }
  for (split /\n/, qx(netquery ip))
  {
    print "      Require expr %{HTTP_HOST} =~ /^$_\$/\n";
  }
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
