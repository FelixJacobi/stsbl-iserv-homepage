#!/usr/bin/perl -CSDAL
use strict;
use warnings;
use IServ::Conf;
use IServ::DB;
use List::MoreUtils qw(uniq);
use Sys::Hostname;

my $servername = $conf->{Servername} // hostname;

print "\n";
print "# list of user and group homepages to include\n";

# collect domain names to include
my @x = split /\./, hostname;
my $hostname_s = shift @x;
my $domain = join '.', @x;
# admins is covered by default
my @label = IServ::DB::SelectCol "SELECT act FROM users_priv WHERE privilege = ? AND act != ?".
  "UNION SELECT act FROM group_flag_assign WHERE flag = ? AND act != ?", "hp_ssl_cert", "admins", "hp_ssl_cert", "admins";
my @domain = ($domain, @{$conf->{AliasDomains} // []});
my @fqdn = uniq(map { my $d = $_; map { ($_ ? $_ . '.' : '') . $d } @label }
    @domain);
print map { $_, "\n" } grep !/^\Q$servername\E$/, @fqdn;

print "\n";
