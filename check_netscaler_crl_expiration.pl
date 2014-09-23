#!/usr/bin/perl -w
#
# =========================== SUMMARY =====================================
# File name: check_netscaler_crl_expiration.pl
# Author : Tom Geissler	<Tom.Geissler@bertelsmann.de>
#			<Tom@d7031.de>
# Date : 22.09.2014
# =========================== LICENSE =====================================
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
# ========================== ABOUT THIS PLUGIN ===========================
#
# This plugin for icinga/nagios checks the crl lifetime on a netscaler 
# using the command line interface (cli)
# 
# This plugin can also be used a an template for other cli-commands.
# 
# status information:
# OK = CRL  lifetime OK
# Warning = CRL lifetime expire soon (default 3 days)
# Critical = CRL lifetime expire VERY soon (default 1 days)
#
# This script is tested with Netscaler 9.3 and 10.1
#
# ========================================================================

use lib "/usr/lib/nagios/plugins";
use utils qw($TIMEOUT %ERRORS &print_revision &support);
use Getopt::Long;

use Net::OpenSSH;

use vars qw($script_name $script_version $o_host $o_loginname $o_password $o_port $o_ca_name $o_help $o_version $o_timeout $o_debug $o_warning $o_critical);

use strict;

#========================================================================= 

$script_name = "check_netscaler_crl_expiration.pl";
$script_version = "0.2";

$o_host = undef;
$o_loginname = undef;
$o_password = undef;
$o_port = 22;
$o_ca_name= undef;
$o_help = undef;
$o_version = undef;
$o_timeout = 10;
$o_warning = 3;
$o_critical = 1;

my $return_string = "";
my $state = "UNKNOWN";
my $exitstate = 3;
my $lastupdate ="DAILY	Last Update";
my $daystoexpire ="Days to expiration";
my $crltime;
my $daysleft;
my @updateresult;
my @expireresult;

#============================= get options ===============================

check_options();

#============================= main ======================================

my $ssh = Net::OpenSSH->new("$o_loginname:$o_password\@$o_host:$o_port");
	$ssh->error and
	die "Couldn't establish SSH connection: ". $ssh->error;

	my @crltime = $ssh->capture({timeout => $o_timeout},"show crl $o_ca_name\n");
		$ssh->error and
		die "remote crl command failed: " . $ssh->error;

	@updateresult = grep /$lastupdate/, @crltime;
	if (scalar($updateresult[0]) =~ /Successful/) {
		$lastupdate = substr $updateresult[0], -25,25;        
		#print "$lastupdate";
	}

	@expireresult = grep /$daystoexpire/, @crltime;
	if (scalar($expireresult[0]) =~ /Valid/) {
		$daysleft = substr $expireresult[0], -3,3;
		$daysleft =~ s/^\s+|\s+$//g;
		#print "$daysleft";
	}
	
	if($daysleft > $o_warning) {
                $state= "OK";
		$exitstate = 0;
               	$return_string = $state.", CRL lifetime: ".$daysleft." days, Last update: ".$lastupdate;
        }
        else {
                if (($daysleft > $o_critical) && ($daysleft <= $o_warning)) {
                        $state = "WARNING";
			$exitstate = 1;
                	$return_string = $state.", CRL expires SOON: ".$daysleft." days, Last update: ".$lastupdate;
                } else {
                        $state = "CRITICAL";
                	$return_string = $state.", CRL expires VERY SOON: ".$daysleft." days, Last update: ".$lastupdate;
			$exitstate = 2;
                }
        }

	if (defined($state) && defined($return_string)) {
		print "$return_string\n"; 
	exit ($exitstate);
	}

exit ($exitstate);



sub usage {
	print "Usage: $0 -H <host> -l <loginname> -pw <password> -ca <ca-name> [-p <ssh port>] [ -t <timeout>] [-w <warning>] [-c <critical>] [-V] [-h]\n";
}


sub version {
	print "$script_name v$script_version\n";
}


sub help {
	version();
	usage();

	print <<HELP;
	-h, --help
   		print this help message
	-H, --hostname=HOST
		name or IP address of host to check
	-l, --loginname=loginname
		loginname for the host
	-pw, --password=password
		password for the host
	-p, --port=port
		ssh port for the host
	-ca, --ca-name=ca-name
		name of ca
	-w, --warning
		integer threshold for warning level on days to expire, default 3
	-c, --critical
		 integer threshold for critical level on days to expire, default 1
	-t, --timeout=INTEGER
		timeout for SNMP
	-V, --version
		version number
HELP
}



sub check_options {
	Getopt::Long::Configure("no_ignore_case");
	GetOptions(
		'h'	=> \$o_help,		'help'		=> \$o_help,
		'H:s'	=> \$o_host,		'hostname:s'	=> \$o_host,
		'l:s'	=> \$o_loginname,	'loginname:s'	=> \$o_loginname,
		'pw:s'	=> \$o_password,	'password:s'	=> \$o_password,
		'p:i'	=> \$o_port,		'port:i'	=> \$o_port,
		'ca:s'	=> \$o_ca_name,		'ca-name:s'	=> \$o_ca_name,
		't:i'	=> \$o_timeout,		'timeout:i'	=> \$o_timeout,
		'V'	=> \$o_version,		'version'	=> \$o_version,
		'w:i'	=> \$o_warning,		'warning:i'	=> \$o_warning,
		'c:i'	=> \$o_critical,	'critical:i'	=> \$o_critical
	);

	if(defined($o_help)) {
		help(); 
		exit $ERRORS{'UNKNOWN'};
	}

	if(defined($o_version)) {
		version();
		exit $ERRORS{'UNKNOWN'};
	}

	if(!defined($o_host) || !defined($o_loginname) || !defined($o_password)|| !defined($o_ca_name)) {
		usage();
		exit $ERRORS{'UNKNOWN'};
	}

}

