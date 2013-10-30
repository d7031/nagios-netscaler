#!/usr/bin/perl -w
#
# =========================== SUMMARY =====================================
# File name: check_netscaler_certificates.pl
# Author : Tom Geissler	<Tom.Geissler@perdata.de>
#			<Tom@d7031.de>
# Date : 21.02.2012
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
# This plugin for icinga/nagios checks the lifetime of SSL Certificates
# on a netscaler.
#
# status information:
# OK = All Certificates are ready to use
# Warning = One or more Certificates expire soon (default 30 days)
# Critical = One or more Certificates expire VERY soon (default 10 days)
#
# This script is tested with Netscaler 9.3
# see also http://support.citrix.com/article/CTX128676
#
# A version reporting Certificate nameswill follow.
#
# This script require Net::SNMP
#
# ========================================================================

use lib "/usr/lib/nagios/plugins";
use utils qw($TIMEOUT %ERRORS &print_revision &support);
use Getopt::Long;
use Net::SNMP;

use vars qw($script_name $script_version $o_host $o_community $o_port $o_help $o_version $o_timeout $o_debug $o_warning $o_critical);

use strict;

#========================================================================= 

$script_name = "check_netscaler_certificates.pl";
$script_version = "0.1";

$o_host = undef;
$o_community = "public";
$o_port = 161;
$o_help = undef;
$o_version = undef;
$o_timeout = 10;
$o_warning = 30;
$o_critical = 10;

my $return_string = "";
my $state = "UNKNOWN";
my $exitstate = 3;
my $daysleft;

#============================= get options ===============================

check_options();

#============================= SNMP ======================================

my $oid_daysleft= "1.3.6.1.4.1.5951.4.1.1.56.1.1.5";

#============================= main ======================================

# Opening SNMP Session
my $session = &open_session();
if (!defined($session)) {
	print "ERROR opening session: $return_string\n";
	exit $ERRORS{"UNKNOWN"};
}

if(defined($o_host)) {
	my $daysleft = &get_cert_daysleft($session);
	if($daysleft > $o_warning) {
                $state= "OK";
		$exitstate = 0;
               	$return_string = $state.", all Certificates have a good lifetime min: ".$daysleft." days";
        }
        else {
                if (($daysleft > $o_critical) && ($daysleft <= $o_warning)) {
                        $state = "WARNING";
			$exitstate = 1;
                	$return_string = $state.", one or more Certificates expire soon in: ".$daysleft." days";
                } else {
                        $state = "CRITICAL";
                	$return_string = $state.", one or more Certificates expire VERY soon in: ".$daysleft." days";
			$exitstate = 2;
                }
        }

	# Closing SNMP Session
	&close_session($session);

	if (defined($state) && defined($return_string)) {
		print "$return_string\n"; 
	exit ($exitstate);
	}
}

exit ($exitstate);


#============================ functions ==================================

sub open_session {
	my ($session, $str) = Net::SNMP->session(
		-hostname	=> $o_host,
		-community	=> $o_community,
		-port		=> $o_port,
		-timeout	=> $o_timeout
	);

	return $session;
}


sub close_session {
	my ($session) = @_;

	if(defined($session)){
		$session->close;
	}
}

sub get_cert_daysleft {
 	my ($session) = @_;
	my $certoid;
	my @sortcert;
 
	my $result = $session->get_table(
			-baseoid => $oid_daysleft
         );
	my %certtable = %{$result};
	@sortcert= sort {
		$certtable{$a} <=> $certtable{$b}
		} keys %certtable;

	foreach $certoid(@sortcert){
		if($certtable{$certoid} > $o_warning) {
			$daysleft = $certtable{$certoid};
			last;
        	}
	        else {
        	        if (($certtable{$certoid} <= $o_warning) && ($certtable{$certoid} > $o_critical)) {
				$daysleft = $certtable{$certoid};
				last;
	                } else {
				$daysleft = $certtable{$certoid};
				last;
                	}
	        }
	}
	return $daysleft;
}

sub usage {
	print "Usage: $0 -H <host> -C <community> [-p <port>] [-t <timeout>] [-w <warning>] [-c <critical>] [-V] [-h]\n";
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
	-C, --community=COMMUNITY NAME
		community name for the host's SNMP agent (implies v1 protocol)
	-w, --warning
		integer threshold for warning level on days to expire, default 30
	-c, --critical
		 integer threshold for critical level on days to expire, default 10
	-P, --port=PORT
		SNMP port (Default 161)
	-t, --timeout=INTEGER
		timeout for SNMP
	-V, --version
		version number
HELP
}



sub check_options {
	Getopt::Long::Configure("bundling");
	GetOptions(
		'h'	=> \$o_help,		'help'		=> \$o_help,
		'H:s'	=> \$o_host,		'hostname:s'	=> \$o_host,
		'P:i'	=> \$o_port,		'port:i'	=> \$o_port,
		'C:s'	=> \$o_community,	'community:s'	=> \$o_community,
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

	if(!defined($o_host) || !defined($o_community)) {
		usage();
		exit $ERRORS{'UNKNOWN'};
	}

}
