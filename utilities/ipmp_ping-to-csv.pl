#!/usr/bin/perl

use strict;
use warnings;

# This scripts parses the destination ip, fwd and rev path length and RTT from
# IPMP output into CSV files. Paths, timestamps and flow counters are
# serialized to fit into a single field.

# The input file was created using
# ipmp_ping -4 -R -c 1000 -w 100 -s 300 -t 1 -r -h -p 3 <dest_host_ip>
# on a linux router running OpenWRT.

# Specify the source IP as part of the incoming filename.
# Example: 10.20.1.9.hping.log
die "usage: ipmp_ping-to-csv.pl <infile: <ip>.ipmp_ping.log> <outfile>\n" unless @ARGV;

my $in = $ARGV[0];
my $out = $ARGV[1];
open(IN, "<$in") or die "Cannot open file $in: $!\n";
open(OUT, ">$out") or die "Cannot open file $out: $!\n";


# construct source IP from <infile> file name
my $src_ip = $ARGV[0];
$src_ip =~ s/\.ipmp_ping\.log//;
$src_ip =~ s/.*\///;


my $wholefile;
# let's hope the whole file fits into one string...
while (my $line = <IN>) {
	$wholefile .= $line;
}

# Put timestamps onto their own line
$wholefile =~ s/\s+(\w{3}\s+\d+\s+[0-9:]+\s+\d{4}\s+\d+\s+\w)/\n$1/g;

# Replace localhost with (mesh interface) IP from the command line parameter
$wholefile =~ s/127\.0\.0\.1/$src_ip/g;

# CSV header
print OUT "src_ip;dst_ip;fwd_path_hops;rev_path_hops;rtt;full_path;timestamps;flow_counter\n";

my ($dst_ip, $fwd_path_hops, $rev_path_hops, $rtt, $full_path, $timestamps, $flowcounter);
foreach my $line (split(/\n/, $wholefile)) {
	# print OUT "$line";

	if ($line =~ m/ipmp_ping ([\d\.]+)/) {
		# destination IP
		$dst_ip = "$1";
		next;
	}
	if ($line =~ m/^([\*\ ])\s+(\d+)\s+([\d\.]+)$/) {
		$full_path .= "$1$2 $3>";
		next;
	}
	if ($line =~ m/^(\w{3}\s+\d+\s+[0-9:]+\s+\d{4}\s+\d+)\s+(\w)$/) {
		$timestamps .= "$1>";
		$flowcounter .= hex($2) . ">";
		next;
	}
	if ($line =~
	m/forward path = ([\d]+) hops, reverse path = ([\d]+) hops/) {
		$fwd_path_hops = $1;
		$rev_path_hops = $2;
		next;
	}
	if ($line =~ m/rtt: ([\d\.]+)ms/) {
		$rtt = $1;
	}

	# Strip the last character (">")
	$full_path = substr($full_path, 0, -1);
	$timestamps = substr($timestamps, 0, -1);
	$flowcounter = substr($flowcounter, 0, -1);

	print OUT "$src_ip;$dst_ip;$fwd_path_hops;$rev_path_hops;$rtt;$full_path;$timestamps;$flowcounter\n";

	# Re-init
	$full_path = $timestamps = $flowcounter = "";
}

close IN;
close OUT;
