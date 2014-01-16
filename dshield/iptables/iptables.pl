#!/usr/bin/perl -s 
$VERSION='iptables_2013-05-17';
$PARSER='IPTABLES';

# DShield iptables parser
#
# iptables defaults to saving logs in /var/logs/messages, so set
# 'log=/var/log/messages' in dshield.cnf.
#
# The parser defaults to only processing lines that contain 'kernel:'
# If this isn't correct for you, then set the 'line_filter' variable in 
# dshield.cnf so it is a string that is contained in the log lines
# that the parser should process.
#
my $PARSER_VERSION = "2013-05-17";# DShield Client Framework
#
my $FRAMEWORK_VERSION = "2013-05-17";

# The idea of this framework is to establish a list of common
# features and command line paramaters accross all clients.
#
# developers:
#   - initial framework: Johannes B. Ullrich, 
#   - additional development by Ken McKinlay kmckinlay@home.com
#   - added IPv6 Support: Johannes B. Ullrich (May 2013)
#
# parameters
#   Defaults to looking in /etc/dshield.cnf for these parameters.  You can
#   also set them from the command line in the form of
#      -[variable]=[value]
#   e.g.,
#      -log=/var/log/firewall
#   would set the $log variable to use '/var/log/firewall'
#
#   !!!! Any variables passed on the command line (except for '-config') can 
#   *not* exist in the configuration file.  (Comment them out first.) !!!!!
#
#   -config  - Name of config file (default /etc/dshield.cnf )
#   -from    - e-mail 'from' information
#   -to      - e-mail 'to' information (default report@dshield.org )
#   -cc      - e-mail 'cc' information (default is none) 
#   -bcc     - e-mail blind 'cc' information (default is none) 
#   -userid  - dshield numerid userid (default 0)
#   -tz      - timezone (default: calculated TZ based on localtime)
#   -log     - location of your firewall log file (default: STDIN)
#   -verbose - turn on extra output 
#   -debug   - turn on even more output (implies -verbose)
#   -sendmail - location of mail software 
#                (default: "/usr/sbin/sendmail -oi -t")
#   -rotate  - Y: copy your log to "log.bak" and erase original
#                 This effectively *erases* all historical data
#              N: do nothing, but keep line count file
#              A: append to "log.bak"  Will keep historical data.
#   -linecnt - name of saved timestamp file (if rotate=N). 
#                   Default: /var/log/dshield.cnt
#              this file save the date and time of the last log line      
#   -tmp     - specify a temp file name
#   -obfus   - Y: hide target IP (replace first byte with 10.)
#            - N: don't (default).
#   -target_exclude - name of file with excluded target IPs.
#                     (default: none)
#   -source_exclude - name of file with excluded source IPs.
#                     (default: none)
#   -target_port_exclude - name of file with excluded target Ports.
#                     (default: none)
#   -source_port_exclude - name of file with excluded source Ports.
#                     (default: none)
#   -whereto - Specify where the final converted log will go
#              MAIL sends as mail to the address specified by the
#              'to' variable. (default)
#              Anything else is assumed to be a filename.  If it is a filename
#              then the output will be written to this file.  It is up to you
#              to do something with it.  (Wrapper script....)
#   -line_filter An optional regex that is passed to the parser.  If
#                used, then each log line must match this regex.  (The parser
#                has a default that should work for most common cases.)
#   -line_exclude Optional regex to *exclude* log lines.
#
#
# thanks from Ken:
#	- Many thanks to Johannes B. Ullrich for the
#	  Dshield project and allowing me to create some of
#	  the client parsers.
#	- Thanks to Bruce Lilly for providing a working
#	  time zone calculator
#	- Thanks to Dan Crooks for helping troubleshoot one
#	  very strange configuration file issue.

# define variables
my @dshield_array;
my ($name,$value,$line,$dshield);
my $excluded_sources="=";
my $excluded_targets="=";
my $line_count=0;
my $timestamp=0;

# Counters for various log line dipositions
my $log_cnt=0;
my $ship_cnt=0;
my $bad_cnt=0;
my $date_exc_cnt=0;
my $src_exc_cnt=0;
my $tar_exc_cnt=0;
my $src_port_exc_cnt=0;
my $tar_port_exc_cnt=0;
my $tmpsrc='';
# Parsers can set this to explain why they rejected a line
my $reason_skipped="";

$VERSION = "DShield Framework $FRAMEWORK_VERSION $PARSER $PARSER_VERSION";

my $format="DSHIELD";
my ($s, $s1);

# ipchains and iptables should be sent in in their native format.
# All others are sent in in DSHIELD format
# Do *not* submit any other formats in native format.  Only
# ipchains and iptables should be submitted in native format.
# (Comment this line out to submit in DSHIELD format.)
if ( $PARSER eq "IPCHAINS" || $PARSER eq "IPTABLES" ) { $format=$PARSER; }

my ($prev_dline, $prev_nline);

$ENV{"PATH"}="/usr/bin";
$ENV{"BASH_ENV"}="";

my %Month=("Jan" => 1,
	"Feb" => 2,
	"Mar" => 3,
	"Apr" => 4,
	"May" => 5,
	"Jun" => 6,
	"Jul" => 7,
	"Aug" => 8,
	"Sep" => 9,
	"Oct" => 10,
	"Nov" => 11,
	"Dec" => 12 );

my @now=localtime(time());
my $this_year=$now[5]+1900;
my $this_month=$now[4]+1;
my $this_day=$now[3];

# Calculate valid date range.  All dates must be between this range.
# Upper range is about one day in the future.  (Allows for a little TZ slop.)
# Lower range is a the same, but one year earlier.
my $y = $this_year;
my $m = $this_month;
my $d = $this_day + 1;
while ($d > 28) {  # Approximately a month.  Approximately.
	$d -= 28;
	$m++;
	if ($m > 12) { 
		$m = 1; 
		$y++;
	}
}
my $upper_date = sprintf("%0.4d-%0.2d-%0.2d 24:59:59", $y, $m, $d);
my $lower_date = sprintf("%0.4d-%0.2d-%0.2d 00:00:00", $y-1, $m, $d);
$upper_date = convert_to_timestring($upper_date);
$lower_date = convert_to_timestring($lower_date);

# define the default config file
$config="/etc/dshield.cnf" unless $config;

$verbose="N" unless $verbose;
$debug="N" unless $debug;
print center_string("Variable initialization","=") . "\n"  if ($debug eq "Y" );
print "CONFIGURATION FILE: [$config]\n" if ( $verbose eq "Y" );

# if -config= is specific on the command line, or default exists, then
#  open the config file
if ( -f $config ) {
	open (CONFIGFILE,"$config") || die ("Can't open $config for reading\n");
	foreach (<CONFIGFILE>) {

		# ignore lines starting with "#"
		if ( ! /^#/ ) {
			chomp;

			# skip blank lines
			next if ( /^\s*$/ );
			#print "$_\n";

			# split the line into variable and value
			($name,$value)=split("=");

			# get rid of leading and trailing spaces in value and name
			$name =~ s/^\s+//;
			$name =~ s/\s+$//;
			$value =~ s/^\s+//;
			$value =~ s/\s+$//;

			# make the variable lowercase
			$name=lc($name);

			#print "DEBUG: configuration file value - $name=[$value]\n" if ($debug eq "Y" );
			$$name=$value;
		}
	}
	close CONFIGFILE;
}

# for anything not set in the config file, set them to default
$from='nobody@nowhere.com' unless $from;
$to='report@dshield.org' unless $to;
$cc='' unless $cc;
$bcc='' unless $bcc;
$userid=0 unless $userid;
$tz=tz_offset() unless $tz;
$log="-" unless $log;
$verbose="N" unless $verbose;
$debug="N" unless $debug;
$sendmail="/usr/sbin/sendmail -oi -t" unless $sendmail;
$rotate="Y" unless $rotate;
$linecnt="/var/log/dshield.cnt" unless $linecnt;
$line_filter="" unless $line_filter;
$line_exclude="" unless $line_exclude;
$obfus="N" unless $obfus;
$tmpfile="/tmp/dshield.$$.tmp" unless $tmpfile;
$source_exclude="" unless $source_exclude;
$target_exclude="" unless $target_exclude;
$source_port_exclude="" unless $source_port_exclude;
$target_port_exclude="" unless $target_port_exclude;
$whereto="MAIL" unless $whereto;

# turn on verbose if debug is enabled
$verbose="Y" if ( $debug eq "Y" );
if ( $debug eq "Y" ) {
	print center_string("Variable initialization", "=") . "\n";
	print "DEBUG: FRAMEWORK_VERSION=[$FRAMEWORK_VERSION]\n";
	print "DEBUG: PARSER_VERSION=[$PARSER_VERSION]\n";
	print "DEBUG: PARSER=[$PARSER]\n";
	print "DEBUG: VERSION=[$VERSION]\n";
	print "DEBUG: format=[$format]\n";
	print "DEBUG: upper_date=[$upper_date]\n";
	print "DEBUG: lower_date=[$lower_date]\n";
	print "DEBUG: whereto=[$whereto]\n";
	print "DEBUG: from=[$from]\n";
	print "DEBUG: to=[$to]\n";
	print "DEBUG: cc=[$cc]\n";
	print "DEBUG: bcc=[$bcc]\n";
	print "DEBUG: userid=[$userid]\n";
	print "DEBUG: line_filter=[$line_filter]\n";
	print "DEBUG: line_exclude=[$line_exclude]\n";
	print "DEBUG: this_year=[$this_year]\n";
	print "DEBUG: this_month=[$this_month]\n";
	print "DEBUG: tz=[$tz]\n";
	print "DEBUG: log=[$log]\n";
	print "DEBUG: verbose=[$verbose]\n";
	print "DEBUG: sendmail=[$sendmail]\n";
	print "DEBUG: rotate=[$rotate]\n";
	print "DEBUG: linecnt=[$linecnt]\n";
	print "DEBUG: obfus=[$obfus]\n";
	print "DEBUG: tmpfile=[$tmpfile]\n";
	print "DEBUG: source_exclude=[$source_exclude]\n";
	print "DEBUG: target_exclude=[$target_exclude]\n";
	print "DEBUG: source_port_exclude=[$source_port_exclude]\n";
	print "DEBUG: target_port_exclude=[$target_port_exclude]\n";
}

print center_string("Exclusions file initialization", "=") . "\n"  if ($debug eq "Y" );

my (@src_exc_lo, @src_exc_hi, @tar_exc_lo, @tar_exc_hi);

# read the excluded source IP file
load_exclude($source_exclude, \@src_exc_lo, \@src_exc_hi, "1");

# read the excluded target IP file
load_exclude($target_exclude, \@tar_exc_lo, \@tar_exc_hi, "1");

my (@src_port_exc_lo, @src_port_exc_hi, @tar_port_exc_lo, @tar_port_exc_hi);

# read the excluded source Ports file
load_exclude($source_port_exclude, \@src_port_exc_lo, \@src_port_exc_hi, "0");

# read the excluded target Ports file
load_exclude($target_port_exclude, \@tar_port_exc_lo, \@tar_port_exc_hi, "0");

if ( $debug eq "Y" ) {
	print "DEBUG: Source Exclude IPs:\n";
	print_exclude(\@src_exc_lo, \@src_exc_hi);
	print "DEBUG: Target Exclude IPs:\n";
	print_exclude(\@tar_exc_lo, \@tar_exc_hi);
	print "DEBUG: Source Exclude Ports:\n";
	print_exclude(\@src_port_exc_lo, \@src_port_exc_hi);
	print "DEBUG: Target Exclude Ports:\n";
	print_exclude(\@tar_port_exc_lo, \@tar_port_exc_hi);
}

print center_string("Other file initialization", "=") . "\n"  if ($debug eq "Y" );

# if the log input is not from STDIN, check for the log file
if ( $log ne "-") {
	die ("Can't find log file at $log\n") unless ( -f $log );
}

# if rotate is "N", then use the date as the point to start
if ($rotate eq "N") {
	print "DEBUG: Opening time stamp file $linecnt\n" if ($debug eq "Y");
	if ( -f $linecnt ) { 
		open (LINECOUNT,$linecnt) || die "Can't open line count file $linecnt\n";
		chomp ($line_count = <LINECOUNT>);
		close LINECOUNT;
		print "DEBUG: Will only submit log lines later than ", convert_from_timestring($line_count), " (from previous session.)\n" if ($debug eq "Y");
	} else {
		print "DEBUG: Time stamp file $linecnt does not exist.  Will send all log lines.\n" if ($debug eq "Y");
	}
}

# open the log file for reading
print "DEBUG: opening $log for reading\n" if ( $debug eq "Y" );
open (LOGFILE,$log) || die ("Can't open $log for reading\n");

# open the file holding the valid processed line for writing
print "DEBUG: opening $tmpfile for writing\n" if ( $debug eq "Y" );
open (TMPFILE,"> $tmpfile") || die ("Can't open temp file $tmpfile for writing\n"); 

print center_string("Processing log file $log ", "=") . "\n"  if ($verbose eq "Y" );

# loop through the log file
while (<LOGFILE>) {
	$line=$_;
 
	#
	#  @dshield_array:
	#
	# 0 - time/date/timezone 1 - author 2 - count
	# 3 - sourceip, 4 - sourceport, 
	# 5 - targetip, 6 - targetport,
	# 7 - protocol, 8 - flags

	# send the log line to the parser

	$log_cnt++;
	print center_string("Processing line $log_cnt", "-") . "\nPARSING: $line" if ( $verbose eq "Y" );

 if (6 == 6) {
	if ($prev_dline) {
		$reason_skipped="";
	} else {
		$reason_skipped="Previous line was not a valid firewall log";
		#$prev_dline="";
	}
 }

	# $prev_dline will be non-NULL only if the previous line was a valid
	# DShield log line.  Note the rule.  Any operation that skips a line
	# must also clear $prev_dline.
	if ( $prev_dline && $line =~ /last message repeated (\d+) time/ ) {
		chomp($line); 
		printf "$1 REPEATED LINE%s.\n", ($1 == 1) ? "" : "S" if ( $verbose eq "Y" );
		if ($format ne "DSHIELD" ) { 
			# Native format.  Print out however many of the native logs,
			# because we don't know how to set the count in
			# native logs.  And can't anyway in the case of ipchains and iptables.
			$dshield = $prev_nline; chomp($dshield); 
			for ( $i = 0; $i < $1; $i++ ) {
				print TMPFILE "$dshield\n";
				print "WRITTEN: $dshield\n" if ( $verbose eq "Y" );
				$ship_cnt++;
			}
		} else {
			# But we can set the count field in a DShield record.
			@dshield_array = split("\t",$prev_dline);
			$dshield_array[2] = $1;
			$dshield = join("\t",@dshield_array);
			print TMPFILE "$dshield\n";
			print "WRITTEN: $dshield\n" if ( $verbose eq "Y" );
			$ship_cnt++;
		}
		next;
	} else {
		# Not a repeat.  Parse it.
		@dshield_array = parse($line);
		if ( ! $dshield_array[0] ) {
			# We flunked.
			if ( $verbose eq "Y" ) {
				if ( $reason_skipped ) {
					print "SKIPPING: $reason_skipped\n";
				} else {
					print "SKIPPING: $line" 
				}
			}
			$bad_cnt++;
			$prev_dline=""; $prev_nline="";
			next;
		}
	}

	# Reject if this line if date/time is less than date/time from last session
	# $line_count is date/time from last session
	$logtime = convert_to_timestring($dshield_array[0]);
	if ( $logtime < $line_count ) {
		$dshield = join("\t",@dshield_array);
		print "PARSE RESULT:", join("|",@dshield_array) ,"\n" if ( $verbose eq "Y" );
		print "SKIPPING: $dshield_array[0] is too early\n" if ( $verbose eq "Y" );
		$date_exc_cnt++;
		$prev_dline=""; $prev_nline="";
		next;
	}

	# Reject if date is in the future (Bad date conversion?)
	if ( $logtime > $upper_date ) {
		$dshield = join("\t",@dshield_array);
		print "PARSE RESULT:", join("|",@dshield_array) ,"\n" if ( $verbose eq "Y" );
		print "SKIPPING: $dshield_array[0] is too far in the future\n" if ( $verbose eq "Y" );
		$date_exc_cnt++;
		$prev_dline=""; $prev_nline="";
		next;
	}

	# Reject if date is too old.
	if ( $logtime < $lower_date ) {
		$dshield = join("\t",@dshield_array);
		print "PARSE RESULT:", join("|",@dshield_array) ,"\n" if ( $verbose eq "Y" );
		print "SKIPPING: $dshield_array[0] is too far in the past\n" if ( $verbose eq "Y" );
		$date_exc_cnt++;
		$prev_dline=""; $prev_nline="";
		next;
	}

	# Save the highest date/time from *this* session.
	# (We don't require log lines to be in date/time order....)
	if ($logtime > $timestamp) { $timestamp = $logtime; }

	# Now test to see if IPs or ports are to be excluded
	if (test_IP_exclude(\@src_exc_lo, \@src_exc_hi, padip($dshield_array[3]))) {
		$dshield = join("\t",@dshield_array);
		print "PARSE RESULT:", join("|",@dshield_array) ,"\n" if ( $verbose eq "Y" );
		print "SOURCE IP EXCLUDED: $dshield_array[3]\n" if ( $verbose eq "Y" );
		$src_exc_cnt++;
		$prev_dline=""; $prev_nline="";
		next;
	}

	if (test_IP_exclude(\@tar_exc_lo, \@tar_exc_hi, padip($dshield_array[5]))) {
		$dshield = join("\t",@dshield_array);
		print "PARSE RESULT:", join("|",@dshield_array) ,"\n" if ( $verbose eq "Y" );
		print "TARGET IP EXCLUDED: $dshield_array[5]\n" if ( $verbose eq "Y" );
		$tar_exc_cnt++;
		$prev_dline=""; $prev_nline="";
		next;
	}

	if (test_exclude(\@src_port_exc_lo, \@src_port_exc_hi, $dshield_array[4])) {
		$dshield = join("\t",@dshield_array);
		print "PARSE RESULT:", join("|",@dshield_array) ,"\n" if ( $verbose eq "Y" );
		print "SOURCE PORT EXCLUDED: $dshield_array[4]\n" if ( $verbose eq "Y" );
		$src_port_exc_cnt++;
		$prev_dline=""; $prev_nline="";
		next;
	}

	if (test_exclude(\@tar_port_exc_lo, \@tar_port_exc_hi, $dshield_array[6])) {
		$dshield = join("\t",@dshield_array);
		print "PARSE RESULT:", join("|",@dshield_array) ,"\n" if ( $verbose eq "Y" );
		print "TARGET PORT EXCLUDED: $dshield_array[6]\n" if ( $verbose eq "Y" );
		$tar_port_exc_cnt++;
		$prev_dline=""; $prev_nline="";
		next;
	}
			
	# if obfuscate is enabled, replace first octet with 10
	if ( $obfus eq "Y" ) {
		# Original IP
		$s = $dshield_array[5];
		# Now obsfuscate it in DShield array
		$dshield_array[5] =~ s/^\d+\./10./;
		# $s1 is the obsfuscated IP
		$s1 = $dshield_array[5];
		# Now search/replace in the original native line
		$line =~ s/$s/$s1/eg;
		chomp($line);
		print "OBFUSCATE: target IP $s changed to $s1\n" if ( $verbose eq "Y" );
	}

	# join the array elements into one line, tab separated
	$dshield = join("\t",@dshield_array);
	print "PARSE RESULT:", join("|",@dshield_array) ,"\n" if ( $verbose eq "Y" );

	# if the line is valid, output to temp file
	if (validate_dshield($dshield) ) {
		# Send the native log line, if not DSHIELD format
		if ($format ne "DSHIELD" ) { $dshield = $line; chomp($dshield);}
		print TMPFILE "$dshield\n";
		print "WRITTEN: $dshield\n" if ( $verbose eq "Y" );
		$ship_cnt++;
		$prev_dline = $dshield; $prev_nline = $line;
	} else {
		print "NOT WRITTEN\n" if ( $verbose eq "Y" );
		$bad_cnt++;
		$prev_dline=""; $prev_nline="";
	}
}

#print "=" x 79 , "\n" if ( $verbose eq "Y" );
print center_string("Clean-up processing", "=") . "\n"  if ($verbose eq "Y" );

close LOGFILE;
close TMPFILE;

# if rotate is specified as "Y" and the input is not from STDIN, rotate
if ( $rotate eq "Y" && $log ne "-" ) {
	print "DEBUG: rotating $log to $log.bak\n" if ( $debug eq "Y" );
	open LOGFILE,$log || die "Can't open $log for reading\n";
	open LOGROTATE,">$log.bak" || die "Can't open $log.bak for writing\n";
	while ( <LOGFILE> ) {
		print LOGROTATE;
	}
	close LOGROTATE;
	close LOGFILE;

	# remove the old log file
	unlink $log;
}

# if the rotate is append and the input is not STDIN, append the data
if ( $rotate eq "A" && $log ne "-" ) {
	print "DEBUG: appending $log to $log.bak\n" if ( $debug eq "Y" );
	open LOGFILE,$log || die "Can't open $log for reading\n";
	open LOGAPPEND,">>$log.bak" || die "Can't open $log.bak for appending\n";
	while ( <LOGFILE> ) {
		print LOGAPPEND;
	}
	close LOGAPPEND;
	close LOGFILE;

	# remove the old log file
	unlink $log;
}

# if rotate is no, then write the current date as the marker
if ( $rotate eq "N") {
	$timestamp++;
	if ($line_count > $timestamp ) { $timestamp = $line_count; }
	print "DEBUG: updating timestamp file $linecnt (", convert_from_timestring($timestamp), ")\n" if ( $debug eq "Y" );
	open (LINECOUNT,"> $linecnt") || die "Can't open line count file for writing $linecnt\n";
	print LINECOUNT $timestamp;
	close LINECOUNT;
}

# if the temporary file is not empty, send the contents as and e-mail
unless ( -z $tmpfile ) {
	if ( $verbose eq "Y" ) {
      if ( $whereto eq "MAIL" ) {
		print "SENDING USING: $sendmail\n";
		print "SENDING TO/FROM: $to / $from\n";
	  } else {
		print "WRITING OUTPUT TO: $whereto\n";
      }
	}
	if ($whereto eq "MAIL" ) {
	    open (MAIL,"| $sendmail") or die "Can't access $sendmail for sending the e-mail\n";
	} else {
	    open (MAIL,"> $whereto") or die "Can't open $whereto for writing the output file.\n";
	}	    
	print MAIL "To: $to\n";
	print MAIL "Cc: $cc\n" if $cc;
	print MAIL "Bcc: $bcc\n" if $bcc;
	print MAIL "From: $from\n";
	print MAIL "Subject: FORMAT $format USERID $userid TZ $tz VERSION $VERSION\n\n";
	open (TMPFILE,"$tmpfile") || die ("Can't open temp file $tmpfile for reading\n");
	foreach (<TMPFILE>) {
		print MAIL $_;
	}
	close TMPFILE; 

	# politely end the mail session
	close MAIL;
} else {
	print "WARNING: $tmpfile is empty.  Not sending any mail.\n" if ( $verbose eq "Y" );
}

# remove the temporary file
if ( -f $tmpfile ) {
	print "DEBUG: deleting $tmpfile\n" if ( $debug eq "Y" );
	unlink ($tmpfile);
}

if ($verbose eq "Y" ) {
	print center_string("Totals", "=") . "\n";
	#print "-" x 79 , "\n";
	printf "Wrote %d valid log lines\n", $ship_cnt;
	printf "Excluded %d invalid (unparsable for some reason) lines\n",$bad_cnt;
	printf "Excluded %d lines that were too early\n", $date_exc_cnt;
	printf "Excluded %d source IP filtered lines\n", $src_exc_cnt;
	printf "Excluded %d target IP filtered lines\n", $tar_exc_cnt;
	printf "Excluded %d source Port filtered lines\n", $src_port_exc_cnt;
	printf "Excluded %d target Port filtered lines\n", $tar_port_exc_cnt;
	print center_string("All Done", "=") . "\n";
}

exit 0;

# ----------And that's a wrap----------------------------


# ----------Beginning of subroutines---------------------
#
# calculate TZ based on gmtime and localtime
# based on a C routine provided by Bruce Lilly (many thanks!)
#
sub tz_offset {
	my ($year,$numberDays,$hhmm);

	my $now = time;
	my ($l_min,$l_hour,$l_year,$l_yday)=(localtime $now)[1,2,5,7];
	my ($g_min,$g_hour,$g_year,$g_yday)=(gmtime $now)[1,2,5,7];

	if ( $l_year > $g_year ) {
		$year = 1900 + $g_year;
	} else {
		$year = 1900 + $l_year;
	}
	if ( ( ($year % 4) == 0 ) && ( ($year %100) != 0) || ( ($year % 400) == 0) ) {
		$numberDays = 366;
	} else {
		$numberDays = 365;
	}

	$hhmm = ( ( ( $l_year - $g_year ) * $numberDays 
		+ $l_yday - $g_yday ) * 24
		+ $l_hour - $g_hour ) * 100
		+ $l_min - $g_min;

	print center_string("Calculating Time Zone", "=") . "\n"  if ($debug eq "Y" );

	my $return = sprintf ("%+0.4d",$hhmm);	# format used by RFCs 821/822/2821/2822 
	print "DEBUG: calculated RFC 821 based tz = $return\n" if ( $debug eq "Y" );

	$return = sprintf ("%s:%s",substr ($return,0,-2),substr ($return,-2,2)); # dshield
	print "DEBUG: calculated tz = $return\n" if ( $debug eq "Y" );

	$return;
} 

sub convert_to_timestring {
	my ($timestring) = @_;
	my ($year,$month,$day,$hour,$minute,$seconds);

	# break down the timestring into atomic parts
	($year,$month,$day,$hour,$minute,$seconds)=( $timestring =~ m/(\d+)-(\d+)-(\d+)\s+(\d+):(\d+):(\d+)/ );

	join "",$year,$month,$day,$hour,$minute,$seconds;
}

sub convert_from_timestring {
	my ($timestring) = @_;
	my ($year,$month,$day,$hour,$minute,$seconds);
	$year = substr($timestring, 0, 4);
	$month = substr($timestring, 4, 2);
	$day = substr($timestring, 6, 2);
	$hour = substr($timestring, 8, 2);
	$minute = substr($timestring, 10, 2);
	$seconds = substr($timestring, 12, 2);

	return "$year-$month-$day $hour:$minute:$seconds";
}

# validate the format of the output line
sub validate_dshield {

	my $line=shift;
    #                      Date           Time               TZ           ID   Cnt    Src IP     SPrt   Target IP   TPrt    Protocol            Flags                            
#	if ( $line =~ /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{2}:?\d{2}\t\d+\t\d+\t[0-9.]{7,15}\t\d+\t[0-9.]{7,15}\t\d+\t[0-9TCPIMPUD\?]{0,4}\t?[12UPFSAR]{0,6}$/ ) {
    # Also allow "???" for protocol
    #                      Date           Time               TZ           ID   Cnt    Src IP        SPrt        Target IP     TPrt         Protocol            Flags
	if ( $line =~ /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{2}:?\d{2}\t\d+\t\d+\t[0-9.]{7,15}\t\d+|\?\?\?\t[0-9.]{7,15}\t\d+|\?\?\?\t[0-9TCPIMPUD\?]{0,4}\t?[12UPFSAR]{0,8}$/ ) {
		return 1;
	} else {

# ([0-9a-f]{4}:){7}[0-9a-f]{4}
	    if ( $line =~ /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{2}:?\d{2}\t\d+\t\d+\t([0-9a-f]{4}:){7}[0-9a-f]{4}\t\d+|\?\?\?\t([0-9a-f]{4}:){7}[0-9a-f]{4}\t\d+|\?\?\?\t[0-9TCPIMPUD\?]{0,4}\t?[12UPFSAR]{0,8}$/ ) {
		return 1;
	    } else {


		print "INVALID: $line\n";
		talky_validate($line);
		return 0;
	    }
	}
}

sub talky_validate {
	my $line = shift;
	my @t;
	my $f = "1";

	@t = split ("\t", $line);
	if ($#t < 7 ) {
		print "\tINVALID: Not enough fields $#t\n";
		return 0;
	}

	# Date/Time/TZ  YYYY-DD-MM HH:MM:SS [+-]HH:SS
	if ( $t[0] !~ /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{2}:?\d{2}/ ) {
		print "\tInvalid date/time: $t[0]\n";
		$f = "0";
	}	
	# User ID
	if ( $t[1] !~ /^\d+/ ) {
		print "\tInvalid User ID: $t[1]\n";
		$f = "0";
	}	
	# Count
	if ( $t[2] !~ /^\d+$/ ) {
		print "\tInvalid count: $t[2]\n";
		$f = "0";
	}	
	# Source IP
	#if ( $t[3] !~ /[0-9.]{7,15}/ ) {
	if ( $t[3] !~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ) {
	    $tmpsrc=$t[3];
	    $t[3]=valid_ipv6($t[3]);
	    if ( $t[3]==0 ) {
		print "\tInvalid source IP: $tmpsrc\n";
		$f = "0";
	    }
	}


	
	# Source Port
	if ( $t[4] !~ /\d+/ ) {
	  if ( $t[4] ne "???" ) {
		print "\tInvalid source port: $t[4]\n";
		$f = "0";
	  }
	}	
	# Target IP
	if ( $t[5] !~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ) {
	    $tmpsrc=$t[5];
	    $t[5]=valid_ipv6($t[5]);
	    if ( $t[5]==0 ) {
		print "\tInvalid target IP: $tmpsrc\n";
		$f = "0";
	    }
	}	
	# Target Port
	if ( $t[6] !~ /\d+/ ) {
	  if ( $t[6] ne "???" ) {
		print "\tInvalid target port: $t[6]\n";
		$f = "0";
	  }
	}
	# Protocol
	if ( $t[7] !~ /[0-9TCPIMPUD\?]{1,4}/ ) {
	#if ( $t[7] !~ /[0-9TCPIMPUD\?]+/ ) {
		print "\tInvalid Protocol: $t[7]\n";
		$f = "0";
	}	
	# Flags (is optional)
	if ($t[8]) {
		if ( $t[8] !~ /[12UPFSAR]{1,8}/ ) {
			print "\tInvalid Flags: $t[8]\n";
			$f = "0";
		}
	}
	
	return $f;		
}

sub valid_ipv6 {
    my $ip=shift;
    my $c=($ip =~ s/:/:/g );
    if ( $c<7 && $c>1 ) {
        my $ins="0000:" x (8-$c);
        $ip=~ s/::/:$ins/;
        if ( $ip=~/::/ ) {
            return 0;
        }
    }
    $c=($ip =~ s/:/:/g );
    if ( $c==7 ) {
        my @sub=split(/:/,$ip);
        my $i=0;
        foreach ( @sub ) {
            my $zeros='0' x (4-length($_));
            $sub[$i]=$zeros.$sub[$i];
            $i++;
        }
        $ip=join(':',@sub);
    }
    if ( $ip=~/^([0-9a-f]{4}:){7}[0-9a-f]{4}$/ ) {
        return $ip;
    }
    return 0;
}


# Converts from 0.0.0.0 format to a 32 bit long integer
sub pack_ip {
	#return pack("C4", split(/\./, $_[0]));

	my @b = split(/\./, $_[0]);
	my $tmp = 0;
	$tmp += $b[3];
	$tmp += $b[2] * 256;
	$tmp += $b[1] * 65536;
	$tmp += $b[0] * 16777216;
	return $tmp;
}
        
# Converts from a 32 bit long integer to 0.0.0.0 format
sub unpack_ip {
	#return join('.', unpack("C4", $_[0]));

	my $packedip = shift;
	my @ip;
	$ip[3] = $packedip & 0xff;
	$ip[2] = ($packedip & 0xff00) >> 8;
	$ip[1] = ($packedip & 0xff0000) >> 16;
	$ip[0] = ($packedip & 0xff000000) >> 24;
	return join('.', @ip);
}

# Put leading zeros before each "quad", so IPs can be compared alphabetically.
sub padip {
	my $ip = $_[0];
	#if ($ip eq "???" ) { return $ip }

	my @t = split(/\./, $ip);
        
    return sprintf("%0.3d.%0.3d.%0.3d.%0.3d",$t[0],$t[1],$t[2],$t[3]);
}

# Is this a valid IP?
sub is_good_ip {
	my $ip = shift;

	# Does it match the regex for an IP?
	#if ( $ip !~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ) { return 0 }

	my @p = split(/\./, $ip);
	if ( $#p != 3 ) { return 0 }

	my $byte;
	foreach $byte (@p) {
		if ($byte !~ m/\d{1,3}/ ) { return 0 }
		if ($byte < "0"  || $byte > "255" ) { return 0 }
	}

	# Finally passed all the tests.
	return 1;
}

# Is this a valid port number?
sub is_good_port {
	my $port = shift;

	if ( $port =~ /^[\d{1,5}]/ ) {
		if ($port >= "0" && $port <= "65536" ) {
			return "1";
		}
	} else {
		return "0";
	}
}

# Read the excluded destination IP or Port file
# If IP, then store them padded.  (Ports are stored unpadded.)
sub load_exclude {
	# File name of IPs or ports that are to be excluded
	my $exclude = $_[0];
	# *References* to arrays that we are going to fill.
	# i.e., passed like /@ar_lo, /@ar_hi
	my $ar_lo = $_[1];
	my $ar_hi = $_[2];
	# Are we processing IPs? (or just ports)  "1" == IP
	my $is_ip = $_[3]; 	
	my ($lo, $hi);
	my $i = 0;
	if ( -f $exclude ) {
		open (FILE,$exclude) || die "Can't open $exclude for reading\n";
		foreach (<FILE>) {
			chomp;

			# Eliminate leading and trailing white space
			s/^\s+//;
			s/\s+$//;

			# Skip comment lines that start with '#'
			unless ( /^#/ ) {

				# Skip blank lines
				next if ( /^\s*$/ );

				if ( index( $_, "/") > 0 ) {
					# 127.0.0.0/8 format
				    my ($ip, $maskbits, $bitmask, $bitmaskc, $packedip, $packedlo);
					($ip, $maskbits) = split("/");

					# Remove leading and trailing white space
					$ip =~ s/^\s+//;
					$maskbits =~ s/\s+$//;

					# Now convert to a 32 bit integer
					$packedip = pack_ip($ip);

					# Convert to bitmasks
					$bitmask = (1 << (32 - $maskbits)) - 1;
					$bitmaskc = ($bitmask * -1) - 1;

					# And apply the masks
					$lo = unpack_ip( $packedip & $bitmaskc );
					$hi = unpack_ip( $packedip | $bitmask );
					#printf "%s %u %08x %08x %08x %s - %s\n", $ip, $maskbits, $packedip, $bitmask, $bitmaskc, $lo, $hi;					
				} else {
					# 127.0.0.0 - 127.255.255.255 format
					($lo, $hi) = split("-");
					# Remove leading and trailing white space
					$lo =~ s/^\s+//;
					$lo =~ s/\s+$//;
					if ($hi) {
						$hi =~ s/^\s+//;
						$hi =~ s/\s+$//;
					} else {
						$hi = $lo;
					}
				}

				if ($is_ip) {
					# make sure it is in dotted IP format.
					# Then pad each IP with leading zeros.
					if ( is_good_ip($lo) && is_good_ip($hi) ) {
						$i++;
						$ar_lo->[$i] = padip($lo);
						$ar_hi->[$i] = padip($hi);
						#print "$i $lo - $hi\n";
					} else {
						print "WARNING: Bad IP address range [$lo - $hi] in $exclude\n";
					}
				} else {
					# Make sure it is is a valid port number.
					if ( is_good_port($lo) && is_good_port($hi) ) {
						$i++;
						$ar_lo->[$i] = $lo;
						$ar_hi->[$i] = $hi;
						#print "$i $lo - $hi\n";
					} else {
						print "WARNING: Bad Port range [$lo - $hi] in $exclude\n";
					}
				}
			}
		}
	} else {
	    if ( $exclude ne '' ) {
		print "Warning: Can't find the exclude file $exclude\n";
            }
	}
}

# Prints the arrays of exclude IPs (for debugging.)
sub print_exclude {
	# Is a reference to the arrays.
    my $ar_lo = $_[0];
    my $ar_hi = $_[1];
	my $cnt = $#{$ar_lo};
	if ( $cnt > 0 ) {
		print "DEBUG: Using $cnt exclusions.\n";
	} else {
		print "DEBUG: No exclusions.\n";
	}
	my ($i, $lo, $hi);

	for ($i = 1; $i <= $cnt; $i++) {
		$lo = $ar_lo->[$i];
		$hi = $ar_hi->[$i];
		print "DEBUG: $i  $lo - $hi\n"; 
		#printf "(%u) 0x%08x %s - ", pack_ip($lo), pack_ip($lo), unpack_ip(pack_ip($lo));
		#printf "(%u) 0x%08x %s\n", pack_ip($hi), pack_ip($hi), unpack_ip(pack_ip($hi));
	}
}

# Is $ip in the range to be excluded? 
sub test_IP_exclude {
    my $ar_lo = $_[0];
    my $ar_hi = $_[1];
	my $ip = $_[2];
	my $cnt = $#{$ar_lo};
	my $i;
	#print "DEBUG: Searching $cnt exclusions\n"  if ( $debug eq "Y" );

	#if ( $ip =~ /\?\?\?/ ) { return 0; }
	# At this point $ip and the range are all padded.  (Or not, in the case of ports.)
	for ($i = 1; $i <= $cnt; $i++) {
		if ($ip ge $ar_lo->[$i] && $ip le $ar_hi->[$i] ) { 
			print "DEBUG: $ip excluded because it is between $ar_lo->[$i] and $ar_hi->[$i]\n" if ( $debug eq "Y" );
			return 1;
		}
	}
	return 0;
}

# Is $port) in the range to be excluded? 
sub test_exclude {
    my $ar_lo = $_[0];
    my $ar_hi = $_[1];
	my $ip = $_[2];
	my $cnt = $#{$ar_lo};
	my $i;
	#print "DEBUG: Searching $cnt exclusions\n"  if ( $debug eq "Y" );
	# At this point $ip and the range are all padded.  (Or not, in the case of ports.)
	for ($i = 1; $i <= $cnt; $i++) {
		if ($ip >= $ar_lo->[$i] && $ip <= $ar_hi->[$i] ) { 
			print "DEBUG: $ip excluded because it is between $ar_lo->[$i] and $ar_hi->[$i]\n" if ( $debug eq "Y" );
			return 1;
		}
	}
	return 0;
}

sub center_string {
	# String to center, [Padding character, Width]
	my $s = shift;
	my $p = shift;
	my $w = shift;
	my ($i, $t);

	if ( ! $p ) { $p = " "; }
	if ( ! $w ) { $w = "79"; }
	$s = substr($s, 0, $w);

	# Roundoff....
	$i = ( $w - length($s) ) / 2;
	$t = $p x $i . $s;
	return $t . $p x ( $w - length($t) );
}

# End of framework section.

# Beginning of iptables Parser

#
# Framework for parsing of the log line
#
# @rline - array to be returned holding the required values for Dshield
#  $rline[0] - date in yyyy-mm-dd HH:MM:SS tz format
#  $rline[1] - Dshield user ID
#  $rline[2] - number of lines this log entry represents (normally 1)
#  $rline[3] - source IP in dotted decimal format (x.x.x.x)
#  $rline[4] - numeric source port for TCP/UDP or ithe ICMP code
#  $rline[5] - destination IP in dotted decimal format (x.x.x.x)
#  $rline[6] - numeric destination port for TCP/UDP or the ICMP type
#  $rline[7] - protocol in uppercase
#  $rline[8] - TCP flags (SFAPRU12)
#
# Global variables defined by calling routine
# $this_year - Current year in YYYY format
# $this_month - Current month in numerical format.  '1' for Jan.
# @Month  Hash of three letter abgreviations for months.  
# $tz - (i.e. -04:00 for EDT)
# $userid - Dshield user ID
# $line_filter  Regex that each line must match.  
# $line_exclude Regex for lines we want to exclude.
# $reason_skipped  You fill this with the reason the line wasn't parsed.

sub parse {
	my $line=shift;
	my @rline;
	my (%param, $name, $value);
	my ($srcpt, $dstpt);
	my $flags="";

	#print "$line\n" if ($verbose eq 'Y'); 
	$reason_skipped = "Does not contain 'kernel:'"; return 0 unless ( $line =~ /kernel:/ );

	# Is this any kind of packet filter log line?
	if ($line_filter) { 
		$reason_skipped = "Does not contain '$line_filter'"; return 0 unless ( $line =~ /$line_filter/ ) 
	}

	# Or maybe it has something undesirable that we don't want to see?
	if ($line_exclude) { $reason_skipped = "Contains `$line_exclude`"; return 0 if ( $line =~ /$line_exclude/ ) }

	my @fields=split(' ', $line);

	# First do date/time
	my $month=$fields[0];
	my $day=$fields[1];
	my $time=$fields[2];
	$month=$Month{$month};

	# iptables log does not have the year.  So we take a guess at it.
	# Lets hope that we are't processing more than one year.  :-(
	if ($month <= $this_month) { 
		$year = $this_year;
	} else {
		$year = $this_year - 1;
	}
	my $date=sprintf("%0.4d-%0.2d-%0.2d %s %s",$year,$month,$day,$time,$tz);

	# Put the rest of the fields in a hash
	foreach ( @fields ) {
		($name,$value)=split("=");
		$param{$name}=$value;
		$param{$name}='1' if ($param{'PROTO'} eq 'TCP' && ( ($name eq 'SYN') || ($name eq 'ACK') )); 
	}

	if ( $param{"PROTO"} eq "TCP" ) {
		$flags .= "R" if ( $param{"RES"} ne '0x00' ); 
		$flags .= "U" if ( $param{"URGP"} ne '0' );
		$flags .= "S" if ( $param{"SYN"} );
		$flags .= "A" if ( $param{"ACK"} );
	}

    if ( $param{"PROTO"} eq "ICMP" ) {
		$srcpt = $param{"TYPE"};
		$dstpt = $param{"CODE"};
    } else {
		$srcpt = $param{"SPT"};
		$dstpt = $param{"DPT"};
    }

    # Only fill the output fields if we are valid.
    if ( $date && $param{"SRC"} && ($srcpt ne '') && $param{"DST"} && ($dstpt ne '') && ($param{"PROTO"} ne '')  ) { 
     
		$rline[0] = $date;
		$rline[1] = $userid;
		$rline[2] = "1";
		$rline[3] = $param{'SRC'};
		$rline[4] = $srcpt;
		$rline[5] = $param{'DST'};
		$rline[6] = $dstpt;
		$rline[7] = $param{'PROTO'};
		$rline[8] = $flags;
   } else {
		$reason_skipped = "Failed to parse";
		return 0;
   }

    $_=$x;
    return @rline;
}
