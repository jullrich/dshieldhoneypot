DShield Framework Firewall Log Conversion Client

Send any questions to info@dshield.org

This script reads the log that your firewall produces and converts it to
DShield format and emails it into DShield.  


CONFIGURE IT FIRST

The configuration variables are located in a separate configuration file. 
The default location is /etc/dshield.cnf.  If putting dshield.cnf in 
/etc isn't possible, you can use the '-config=' command line variable to 
point to a different location.  e.g.  
'-config=/home/dshield/script/dshield.cnf' (if you put dshield.cnf in 
'/home/dshield/script')

See dshild.cnf for documentation for each variable.

If you want a "quick start" to test the script, see the TEST IT section,
below.


IP AND PORT EXCLUSION

You can prevent log lines from being included in the file that is sent to
DShield

By IP address:  by specifying IP addresses in the 'dshield-source-exclude.lst'
and dshield-target-exclude.lst' files. Enter either a single IP or a range of
IPs (192.168.1.0 - 192.168.1.255)

By Port: by specifying ports in the 'dshield-source-port-exclude.lst' and
dshield-target-port-exclude.lst' files.  Enter either a single port or a
range of ports (1000 - 1005)

The default location for these files is in /etc.  If you need to put
them somewhere else, change the appropriate variables in dshield.cnf


CONFIGURATION HINTS

- Each time the script runs, it saves the timestamp of the last log line
processed in a file on disk (unless you are using the 'rotate' option) in
the location that is pointed to by the 'linecnt' variable.  The next time
you run the script, it will exclude log lines earlier than this.  This is
great when you have the script all working and put it on a cron job, but is a
headache when you are first configuring and testing.  So remembet to delete
this file before each test run.  (linecnt variable in dshield.cnf.)

- Set the 'verbose' and 'debug' variables in dshield.cnf to 'Y' and redirect
the output of the script to a file.

- The 'whereto' variable in dshield.cnf sets where the output goes.  If
'whereto=MAIL' then the converted file will be sent as email to the address
specified with the 'to' variable.  Again, you would normally set
'to=report@dshield.org' when you are all done testing and configuring.  But
for testing, it might be handier to set 'whereto' to point to a local file
that you can examine.

- The 'line_filter' and 'line_exclue' variables in dshield.cnf control
what log lines are included or excluded for processing.  You
must use a regular expression pattern. If you aren't familiar with regular
expression syntax, see http://www.dshield.org/regex.php for
more information.  (Hint, probably the only part you need to look over
is the part on metacharacters that need escaping.)

- If your log file is large, consider manually extracting a shorter version
into a separate file to use for testing.  Examine this file to see that it
contains valid log lines that should be converted.  (And not just 'programs
has restarted' type status information.)

- You can pass any of the configuration file variables from the command
line *but* these variables must be commented out in the configuration file
first.


TEST IT

We supply test.cnf, which is a configuration file with the
comments stripped down and most of the variables changed to point to the
current directory.  (This is OK for testing from the command line, but not
necessarily a good idea for running from a cron job.  "Current directory"
is not particularily defined for a cron job--so variables should contain
explicit paths when running from a cron job.)

The one variable you must set is 'log=....' This must be set to point
to the file that contains your firewall logs.  Otherwise, test.cnf
is configured to

- Read from and write to the current directory
- Not send the converted file as email to DShield, but to write it to
'output.txt' in the current directory
- set 'verbose=Y" and 'debug=Y' so that it will print lots of intermediate
processing information, so you can see how it processes.  
(Or doesn't process....)
- Not do any log rotation.  (rotate=N)  Log rotation is a headache
when testing, because you have to worry about undoing log rotation when you
are done testing.

Look at the test.wrapper.sh script:

#!/bin/sh
#
# For testing the DShield framework client
#
# Write an arbitrary timestamp to dshield.cnt for testing ONLY.
# Do NOT do this when you are running "for real"
#     YYYYMMDDHHMMSS
echo "20011201000000" > dshield.cnt
#
# Now run the script using test.cnf in the current directory.
# Redirect the verbose debugging output to debug.txt.
./{scriptname}.pl -config=./test.cnf > debug.txt

(where {scriptname}.pl is the name of the script you are running.) 
When you run this, the debugging output will be written to debug.txt.  The
converted log (that is normally sent to DShield.org) will be written
to output.txt

Look at 'debug.txt' in your favorite editor.  It should contain:

- A section showing how the variables are initialized.
- A section showing how the IP and port exclusion files were processed.
- A section showing other initialization  (Creating tmp files, etc.)
- A section that displays each log line and how it was processed.
- A section showing the clean-up processing.  (Erasing tmp files, etc.)
- A summary with totals of various processing tasks.

Note that this test script writes "20011201000000" to dshield.cnt.  This is the
date/time "2001-12-01 00:00:00" in the stripped down format
that dshield.cnt uses.  debug.txt should show that log lines
that are earlier than this are rejected.  Log lines later than
this are accepted.  Adjust this in your test script as needed for testing.

Check to see that any IP or port exclusions you set
in the /etc/dshield*.lst files are executed as you intended them to.

Test and edit .cnf variables as needed.  When you have it working,
then configure the variables in dshield.cnf (or in test.cnf) to mail the
output to dshield (usually 'to=report@dshield.org' and
'whereis=MAIL'), put the .cnf and .lst files where you want them, and then
add a cron job to run the script.  (The cron job shouldn't write
to the dshield.cnt file, of course.)  

test.cnf and test_wrapper.sh are oriented towards keeping everything
in the current directory.  dshield.cnf is oriented towards putting files
in their "classical" locations.  e.g., config files in /etc, temp files in
/tmp, etc.  dshield.cnf also has more extensive comments above each variable.
You can work with whichever version suits the way you want to set
things up.

See http://www.dshield.org/framework.php#security for more information
on how to run this script after you have it configured and tested.

(The reason why this document is vague on the actual name of the script is
that this script is one of our new "framework" clients, which consist of one
processing "engine" and separate parsers for different types for firewalls. 
So the script will be named 'iptables.pl', 'ipchains.pl', depending.  See
CHANGES AND BUG FIXES for more on the framework development system.)

USER SUGGESTION ON HANDLING LOG ROTATION

User Tim Rushing contributed this suggestion:

Instead of letting your ipchains.pl script rotate my logs, I kept the log 
rotation going via logrotate.  (That way I still get things e-mailed to me 
and the old logs compressed without hacking the ipchains.pl script.)  What 
I did, though, to make certain that I don't miss those additional hack 
attempts was to change the "messages" section of my stock Red Hat 
/etc/logrotate.d/syslog file to this:

# Rotates syslog log files
##########################
#
/var/log/messages {
     prerotate
          cd /home/dshield/ipchains; ./ipchains.pl > /home/dshield/ipchains/dshield_debug_.txt
     endscript
     postrotate
         /usr/bin/killall -HUP syslogd
     endscript
}

I still have the daily crontab sending things, but this way there will be 
an additional submission from me just before my logs are rotated on a 
weekly basis.

I have also modified my /etc/crontab file so that the daily cron jobs (the 
ones that call logrotate) do not run at the default Red Hat time of 4:02 
am, so that if you do add this suggestion to your instructions, mine won't 
come in when everyone else's do. :)

         ---Tim Rushing



CHANGES AND BUG FIXES

This script was developed using our "framework" system.  If you fix any
bugs or want to write a new parser (highly encouraged!), please download
framework.tar.gz from the DShield Linux Framework Clients page
(http://www.dshield.org/framework.php#frameworkdevelopment) so that
your development efforts coordinate with ours.  Thank you.

Send any questions to info@dshield.org


NOTES ON CONFIGURING THE IPTABLES FIREWALL

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
my $PARSER_VERSION = "2002-03-28";
