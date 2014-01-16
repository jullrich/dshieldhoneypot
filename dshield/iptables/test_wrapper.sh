#!/bin/sh
#
# For testing the DShield framework client
#
# You must change the 'log' variable in test.cnf to point
# to your log file.
#
# Write an arbitrary timestamp to dshield.cnt for testing ONLY.
# Do NOT do this when you are running "for real"
#     YYYYMMDDHHMMSS
echo "20021201000000" > dshield.cnt
#
# Now run the script using test.cnf in the current directory.
# Redirect the verbose debugging output to debug.txt.
./iptables.pl -config=./test.cnf > debug.txt
#
# When you get this working, you can set it up for real operation by
# commenting out the 'echo "20011201000000" > dshield.cnt' line, 
# deleting dshield.cnf, changing the whereto variable in test.cnf to 
# be MAIL, and make sure that the email variables are correct.  Then
# create a crontab entry like
# 
# 10 4 * * * cd {directory}; ./iptables.pl -config=./test.cnf > debug.txt
#
# where {directory} is the name of the directory that iptables.pl is in.
#
# See README.txt for more detailed instructions
