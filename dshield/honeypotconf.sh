#!/bin/sh

fd=0
if [ ! -t "$fd" ]; then
   echo "This script needs to run on an interactive shell."
   exit
fi

if [ `whoami` != "root" ]; then
   echo "you need to run this script as root (e.g. using 'sudo') "
   exit
fi
if [ ! -x /usr/bin/dialog ] ; then
   echo "you need to install 'dialog'. Please run 'apt-get dialog' as root."
   exit
fi
if [ ! -x /usr/bin/git ] ; then
   echo "you need to install 'dialog'. Please run 'apt-get dialog' as root."
   exit
fi

useradd dshield
mkdir /home/dshield
sudo cp /etc/skel/* /home/dshield/
chmod 775 /home/dshield
find -type f /home/dshield -exec chown dshield:dshield {} \;
cd /home/dshield
sudo -u dshield git clone https://github.com/jullrich/dshieldhoneypot

authkey=$(dialog  --output-fd 1 --title "DShield Sensor Configuration" --inputbox "Enter your DShield Authentication key\n(From dshield.org/myinfo.html#report)" 10 50)

parts=$(dialog --output-fd 1 --title "DShield Sensor Components" --checklist "Select enabled sensors" 15 50 5 1 "iptables logs (IPv4)" on 2 "ip6tables logs (IPv6)" on 3 "Web Honeypot" on 4 "404 Logs" on  5 "Kippo Logs" on)

if echo $parts | grep -q '[12]' ; then
    log=$(dialog --output-fd 1 --title "iptables Configuration IPv4" --inputbox "Firewall Log File" 10 50 /var/log/ufw.log)
fi




