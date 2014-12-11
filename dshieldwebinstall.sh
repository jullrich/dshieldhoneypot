#!/bin/bash
#10 December 2014
# Shell script to install dshield web application honeypot
# Will prompt user for install path and username and password - 
# password will be hashed on the end of the script

# Gotta run as sudo
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
    echo "you need to install 'git'. Please run 'apt-get git' as root."
    exit
fi

ask() {
    # http://djm.me/ask
    while true; do
 
        if [ "${2:-}" = "Y" ]; then
            prompt="Y/n"
            default=Y
        elif [ "${2:-}" = "N" ]; then
            prompt="y/N"
            default=N
        else
            prompt="y/n"
            default=
        fi
 
        # Ask the question
        read -p "$1 [$prompt] " REPLY
 
        # Default?
        if [ -z "$REPLY" ]; then
            REPLY=$default
        fi
 
        # Check if the reply is valid
        case "$REPLY" in
            Y*|y*) return 0 ;;
            N*|n*) return 1 ;;
        esac
 
    done
}

get_dshieldCreds(){
	read "Please enter dshield account username: " duser
	read -s -p "Password: " dpassw 
        echo "[config]" > config.local
        echo "username=$duser" >> config.local
        echo "hashpassword=$dpassw" >> config.local
}

unzip_tar() {
    wget 'https://webhoneypot.googlecode.com/files/webhoneypot.0.1.r123.tgz'
    tar -xvf webhoneypot.0.1.r123.tgz -C $arg1/
}

get_distribution_type() {
    local dtype
    # Assume unknown
    dtype="unknown"

    # First test against Fedora / RHEL / CentOS / generic Redhat derivative
    if [ -r /etc/rc.d/init.d/functions ]; then
        source /etc/rc.d/init.d/functions
        [ zz`type -t passed 2>/dev/null` == "zzfunction" ] && dtype="redhat"

    # Then test against SUSE (must be after Redhat,
    # I've seen rc.status on Ubuntu I think? TODO: Recheck that)
    elif [ -r /etc/rc.status ]; then
        source /etc/rc.status
        [ zz`type -t rc_reset 2>/dev/null` == "zzfunction" ] && dtype="suse"

    # Then test against Debian, Ubuntu and friends
    elif [ -r /lib/lsb/init-functions ]; then
        source /lib/lsb/init-functions
        [ zz`type -t log_begin_msg 2>/dev/null` == "zzfunction" ] && dtype="debian"

    # Then test against Gentoo
    elif [ -r /etc/init.d/functions.sh ]; then
		source /etc/init.d/functions.sh
		[ zz`type -t ebegin 2>/dev/null` == "zzfunction" ] && dtype="gentoo"

    
    # For Slackware we currently just test if /etc/slackware-version exists
    # and isn't empty (TODO: Find a better way :)
    elif [ -s /etc/slackware-version ]; then
        dtype="slackware"
    fi
    echo $dtype
}
echo "Hello,this script will install the dshield honeypot for you."

if ask "Do you have credentials from https://www.dshield.org? (Y/n)" Y; then
	get_dshieldCreds
else
        echo "OK you will need to get those to provide data to dshield, however you can still use this as a personal honeypot."
fi
	
if ask "Is this a dedicated server for the webhoneypot(no other web applications)? (Y/n)" Y; then
    installdir="/opt"
else
    read -p "OK, what is the name of the virtual host?" host
    installdir="/var/www/$host"
fi    

read -p "Please specify an installation directory. ($installdir)" dir
if [ $installdir == "" ]; then
    dir = "/opt"
    echo "Installing dshield webhoneypot in $installdir"
    unzip_tar $installdir
else 
    if [ -d $installdir ]; then
        echo "Installing dshield webhoneypot in $installdir"
	unzip_tar $installdir
    else
        if ask "The directory does not exist would you like to create it? (Y/n)" Y; then
            echo "Creating Directory $installdir"
	    sudo mkdir $installdir
            unzip_tar $installdir
        else
	    echo "ok exiting, try again when your ready."
	    exit 1
	fi		
    fi
fi

echo "Verifying dependencies, commands will be run as sudo."
if [ $(get_distribution_type) == "debian" ]; then
	sudo apt-get update
        sudo apt-get install apache2 php5 php5-mysql mysql-client mysql-server
elif [ $(get_distribution_type) == "redhat" ]; then
	sudo sh -c "yum install httpd httpd-devel mysql mysql-server mysql-devel php php-mysql php-common php-gd php-mbstring php-mcrypt php-devel php-xml -y; service mysqld start && mysql_secure_installation && service mysqld restart && service httpd start && chkconfig httpd on && chkconfig mysqld on &&iptables -I INPUT -p tcp -m tcp --dport 80 -j ACCEPT && /etc/init.d/iptables save"
    elif [ $(get_distribution_type) == "suse" ]; then
    sudo zypper install apache2 php5 php5-mysql apache2-mod_php5 mysql mysql-client mysql-community-server \
           php5-soap php5-mbstring php5-gd php5-mcrypt php5-ldap php5-curl php5-xml php5-soap php5-cli
elif [ $(get_distribution_type) == "gentoo" ]; then
    echo "dev-lang/php xml" >> /etc/portage/package.use
    emerge -av dev-lang/php
    /etc/init.d/apache2 restart
elif [ $(get_distribution_type) == "slackware" ]; then
    slackpkg install  httpd
    httpd  -k  start
else
    if ask "Can't seem to find linux version, would you like to continue with installation? (y/N)" N; then
    	break
    fi
fi

if [ -d config.local ]; then
    sudo mv -f config.local $dir/etc/config.local
fi

#Find out who's running the web app
mv -f /opt/webhoneypot/html/index.php /var/www/html/index.php
currentuser=$(whoami)
apacherunning=$(ps aux | grep apache)
apacheuser=$($apacherunning | awk '{ print $1 }' | sort | uniq | grep -v root | grep -v $currentuser)
