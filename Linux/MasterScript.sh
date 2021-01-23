#!/bin/bash
#copy and paste the postfix configs
#updates
read -p "what is the user's name?" USER
echo "CLEANING PACKAGES"
apt-get update
apt-get autoremove
apt-get autoclean
apt-get update

read -p "Do you want to update packages? [y,n]" runupdates
if [ $runupdates == "y" ]
	then
		echo "UPDATING PACKAGES"
		apt-get upgrade -y
fi

read -p "Do you want to update system? [y,n]" systemupdate
if [ $systemupdate == "y" ]
	then
		echo "UPDATING SYSTEM"
		apt-get dist-upgrade -y
		apt-get install bash -y
fi

#deletingbadpackages
dpkg --get-selections | grep -v deinstall | cut -f1 > /home/$USER/Desktop/packages
#BadPackages="$(grep -e prelink -e talk -e slapd -e darkstat -e httpry -e ophcrack -e dos2unix -e snake -e john -e cain -e crunch medusa -e xinetd -e cowsay -e transmission -e rsh-server -e sendmail -e zenmap -e ksh -e nmap -e openswan -e hydra -e kismet -e freeciv -e minetest -e pyrit -e youtube-dl -e dsniff -e telnet -e nginx -e hashcat -e game -e finger -e keylog -e hping -e deluge -e binwalk -e aircrack -e nikto -e p0f -e acunetix -e metasploit -e wireshark -e snort -e backtrack -e inSSIDer -e KisMAC -e NetCop -e superscan -e angry -e truecrypt -e xprobe -e crypt -e nfs -e stunnel -e KeePass -e RainbowCrack -e Wfuzz -e Brutus -e L0phtCrack -e fgdump -e abel -e hping -e scapy -e netcat -e yersinia -e nemesis -e socat -e splunk -e nagios -e Ngrep -e ettercap -e EtherApe -e Tcpdump -e sqlmap -e sqlninja -e NetSparker -e BeEF -e Dradis -e Nessus -e OpenVAS -e Nipper -e Secunia -e Retina -e QualysGuard -e Nexpose /home/$USER/Desktop/packages)"
#apt-get purge $BadPackages --force-yes -y
apt-get purge tmux snap pinta knocker crunch lynis xprobe john hashcat binwalk sl john-data medusa hydra dsniff netcat-openbsd netcat-traditional traceroute telnet wireshark aircrack-ng pyrit zeitgeist nmap yersinia deluge httpry p0f dos2unix kismet transmission sendmail tightvncserver finger xinetd cain minetest tor moon-buggy dovecot rsh-server aisleriot hping3 freeciv darkstat nis sqlmap libaa-bin gdb skipfish extremetuxracer ninvaders freesweep nsnake bsdgames


read -p "ok, so these ppl will probably have some IRRELEVANT packages that scores when they are removed. Meld will run and compare the packages in the system to the default packages. Notice anything that is sus"
dpkg --get-selections | grep -v deinstall | cut -f1 > /home/$USER/Desktop/packages
chmod 777 /home/$USER/Desktop/packages
apt-get -y install meld
meld /home/$USER/Desktop/packages /home/$USER/Desktop/meld/cleanpackages.txt

read -p "OK, now the program will run an lschattr to list all the immutible files on the computer. Make sure to take notes"
lsattr -R / 2>/dev/null | grep -- "-i-"
read -p "open another root terminal and deal with the badboi files (like deleting them or changing permissions)"

#the thing that carries this script rn
apt-get install libpam-cracklib aide synaptic apparmor clamav auditd audispd-plugins rkhunter ufw libchicken-dev iptables-persistent chkrootkit meld curl silversearcher-ag --force-yes
read -p "Make sure the system account users and shells are correct with meld. Be VERY CAREFUL not to mess with users above uid 1000 and exceptions in the README"
meld /etc/passwd /home/$USER/Desktop/meld/passwd.txt
meld /etc/group /home/$USER/Desktop/meld/groups.txt
meld /home/$USER/.bashrc /home/$USER/Desktop/meld/bashrc.txt
meld /etc/skel/.bashrc /home/$USER/Desktop/meld/bashrc.txt
meld /etc/sudoers.d/README /home/$USER/Desktop/meld/sudoreadme.txt

echo "u want to chage users (y or n)"
read chagemece
if [[ $chagemece == "y" ]]
then
    y=$(awk -F':' '{ print $1}' /etc/passwd)
	declare -a y
	for x in ${y[@]}; do
		 #x="administrator"
		 chage -m 7 -M 90 -W 14 $x
	done
fi
if [[ $chagemece == "n" ]]
then
    echo "ok uncle"
fi
meld /etc/hosts /home/$USER/Desktop/meld/hosts.txt
meld /etc/sudoers /home/$USER/Desktop/meld/sudoers.txt
read -p "While you're at it, you might as well make sure the users and groups are authorized."
gedit /etc/passwd
gedit /etc/group
#packages
apt-get install gedit ufw iptables-persistent rsyslog auditd clamav gufw acct clamtk libpam-cracklib psad ntp debsums debsecan libpam-google-authenticator apparmor aide rkhunter vlock selinux-basics
read -p "ok, so these ppl will probably have some IRRELEVANT packages that scores when they are removed. Meld will run and compare the packages in the system to the default packages. Notice anything that is sus"
dpkg --get-selections | grep -v deinstall | cut -f1 > /home/$USER/Desktop/packages
chmod 777 /home/$USER/Desktop/packages
meld /home/$USER/Desktop/packages /home/$USER/Desktop/meld/cleanpackages.txt\
meld /home/$USER/Desktop/unattendedupgrades.txt /etc/apt/apt.conf.d/50unattended-upgrades
systemctl enable rsyslog
#permissions
chmod 755 /bin/nano
chmod 644 /bin/bzip2
chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny
chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow
chown root:root /etc/motd
chmod 644 /etc/motd
chown root:root /etc/issue.net
chmod 644 /etc/issue.net
/bin/chmod 644 /etc/passwd 
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
/bin/chmod 644 /etc/hosts.deny 
/bin/chmod 644 /etc/hosts.allow 
chmod 644 /etc/passwd /etc/group /etc/shells /etc/login.defs /etc/securetty /etc/hosts.deny /etc/hosts.allow
chown -R root /etc/*
chmod 0000 /etc/shadow /etc/gshadow
chmod 600 /etc/sysctl.conf
chmod 755 /etc
chmod 4700 /bin/su
chmod 755 /sbin/ifconfig
chmod 666 /dev/null /dev/tty /dev/console
chmod 600 /boot/grub/grub.cfg
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg
chmod 0700 /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.monthly/* /etc/cron.weekly/* 
#prediction 100
rm -rf /etc/password
#firewall
meld /etc/ufw/before.rules /home/$USER/Desktop/meld/ufwbeforerules.txt
ufw enable
iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
bash -c "sed -i '/IPV6/d' /etc/default/ufw && echo 'IPV6=no' >> /etc/default/ufw" 
###CRITICAL SERVICES###
#vsftpd
echo Is vsftpd a critical service?
read vsftpdservice
if [[ $vsftpdservice == "y" ]]
then
	apt-get -y install ftp vsftpd
	iptables -I INPUT -p tcp --dport 64000:65535 -j ACCEPT
	chmod 644 /etc/vsftpd.conf
	chown root:root /etc/vsftpd.conf
	meld /etc/vsftpd.conf /home/$USER/Desktop/meld/vsftpd.txt
	chmod 750 /srv/ftp
fi
if [[ $vsftpdservice == "n" ]]
then
	apt-get -y purge vsftpd
fi
#pure-ftpd
echo Is pure-ftpd a critical service?
read pureftpdservice
if [[ $pureftpdservice == "y" ]]
then
	apt-get -y install ftp pure-ftpd
	iptables -I INPUT -p tcp --dport 64000:65535 -j ACCEPT
	bash -c "echo '3' > /etc/pure-ftpd/conf/TLS"
	bash -c 'echo "HIGH:TLSv1.2:!TLSv1:!SSLv3:!SSLv2" > /etc/pure-ftpd/conf/TLSCipherSuite'
	bash -c "echo 'yes' > /etc/pure-ftpd/conf/Daemonize"
	bash -c "echo 'yes' > /etc/pure-ftpd/conf/VerboseLog"
	bash -c "echo 'yes' > /etc/pure-ftpd/conf/NoAnonymous"
	bash -c "echo 'yes' > /etc/pure-ftpd/conf/ChrootEveryone"
	bash -c "echo 'yes' > /etc/pure-ftpd/conf/IPV4Only"
	bash -c "echo 'yes' > /etc/pure-ftpd/conf/ProhibitDotFilesWrite"
	bash -c "echo 'no' > /etc/pure-ftpd/conf/AnonymousCanCreateDirs"
	bash -c "echo 'yes' > /etc/pure-ftpd/conf/AnonymousCantUpload"
	bash -c "echo 'no' > /etc/pure-ftpd/conf/AllowUserFXP"
	bash -c "echo 'no' > /etc/pure-ftpd/conf/AllowAnonymousFXP"
	bash -c "echo 'yes' > /etc/pure-ftpd/conf/PAMAuthentication"
	bash -c "echo 'no' > /etc/pure-ftpd/conf/AnonymousOnly"
	bash -c "echo 'no' > /etc/pure-ftpd/conf/DisplayDotFiles"
	bash -c "echo 'no' > /etc/pure-ftpd/conf/BrokenClientsCompatibility"
	bash -c "echo '10' > /etc/pure-ftpd/conf/MaxClientsNumber"
	bash -c "echo '5' > /etc/pure-ftpd/conf/MaxClientsPerIP"
	bash -c "echo 'ftp' > /etc/pure-ftpd/conf/SyslogFacility"
	bash -c "echo '1000' > /etc/pure-ftpd/conf/MinUID"
	bash -c "echo 'no' > /etc/pure-ftpd/conf/AutoRename"
	systemctl restart pure-ftpd
	chmod 750 /srv/ftp
	read -p "Also go to the pure-ftpd presentation and do the certificate generation stuff manually"
fi
if [[ $pureftpdservice == "n" ]]
then
	apt-get -y purge pure-ftpd
fi
#proftpd
echo Is proftpd a critical service?
read proftpdservice
if [[ $proftpdservice == "y" ]]
then
	apt-get -y install proftpd
	chown root:root /etc/proftpd/proftpd.conf
	chmod 644 /etc/proftpd/proftpd.conf
	meld /etc/proftpd/proftpd.conf /home/$USER/Desktop/meld/proftpd.txt
	systemctl restart proftpd
	chmod 750 /srv/ftp
fi
if [[ $proftpdservice == "n" ]]
then
	apt-get -y purge proftpd
fi
#samba
echo Is samba a critical service?
read sambaservice
if [[ $sambaservice == "y" ]]
then
	apt-get -y install samba smbclient
	chown -R root:root /etc/samba/*
	chmod 644 /etc/samba/smb.conf
	read -p "Ok, when melding the file make sure not to mess with the shares. Do that manually. Set the secure settings to the ones on the meld file as printers and stuff like that"
	meld /etc/samba/smb.conf /home/$USER/Desktop/meld/smbconf.txt
fi
if [[ $sambaservice == "n" ]]
then
	apt-get -y purge samba smbclient
fi

echo Is snmp a critical service?
read snmpservice
if [[ $snmpservice == "y" ]]
then
  apt-get purge snmp
fi

#ssh
echo Is ssh a critical service?
read sshservice
if [[ $sshservice == "y" ]]
then
	apt-get -y install ssh openssh-server openssh-client openssh-sftp-server fail2ban
	chmod 644 /etc/ssh/sshd_config
	chown root /etc/ssh/sshd_config
	meld /etc/ssh/sshd_config /home/$USER/Desktop/meld/sshconfig.txt
	cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
	cp /home/$USER/Desktop/meld/sshfail2ban.txt /etc/fail2ban/jail.local
	systemctl restart ssh
fi
if [[ $sshservice == "n" ]]
then
	apt-get -y purge ssh openssh-server openssh-client openssh-sftp-server
fi
#apache2
echo Is apache2 a critical service?
read apache2service
if [[ $apache2service == "y" ]]
then
	apt-get -y install apache2
	apt-get -y install libapache2-modsecurity
	apt-get -y install libapache2-mod-evasive
	apt-get -y install libapache2-mod-qos
	apt-get -y install libapache2-mod-spamhaus
	apt-get -y install libapache2-modsecurity2
	a2enmod ssl
	bash -c "sed -i '/ServerSignature/d' /etc/apache2/conf-available/security.conf && echo 'ServerSignature Off' >> /etc/apache2/conf-available/security.conf"
	bash -c "sed -i '/ServerTokens/d' /etc/apache2/conf-available/security.conf && echo 'ServerTokens Prod' >> /etc/apache2/conf-available/security.conf"
	bash -c "sed -i '/TraceEnable/d' /etc/apache2/conf-available/security.conf && echo 'TraceEnable Off' >> /etc/apache2/conf-available/security.conf"
	bash -c "sed -i '/Header set/d' /etc/apache2/conf-available/security.conf && echo 'Header set X-Frame-Options: \"sameorigin\"' >> /etc/apache2/conf-available/security.conf"
	echo "Header set X-Content-Type-Options: nosniff" >> /etc/apache2/conf-available/security.conf
	echo "Header set X-XSS-Protection: 1; mode=block" >> /etc/apache2/conf-available/security.conf
	chown -R root:root /etc/apache2/*
	chmod 644 /etc/apache2/apache2.conf
	chmod 0755 /usr/sbin/apache2
  meld /etc/apache2/apache2.conf /home/$USER/Desktop/meld/apache2.txt
	meld /etc/apache2/mods-available/ssl.conf /home/$USER/Desktop/meld/apachesslconf.txt
	mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
	meld /etc/modsecurity/modsecurity.conf /home/$USER/Desktop/meld/a2modsecurity.txt
	a2enmod security2
	a2enmod headers
	systemctl restart apache2
fi
if [[ $apache2service == "n" ]]
then
	apt-get -y purge apache2
	apt-get -y purge apache2-bin
fi
#nginx
echo Is nginx a critical service?
read nginxservice
if [[ $nginxservice == "y" ]]
then
	apt-get -y install nginx
	meld /etc/nginx/nginx.conf /home/$USER/Desktop/meld/nginx.txt
fi
if [[ $nginxservice == "n" ]]
then
	apt-get -y purge nginx
fi
#bind9
echo Is bind9 a critical service?
read bind9service
if [[ $bind9service == "y" ]]
then
	apt-get -y install bind9 bind9-host bind9utils bind9-doc
	meld /etc/bind/named.conf /home/$USER/Desktop/meld/bind9namedconf.txt
	meld /etc/bind/named.conf.local /home/$USER/Desktop/meld/bind9namedconflocal.txt
	meld /etc/bind/named.conf.default-zones /home/$USER/Desktop/meld/bind9namedconfdefault-zones.txt
	meld /etc/bind/named.conf.options /home/$USER/Desktop/meld/bind9namedconfoptions.txt
	cat > /etc/bind/named.conf.log
	meld /etc/bind/named.conf.log /home/$USER/Desktop/meld/bind9namedconflog.txt
	touch /var/log/update_debug.log
	touch /var/log/security_info.log
	touch /var/log/bind.log
	chown bind:root /var/log/update_debug.log /var/log/security_info.log /var/log/bind.log
	chmod 775 /var/log/update_debug.log /var/log/security_info.log /var/log/bind.log
	chmod 644 /etc/bind/named.conf.log
	read -p "you may have to edit /etc/apparmor.d/usr.sbin.named, adding '/var/log/update_debug.log rw,', '/var/log/security_info.log rw,', and '/var/log/bind.log rw,'"
	systemctl restart bind9
fi
if [[ $bind9service == "n" ]]
then
	apt-get -y purge bind9 bind9-host bind9utils bind9-doc
fi
#php
echo Is php a critical service?
read phpservice
if [[ $phpservice == "y" ]]
then
	apt-get -y install php php7.0
	chown -r root:root /etc/php/*
	cp /home/$USER/Desktop/meld/php.txt /etc/php/7.0/apache2/php.ini
	cp /home/$USER/Desktop/meld/php.txt /etc/php/7.0/cli/php.ini
	chmod 644 /etc/php/7.0/apache2/php.ini
	chmod 644 /etc/php/7.0/cli/php.ini
	chown root /etc/php/7.0/apache2/php.ini
	chown root /etc/php/7.0/cli/php.ini
	find /var/www/html ! -name 'index.html' -type f -exec rm -f {} +
fi
if [[ $phpservice == "n" ]]
then
	apt-get -y purge php php5 php7.0
fi
#mysql
echo Is mysql a critical service?
read mysqlservice
if [[ $mysqlservice == "y" ]]
then
	apt-get -y install mysql-server
	mysql_secure_installation
	chmod 644 /etc/mysql/my.cnf
	chmod 700 /var/lib/mysql
	chown mysql:mysql /var/lib/mysql
	meld /etc/mysql/my.cnf /home/$USER/Desktop/meld/mysql.txt
	chown root /usr/bin/mysqlpump
	systemctl restart mysql
fi
if [[ $mysqlservice == "n" ]]
then
	apt-get -y purge mysql-server
fi
#sysctl
meld /etc/sysctl.conf /home/$USER/Desktop/meld/sysctl.txt
sysctl -p /etc/sysctl.conf
#auditing
meld /etc/audit/audit.rules /home/$USER/Desktop/meld/auditrules.txt
meld /etc/audit/auditd.conf /home/$USER/Desktop/meld/auditconf.txt
bash -c "sed -i '/active/d' /etc/audisp/plugins.d/syslog.conf && echo 'active = yes' >> /etc/audisp/plugins.d/syslog.conf"
bash -c "sed -i '/active/d' /etc/audisp/plugins.d/af_unix.conf && echo 'active = yes' >> /etc/audisp/plugins.d/af_unix.conf"
touch /etc/audisp/plugins.d/au-remote.conf
bash -c "sed -i '/active/d' /etc/audisp/plugins.d/au-remote.conf && echo 'active = yes' >> /etc/audisp/plugins.d/au-remote.conf"
service auditd restart
#removing services
bash -c 'echo "manual" > /etc/init.d/avahi-daemon.override'
bash -c 'echo "manual" > /etc/init.d/cups.override'
bash -c 'echo "manual" > /etc/init/avahi-daemon.override'
bash -c 'echo "manual" > /etc/init/cups.override'
bash -c 'echo "manual" > /etc/init/modemmanager.override'
bash -c 'echo "manual" > /etc/init.d/modemmanager.override'
bash -c 'sed -i "/InitiallyPowered/d" /etc/bluetooth/main.conf'
bash -c 'echo "InitiallyPowered = false" >> /etc/bluetooth/main.conf'
bash -c 'echo "InitiallyPowered=false" >> /etc/bluetooth/main.conf'
bash -c "sed -i '/enabled/d' /etc/default/apport && echo 'enabled = 0' >> /etc/default/apport"
bash -c "sed -i '/ENABLED/d' /etc/default/irqbalance && echo 'ENABLED = \"0\"' >> /etc/default/irqbalance"
cp /home/$USER/Desktop/meld/modprobe.txt /etc/modprobe.conf
cp /home/$USER/Desktop/meld/modprobe.txt /etc/modprobe.d/modprobe.conf
cp /home/$USER/Desktop/meld/modprobe.txt /etc/modprobe.d/CIS.conf
bash -c 'echo "install bluetooth /bin/true" > /etc/modprobe.d/bluetooth.conf'
bash -c 'echo "install net-pf-31 /bin/true" >> /etc/modprobe.d/bluetooth.conf'
bash -c 'echo "install usb-storage /bin/true" > /etc/modprobe.d/usb-storage.conf'
bash -c 'echo "install uas /bin/true" >> /etc/modprobe.d/usb-storage.conf'
bash -c 'echo "install appletalk /bin/true" > /etc/modprobe.d/appletalk.conf'
bash -c 'echo "install sctp /bin/true" > /etc/modprobe.d/sctp.conf'
bash -c 'echo "install dccp /bin/true" > /etc/modprobe.d/dccp.conf'
bash -c 'echo "install dccp_ipv4 /bin/true" > /etc/modprobe.d/dccp_ipv4.conf'
bash -c 'echo "install dccp_ipv6 /bin/true" > /etc/modprobe.d/dccp_ipv6.conf'
bash -c 'echo "install rds /bin/true" > /etc/modprobe.d/rds.conf'
bash -c 'echo "install tipc /bin/true" > /etc/modprobe.d/tipc.conf'
bash -c 'echo "install vfat /bin/true" > /etc/modprobe.d/vfat.conf'
bash -c 'echo "install uas /bin/true" > /etc/modprobe.d/uas.conf'
bash -c 'echo "install cramfs /bin/true" > /etc/modprobe.d/cramfs.conf'
bash -c 'echo "install freevxfs /bin/true" > /etc/modprobe.d/freevxfs.conf'
bash -c 'echo "install jffs2 /bin/true" > /etc/modprobe.d/jffs2.conf'
bash -c 'echo "install hfs /bin/true" > /etc/modprobe.d/hfs.conf'
bash -c 'echo "install gfs2 /bin/true" > /etc/modprobe.d/gfs2.conf'
bash -c 'echo "install hfsplus /bin/true" > /etc/modprobe.d/hfsplus.conf'
bash -c 'echo "install squashfs /bin/true" > /etc/modprobe.d/squashfs.conf'
bash -c 'echo "install udf /bin/true" > /etc/modprobe.d/udf.conf'
bash -c 'echo "install net-pf-31 /bin/true" > /etc/modprobe.d/net-pf-31.conf'
#hard core dumps and maxlogins
bash -c 'echo "* hard core 0" >> /etc/security/limits.conf'
bash -c 'echo "* hard maxlogins 10" >> /etc/security/limits.conf'
rm /etc/security/console.perms
#resolv.conf
chown root /etc/resolv.conf
chgrp root /etc/resolv.conf
chmod 0644 /run/resolvconf/resolv.conf
chmod 0644 /etc/resolv.conf
chmod 0644 /run/resolvconf/resolv.conf
acledit /etc/resolv.conf
#umask
bash -c 'echo "umask 077" >> /etc/profile'
bash -c 'sed -i "/umask/d" /lib/lsb/init-functions && echo "umask 022" >> /lib/lsb/init-functions'
bash -c 'echo "umask 077" >> /etc/bash.bashrc'
bash -c 'echo "unmask 077" >> /etc/csh.cshrc'
#/etc/issue stig
bash -c 'echo "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." > /etc/issue'
bash -c 'echo "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." > /etc/issue.net'
#shells
read -p "open the shells and take notes"
meld /etc/shells /home/$USER/Desktop/meld/shells.txt
bash -c 'echo "/bin/sh" > /etc/shells'
bash -c 'echo "/bin/bash" >> /etc/shells'
bash -c 'echo "/bin/dash" >> /etc/shells'
bash -c 'echo "/bin/rbash" >> /etc/shells'
#guest (kind of scuffed)
bash -c 'echo """[Seat:*]
greeter-session=unity-greeter
allow-guest=false
greeter-show-remote-login=false
greeter-hide-users=true
greeter-show-manual-login=true
""" > /etc/lightdm/lightdm.conf'
bash -c 'echo """[Seat:*]
greeter-session=unity-greeter
allow-guest=false
greeter-show-remote-login=false
greeter-hide-users=true
greeter-show-manual-login=true
""" > /usr/share/lightdm/lightdm.conf.d/50-unity-greeter.conf'
bash -c 'echo """[Seat:*]
user-session=ubuntu
allow-guest=false
greeter-show-remote-login=false
greeter-hide-users=true
greeter-show-manual-login=true
""" > /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf'
bash -c 'echo """[LightDM]
backup-logs=false
allow-guest=false
greeter-show-remote-login=false
greeter-hide-users=true
greeter-show-manual-login=true
""" > /usr/share/lightdm/lightdm.conf.d/50-disable-log-backup.conf'
bash -c 'echo """[Seat:*]
greeter-wrapper=/usr/lib/lightdm/lightdm-greeter-session
allow-guest=false
greeter-show-remote-login=false
greeter-hide-users=true
greeter-show-manual-login=true
""" > /usr/share/lightdm/lightdm.conf.d/50-greeter-wrapper.conf'
bash -c 'echo """[Seat:*]
guest-wrapper=/usr/lib/lightdm/lightdm-guest-session
allow-guest=false
greeter-show-remote-login=false
greeter-hide-users=true
greeter-show-manual-login=true
""" > /usr/share/lightdm/lightdm.conf.d/50-guest-wrapper.conf'
bash -c 'echo """[Seat:*]
xserver-command=X -core
allow-guest=false
greeter-show-remote-login=false
greeter-hide-users=true
greeter-show-manual-login=true
""" > /usr/share/lightdm/lightdm.conf.d/50-xserver-command.conf'
#nospoof on
bash -c 'echo "order bind,hosts" > /etc/host.conf'
bash -c 'echo "multi on" >> /etc/host.conf'
bash -c 'echo "nospoof on" >> /etc/host.conf'
#login.defs
cp /home/$USER/Desktop/meld/logindefs.txt /etc/login.defs 
#pam
read -p "We're about to do pam and resolv, I would recommend not editing anything yet and coming back to this later(maybe fix resolv.conf if its obvious)"
meld /etc/pam.d/common-password /home/$USER/Desktop/meld/common-password.txt
meld /etc/pam.d/common-auth /home/$USER/Desktop/meld/common-auth.txt
meld /etc/pam.d/common-account /home/$USER/Desktop/meld/common-account.txt
#meld /etc/pam.d/login /home/$USER/Desktop/meld/pamlogin.txt
meld /etc/pam.d/su /home/$USER/Desktop/meld/pamsu.txt
meld /etc/resolv.conf /home/$USER/Desktop/meld/resolveconf.txt

#stigs
find /etc/sudoers.d ! -name 'README' -type f -exec rm -f {} +
rm /var/spool/cron/crontabs/*
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 23 -j DROP         #Block Telnet
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 2049 -j DROP       #Block NFS
iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 2049 -j DROP       #Block NFS
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 6000:6009 -j DROP  #Block X-Windows
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 7100 -j DROP       #Block X-Windows font server
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 515 -j DROP        #Block printer port
iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 515 -j DROP        #Block printer port
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 111 -j DROP        #Block Sun rpc/NFS
iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 111 -j DROP        #Block Sun rpc/NFS
iptables -A INPUT -p all -s localhost  -i eth0 -j DROP            #Deny outside packets from internet which claim to be from your loopback interface.
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

systemctl mask ctrl-alt-del.target
systemctl enable auditd
systemctl disable avahi-daemon
systemctl disable isc-dhcp-server
systemctl disable isc-dhcp-server6
systemctl disable nfs-kernel-server
systemctl disable rpcbind
echo "" > /etc/issue
sed -i '/SELINUX=/d' /etc/selinux/config && echo "SELINUX=enforcing" >> /etc/selinux/config
sed -i '/SELINUXTYPE=/d' /etc/selinux/config && echo "SELINUXTYPE=ubuntu" >> /etc/selinux/config
echo "0 5 * * * root /usr/sbin/aide --check" >> /etc/crontab
systemctl disable autofs
echo "ALL: ALL" >> /etc/hosts.deny
bash -c "sed -i '/RSYNC_ENABLE/d' /etc/default/useradd && echo 'RSYNC_ENABLE=false
' >> /etc/default/useradd"
systemctl disable avahi-daemon
systemctl disable cups
cp /home/$USER/Desktop/meld/pwquality.txt /etc/security/pwquality.conf
bash -c "echo 'exit 0' > /etc/rc.local"
bash -c "sed -i '/INACTIVE/d' /etc/default/useradd && echo 'INACTIVE=35' >> /etc/default/useradd"
bash -c "sed -i '/enable_krb5/d' /etc/audisp/udisp-remote.conf && echo 'enable_krb5 yes' >> /etc/audisp/audisp-remote.conf"
bash -c "echo 'auth,authpriv.* /var/log/auth.log' >> /etc/rsyslog.d/50-default.conf"
bash -c "echo 'daemon.notice /var/log/messages' >> /etc/rsyslog.d/50-default.conf"
bash -c "echo 'exec /usr/bin/logger -p security.info \"Ctrl-Alt-Delete pressed\"' >> /etc/init/ctrl-alt-delete.override"
bash -c "sed -i '/exec shutdown -r now/d' /etc/init/control-alt-delete.conf"
touch /etc/inittab
echo "id:3:initdefault:" >> /etc/inittab
touch /etc/profile.d/autologout.sh
bash -c 'echo """TMOUT=900
readonly TMOUT
export TMOUT""" >> /etc/profile.d/autologout.sh'
bash -c "sed -i '/SILENTREPORTS/d' /etc/default/aide && echo 'SILENTREPORTS=no' >> /etc/default/aide" 
bash -c "echo '-:ALL EXCEPT users :ALL' >> /etc/security/access.conf"
#psad
bash -c "sed -i '/ENABLE_AUTO_IDS/d' /etc/psad/psad.conf && echo 'ENABLE_AUTO_IDS             Y;' >> /etc/psad/psad.conf"
bash -c "sed -i '/ENABLE_AUTO_IDS_EMAILS/d' /etc/psad/psad.conf && echo 'ENABLE_AUTO_IDS_EMAILS             Y;' >> /etc/psad/psad.conf"
#cron
find /etc/anacrontab -type f -not -name .htaccess -printf "\n%p\n" -exec cat {} \; > /home/$USER/Desktop/cronstuff.txt
find /etc/cron.d -type f -not -name .htaccess -printf "\n%p\n" -exec cat {} \; >> /home/$USER/Desktop/cronstuff.txt
find /etc/cron.daily -type f -not -name .htaccess -printf "\n%p\n" -exec cat {} \; >> /home/$USER/Desktop/cronstuff.txt
find /etc/cron.hourly -type f -not -name .htaccess -printf "\n%p\n" -exec cat {} \; >> /home/$USER/Desktop/cronstuff.txt
find /etc/cron.monthly -type f -not -name .htaccess -printf "\n%p\n" -exec cat {} \; >> /home/$USER/Desktop/cronstuff.txt
find /etc/crontab -type f -not -name .htaccess -printf "\n%p\n" -exec cat {} \; >> /home/$USER/Desktop/cronstuff.txt
find /etc/cron.weekly -type f -not -name .htaccess -printf "\n%p\n" -exec cat {} \; >> /home/$USER/Desktop/cronstuff.txt
read -p "ok kids, listen up. Compare the cronstuff with clean cron. Doing things here won't do anything. So do it manually once you notice the differences/malicious stuff."
meld /home/$USER/Desktop/cronstuff.txt /home/$USER/Desktop/meld/cleancron.txt
ls -la /usr/sbin >> /home/$USER/Desktop/allscriptshere.txt
chmod 777 /home/$USER/Desktop/allscriptshere.txt
meld /home/$USER/Desktop/defaultscripts.txt /home/$USER/Desktop/meld/allscriptshere.txt
systemctl enable cron
systemctl enable anacron
bash -c "echo '05 4 * * * root /usr/sbin/aide --check' >> /etc/crontab"
bash -c "sed -i '/GRUB_CMDLINE_LINUX=/c\GRUB_CMDLINE_LINUX=\"audit=1 apparmor=1 security=apparmor\"' /etc/default/grub"
update-grub
#apparmor
aa-enforce /etc/apparmor.d/*
#Secure shared memory
bash -c "echo 'tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0' >> /etc/fstab"
#Secure /tmp
dd if=/dev/zero of=/usr/tmpDSK bs=1024 count=1024000
cp -Rpf /tmp /tmpbackup
mount -t tmpfs -o loop,noexec,nosuid,rw /usr/tmpDSK /tmp
chmod 1777 /tmp
cp -Rpf /tmpbackup/ /tmp/
rm -rf /tmpbackup/
bash -c "echo '/usr/tmpDSK /tmp tmpfs loop,nosuid,noexec,rw 0 0' >> /etc/fstab"
mount -o remount /tmp
#delete media files
read -p "If you couldn'r find any, then do you want to mass delete all of them? WARNING: THIS WILL LITERALLY TURN YOUR IMAGE INTO NO GUI [y,n]" MassDelete
if [ $MassDelete == "y" ]
	then
	    chattr -i -R /
		find / -type f -iname "*.mp3" -delete -o -iname "*.webm" -delete -o -iname "*.7z" -delete -o -iname "*.mkv" -delete -o -iname "*.flv" -delete -o -iname "*.vob" -delete -o -iname "*.ogv" -delete -o -iname "*.ogg" -delete -o -iname "*.drc" -delete -o -iname "*.gif" -delete -o -iname "*.gifv" -delete -o -iname "*.mng" -delete -o -iname "*.avi" -delete -o -iname "*.mov" -delete -o -iname "*.qt" -delete -o -iname "*.wmv" -delete -o -iname "*.yuv" -delete -o -iname "*.rm" -delete -o -iname "*.rmvb" -delete -o -iname "*.asf" -delete -o -iname "*.amv" -delete -o -iname "*.mp4" -delete -o -iname "*.m4p" -delete -o -iname "*.m4v" -delete -o -iname "*.mpg" -delete -o -iname "*.mp2" -delete -o -iname "*.mpeg" -delete -o -iname "*.mpe" -delete -o -iname "*.mpv" -delete -o -iname "*.svi" -delete -o -iname "*.3gp" -delete -o -iname "*.3g2" -delete -o -iname "*.mxf" -delete -o -iname "*.roq" -delete -o -iname "*.nsf" -delete -o -iname "*.flv" -delete -o -iname "*.f4v" -delete -o -iname "*.f4p" -delete -o -iname "*.f4a" -delete -o -iname "*.f4b" -delete -o -iname "*.aa" -delete -o -iname "*.aac" -delete -o -iname "*.aax" -delete -o -iname "*.act" -delete -o -iname "*.aiff" -delete -o -iname "*.amr" -delete -o -iname "*.ape" -delete -o -iname "*.au" -delete -o -iname "*.awb" -delete -o -iname "*.dct" -delete -o -iname "*.dss" -delete -o -iname "*.dvf" -delete -o -iname "*.flac" -delete -o -iname "*.gsm" -delete -o -iname "*.iklax," -delete -o -iname "*.ivs" -delete -o -iname "*.m4a" -delete -o -iname "*.m4b" -delete -o -iname "*.mmf" -delete -o -iname "*.mpc" -delete -o -iname "*.msv" -delete -o -iname "*.oga" -delete -o -iname "*.opus" -delete -o -iname "*.ra" -delete -o -iname "*.raw" -delete -o -iname "*.sln" -delete -o -iname "*.tta" -delete -o -iname "*.vox" -delete -o -iname "*.wav" -delete -o -iname "*.wma" -delete -o -iname "*.wv" -delete -o -iname "*.jpeg" -delete -o -iname "*.jpg" -delete -o -iname "*.tif" -delete -o -iname "*.tiff" -delete -o -iname "*.gif" -delete -o -iname "*.bmp" -delete -o -iname "*.png" -delete -o -iname "*.pbm" -delete -o -iname "*.pgm" -delete -o -iname "*.ppm" -delete -o -iname "*.pnm" -delete -o -iname "*.webp" -delete -o -iname "*.hdr" -delete -o -iname "*.bpg" -delete -o -iname "*.ico" -delete -o -iname "*.img" -delete -o -iname "*.aup" -delete -o -iname "*.dmg" -delete -o -iname "*.xlsx" -delete -o -iname "*.rhosts" -delete -o -iname "*.hosts.equiv" -delete
		fi

#Secure /var/tmp
mv /var/tmp /var/tmpold
ln -s /tmp /var/tmp
cp -prf /var/tmpold/ /tmp/
#tty
bash -c "sed -i '/tty/d' /etc/securetty && echo 'tty1' >> /etc/securetty"

read -p "these mofos probably hid a nonattributable file. So, type in the command, 'lsattr -R | grep +i' in the / directory to find them"

#end with locking out root
passwd -l root
usermod -g 0 root
