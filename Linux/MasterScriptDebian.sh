#!/bin/bash
echo "what is the name for the main account user?"
read USER
chown root:root /run/gdm
chmod 1777 /run/gdm
chown root:root /run/gdm3
chmod 1777 /run/gdm3
apt-get purge gdm-guest-session
bash -c 'echo "gdm: ALL" >> /etc/hosts.deny'
bash -c 'sed -i "/banner-message-enable/d" /etc/gdm3/greeter.dconf-defaults && echo "banner-message-enable=true" >> /etc/gdm3/greeter.dconf-defaults'
echo "In /etc/gdm3/daemon.conf, make sure under [security] to add 'DisallowTcp = true' and 'RelaxPermissions=0'"
meld /etc/gdm3/daemon.conf /home/$USER/Desktop/meld/daemonconf.txt
#debian Stigs
systemctl enable tmp.mount
mount -o remount,nodev /tmp
mount -o remount,nosuid /tmp
mount -o remount,noexec /tmp
mount --bind /tmp /var/tmp
echo "/tmp /var/tmp none bind 0 0" >> /etc/fstab
mount -o remount,nodev /home
mount -o remount,nodev /run/shm 
mount -o remount,nosuid /run/shm
mount -o remount,noexec /run/shm
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
update-rc.d autofs disable
read -p "enter your password for security"
grub-mkpasswd-pbkdf2
/usr/sbin/prelink -ua
apt-get purge prelink
sed -i '/shell/d' /etc/inetd.conf
sed -i '/login/d' /etc/inetd.conf
sed -i '/exec/d' /etc/inetd.conf
sed -i '/talk/d' /etc/inetd.conf
sed -i '/ntalk/d' /etc/inetd.conf
sed -i '/telnet/d' /etc/inetd.conf
sed -i '/tftp/d' /etc/inetd.conf
update-rc.d xinetd disable
sed -i '/chargen/d' /etc/inetd.conf
sed -i '/daytime/d' /etc/inetd.conf
sed -i '/echo/d' /etc/inetd.conf
sed -i '/discard/d' /etc/inetd.conf
sed -i '/time/d' /etc/inetd.conf
update-rc.d isc-dhcp-server disable
update-rc.d rpcbind disable
update-rc.d nfs-kernel-server disable
update-rc.d squid3 disable
update-rc.d snmpd disable
#sed -i '/dc_local_interfaces/d' /etc/exim4/update-exim4.conf.conf && echo "dc_local_interfaces='127.0.0.1 ; ::1'" /etc/exim4/update-exim4.conf.conf
service exim4 reload
update-rc.d netfilter-persistent enable
sed -i '/banner-message-enable/d' /etc/gdm3/greeter.dconf-defaults && echo "banner-message-enable" >> /etc/gdm3/greeter.dconf-defaults