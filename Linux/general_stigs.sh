#!/bin/bash
#if [ $UID != 0 ]; then
       $echo "shut up boomer"
#	exit 0;
#else	
apt-get install sed

cat /etc/lsb-release > /dev/null | grep "Ubuntu" #stig #1
/usr/lib/update-notifier/apt-check --human-readable > takenote.txt
gsettings set org.gnome.desktop.lock-enabled tru
dpkg -l | grep "vlock"
	if [$? -eq 0]; then
		echo "already installed vlock" >> takenote.txt
		exit 0
	else
		sudo apt-get install vlock -y
		exit 0
	fi
grep -Pzl '(?s)TMOUT=900.*\n.*readonly TMOUT' /etc/profile.d/autologout.sh
grep maxlogins /etc/security/limits.conf
sed -i 's/^* hard maxlogins.*/* hard maxlogins 10' /etc/security/limits.conf
passwd -l root
sed -i 's/^# ucredit.*# ucredit=-1' /etc/security/pwquality.conf
sed -i 's/^# lcredit.*# lcredit=-1' /etc/security/pwquality.conf
sed -i 's/^# dcredit.*# dcredit=-1' /etc/security/pwquality.conf
sed -i 's/^# ocredit.*# ocredit=-1' /etc/security/pwquality.conf
sed -i 's/^# difok.*# difok=1' /etc/security/pwquality.conf
sed -i 's/ENCRYPT_METHOD.*ENCRYPT_METHOD SHA512' /etc/login.defs
sed -i 's/password [success=1 default=ignore].*password [success=1 default=ignore] pam_unix.so obscure sha512 remember=5 rounds=5000' /etc/pam.d/common-password
chage -I -1 -M 99999 root

sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/g' /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/g' /etc/login.defs
sed -i 's/minlen.*/minlen=15/g' /etc/security/pwquality.conf
sed '/nullok/d' /etc/pam.d
sed -i 's/dictcheck.*/dictcheck=1/g' /etc/security/pwquality.conf
sed -i 's/@ include.*/@ include common-password/g' /etc/pam.d/passwd
useradd -D -f 35
sed -i 's/auth\srequired\spam_tally2.so.*auth required pam_tally2.so onerr=fail deny=3' /etc/pam.d/common-auth
sed '/NOPASSWD/d' /etc/sudoers
sed '/NOPASSWD/d' /etc/sudoers.d
sed '!authenticate' /etc/sudoers
sed '!authenticate' /etc/sudoers.d
sed -i 's/^auth\sreuired\spam_faildely.so.*auth required pam_faildelay.so delay=4000000/g' /etc/pam.d/common-auth
sed -i 's/^AutomaticLoginEnable.*AutomaticLoginEnable=false/g' /etc/gdm3/custom.conf
if [$? -eq 0]; then
		exit 0
	else
		echo AutomaticLoginEnable=false >> /etc/gdm3/custom.conf
	fi
sed -i 's/^session\srequired.*session required pam_lastlog.so showfailed' /etc/pam.d/login
rm /etc/ssh/shosts.equiv
more /etc/crypttab
find / -type d -perm -0002 -exec ls -1Ld {}; > e.txt
sudo apt-get install aide -y
sed -i 's/VarFile\s=.*VarFile = OwnerMode+n+l+X+acl/g' /etc/aide/aide.conf
sed -i 's/SILENTREPORTS.*SILENTREPORTS=no/g' /etc/default/aide
echo -e "/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattr+sha512\n/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattr+sha512\n/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattr+sha512\n
/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattr+sha512\n/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattr+sha512\n/usr/sbin/audispd p+i+n+u+g+s+b+acl+xattr+sha512\nusr/sbin/augenrules p+i+n+u+g+s+b+acl+xattr+sha512" >> /etc/aide/aide.conf
#sed -i 's/APT::Get::AllowUnauthenticated.*APT::Get::AllowUnauthenticated "false";' /etc/apt/apt.conf.d/* //i have no clue what this is or was
#fi

