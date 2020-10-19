#!/bin/bash

#checking for sudo
if [ $UID != 0 ]; then
    echo " use sudo and try again... "
    exit
else
	y=$(sudo awk -F':' '{ print $1}' /etc/passwd)
	declare -a y
	for x in ${y[@]}; do
		#x="administrator"
		#passwd $x --delete
		#sudo awk -F':' '{ print $1}' /etc/passwd | passwd CyberPatriot1!
		echo -e "CyberPatriot1!\nCyberPatriot1!" | passwd "$x"
	done
fi

