#!/bin/bash
function sshd_no ()
{
    list=(AllowTcpForwarding  ChallengeResponseAuthentication  Compression  HostbasedAuthentication  PasswordAuthentication  PermitEmptyPasswords  PermitRootLogin  PermitUserEnvironment  PrintMotd  RhostsRSAAuthentication  UsePAM  X11Forwarding)
    for i in "${list[@]}"
    do
        count=$(grep -c $i $1)
        if [[ "$count" -eq 0 ]]
        then
            echo "$i not found"
            echo "$i no" >> sshtemplate.txt
        else 
            sed -i -Ee "s/[#| \t]*($i).+/\1 no/" $1
        fi
    done

}

function sshd_yes ()
{
    list=(UsePrivilegeSeparation StrictModes RSAAuthentication PubkeyAuthentication IgnoreRhosts IgnoreUserKnownHosts PrintLastLog TCPKeepAlive UseDNS)
    for i in "${list[@]}"
    do
        count=$(grep -c $i $1)
        if [[ "$count" -eq 0 ]]
        then
            echo "$i not found"
            echo "$i yes" >> sshtemplate.txt
        else 
            sed -i -Ee "s/[#| \t]*($i).+/\1 yes/" $1
        fi
    done
}


sshd_no sshtemplate.txt
sshd_yes sshtemplate.txt
