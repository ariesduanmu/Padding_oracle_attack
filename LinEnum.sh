#!/bin/bash
#A script to enumerate local information from a Linux host
v="version 0.7"
#@rebootuser

#help function
usage () 
{ 
echo -e "\n\e[00;31m#########################################################\e[00m" 
echo -e "\e[00;31m#\e[00m" "\e[00;33mLocal Linux Enumeration & Privilege Escalation Script\e[00m" "\e[00;31m#\e[00m"
echo -e "\e[00;31m#########################################################\e[00m"
echo -e "\e[00;33m# www.rebootuser.com | @rebootuser \e[00m"
echo -e "\e[00;33m# $v\e[00m\n"
echo -e "\e[00;33m# Example: ./LinEnum.sh -k keyword -r report -e /tmp/ -t \e[00m\n"

        echo "OPTIONS:"
        echo "-k    Enter keyword"
        echo "-e    Enter export location"
        echo "-t    Include thorough (lengthy) tests"
        echo "-r    Enter report name" 
        echo "-h    Displays this help text"
        echo -e "\n"
        echo "Running with no options = limited scans/no output file"
        
echo -e "\e[00;31m#########################################################\e[00m"      
}
header()
{
echo -e "\n\e[00;31m#########################################################\e[00m" 
echo -e "\e[00;31m#\e[00m" "\e[00;33mLocal Linux Enumeration & Privilege Escalation Script\e[00m" "\e[00;31m#\e[00m" 
echo -e "\e[00;31m#########################################################\e[00m" 
echo -e "\e[00;33m# www.rebootuser.com\e[00m" 
echo -e "\e[00;33m# $version\e[00m\n" 

}

debug_info()
{
echo "Debug Info" 

if [ "$keyword" ]; then 
    echo "keyword = $keyword" 
else 
    :
fi

if [ "$report" ]; then 
    echo "report name = $report" 
else 
    :
fi

if [ "$export" ]; then 
    echo "export location = $export" 
else 
    :
fi

if [ "$thorough" ]; then 
    echo "thorough tests = enabled" 
else 
    echo "thorough tests = disabled" 
fi

sleep 2

if [ "$export" ]; then
  mkdir $export 2>/dev/null
  format=$export/LinEnum-export-`date +"%d-%m-%y"`
  mkdir $format 2>/dev/null
else 
  :
fi

who=`whoami` 2>/dev/null 
echo -e "\n" 

echo -e "\e[00;33mScan started at:"; date 
echo -e "\e[00m\n" 
}

system_info()
{
echo -e "\e[00;33m### SYSTEM ##############################################\e[00m" 

#basic kernel info
unameinfo=`uname -a 2>/dev/null`
if [ "$unameinfo" ]; then
  echo -e "\e[00;31mKernel information:\e[00m\n$unameinfo" 
  echo -e "\n" 
else 
  :
fi

procver=`cat /proc/version 2>/dev/null`
if [ "$procver" ]; then
  echo -e "\e[00;31mKernel information (continued):\e[00m\n$procver" 
  echo -e "\n" 
else 
  :
fi

#search all *-release files for version info
release=`cat /etc/*-release 2>/dev/null`
if [ "$release" ]; then
  echo -e "\e[00;31mSpecific release information:\e[00m\n$release" 
  echo -e "\n" 
else 
  :
fi

#target hostname info
hostnamed=`hostname 2>/dev/null`
if [ "$hostnamed" ]; then
  echo -e "\e[00;31mHostname:\e[00m\n$hostnamed" 
  echo -e "\n" 
else 
  :
fi
}

user_info()
{
echo -e "\e[00;33m### USER/GROUP ##########################################\e[00m" 

#current user details
currusr=`id 2>/dev/null`
if [ "$currusr" ]; then
  echo -e "\e[00;31mCurrent user/group info:\e[00m\n$currusr" 
  echo -e "\n" 
else 
  :
fi

#last logged on user information
lastlogedonusrs=`lastlog 2>/dev/null |grep -v "Never" 2>/dev/null`
if [ "$lastlogedonusrs" ]; then
  echo -e "\e[00;31mUsers that have previously logged onto the system:\e[00m\n$lastlogedonusrs" 
  echo -e "\n" 
else 
  :
fi


#who else is logged on
loggedonusrs=`w 2>/dev/null`
if [ "$loggedonusrs" ]; then
  echo -e "\e[00;31mWho else is logged on:\e[00m\n$loggedonusrs" 
  echo -e "\n" 
else 
  :
fi

#lists all id's and respective group(s)
grpinfo=`for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null`
if [ "$grpinfo" ]; then
  echo -e "\e[00;31mGroup memberships:\e[00m\n$grpinfo"
  #added by phackt - look for adm group (thanks patrick)
  adm_users=$(echo -e "$grpinfo" | grep "(adm)")
  if [[ ! -z $adm_users ]];
  then
    echo -e "\nSeems we met some admin users!!!\n"
    echo -e "$adm_users\n"
  fi
  echo -e "\n"
else 
  :
fi

#checks to see if any hashes are stored in /etc/passwd (depreciated  *nix storage method)
hashesinpasswd=`grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null`
if [ "$hashesinpasswd" ]; then
  echo -e "\e[00;33mIt looks like we have password hashes in /etc/passwd!\e[00m\n$hashesinpasswd" 
  echo -e "\n" 
else 
  :
fi
 
#locate custom user accounts with some 'known default' uids
readpasswd=`grep -v "^#" /etc/passwd | awk -F: '$3 == 0 || $3 == 500 || $3 == 501 || $3 == 502 || $3 == 1000 || $3 == 1001 || $3 == 1002 || $3 == 2000 || $3 == 2001 || $3 == 2002 { print }'`
if [ "$readpasswd" ]; then
  echo -e "\e[00;31mSample entires from /etc/passwd (searching for uid values 0, 500, 501, 502, 1000, 1001, 1002, 2000, 2001, 2002):\e[00m\n$readpasswd" 
  echo -e "\n" 
else 
  :
fi

if [ "$export" ] && [ "$readpasswd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/passwd $format/etc-export/passwd 2>/dev/null
else 
  :
fi

#checks to see if the shadow file can be read
readshadow=`cat /etc/shadow 2>/dev/null`
if [ "$readshadow" ]; then
  echo -e "\e[00;33m***We can read the shadow file!\e[00m\n$readshadow" 
  echo -e "\n" 
else 
  :
fi

if [ "$export" ] && [ "$readshadow" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/shadow $format/etc-export/shadow 2>/dev/null
else 
  :
fi

#checks to see if /etc/master.passwd can be read - BSD 'shadow' variant
readmasterpasswd=`cat /etc/master.passwd 2>/dev/null`
if [ "$readmasterpasswd" ]; then
  echo -e "\e[00;33m***We can read the master.passwd file!\e[00m\n$readmasterpasswd" 
  echo -e "\n" 
else 
  :
fi

if [ "$export" ] && [ "$readmasterpasswd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/master.passwd $format/etc-export/master.passwd 2>/dev/null
else 
  :
fi

#all root accounts (uid 0)
echo -e "\e[00;31mSuper user account(s):\e[00m" | tee -a $report 2>/dev/null; grep -v -E "^#" /etc/passwd 2>/dev/null| awk -F: '$3 == 0 { print $1}' 2>/dev/null 
echo -e "\n" 

#pull out vital sudoers info
sudoers=`grep -v -e '^$' /etc/sudoers 2>/dev/null |grep -v "#" 2>/dev/null`
if [ "$sudoers" ]; then
  echo -e "\e[00;31mSudoers configuration (condensed):\e[00m$sudoers" | tee -a $report 2>/dev/null
  echo -e "\n" 
else 
  :
fi

if [ "$export" ] && [ "$sudoers" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/sudoers $format/etc-export/sudoers 2>/dev/null
else 
  :
fi

#can we sudo without supplying a password
sudoperms=`echo '' | sudo -S -l 2>/dev/null`
if [ "$sudoperms" ]; then
  echo -e "\e[00;33mWe can sudo without supplying a password!\e[00m\n$sudoperms" 
  echo -e "\n" 
else 
  :
fi

#known 'good' breakout binaries
sudopwnage=`echo '' | sudo -S -l 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'emacs'\|'vim'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb' | xargs -r ls -la 2>/dev/null`
if [ "$sudopwnage" ]; then
  echo -e "\e[00;33m***Possible Sudo PWNAGE!\e[00m\n$sudopwnage" 
  echo -e "\n" 
else 
  :
fi

#checks to see if roots home directory is accessible
rthmdir=`ls -ahl /root/ 2>/dev/null`
if [ "$rthmdir" ]; then
  echo -e "\e[00;33m***We can read root's home directory!\e[00m\n$rthmdir" 
  echo -e "\n" 
else 
  :
fi

#displays /home directory permissions - check if any are lax
homedirperms=`ls -ahl /home/ 2>/dev/null`
if [ "$homedirperms" ]; then
  echo -e "\e[00;31mAre permissions on /home directories lax:\e[00m\n$homedirperms" 
  echo -e "\n" 
else 
  :
fi

#looks for files we can write to that don't belong to us
if [ "$thorough" = "1" ]; then
  grfilesall=`find / -writable -not -user \`whoami\` -type f -not -path "/proc/*" -exec ls -al {} \; 2>/dev/null`
  if [ "$grfilesall" ]; then
    echo -e "\e[00;31mFiles not owned by user but writable by group:\e[00m\n$grfilesall" 
    echo -e "\n" 
  else
    :
  fi
fi

#looks for world-reabable files within /home - depending on number of /home dirs & files, this can take some time so is only 'activated' with thorough scanning switch
if [ "$thorough" = "1" ]; then
wrfileshm=`find /home/ -perm -4 -type f -exec ls -al {} \; 2>/dev/null`
    if [ "$wrfileshm" ]; then
        echo -e "\e[00;31mWorld-readable files within /home:\e[00m\n$wrfileshm" 
        echo -e "\n" 
    else 
        :
    fi
  else
    :
fi

if [ "$thorough" = "1" ]; then
    if [ "$export" ] && [ "$wrfileshm" ]; then
        mkdir $format/wr-files/ 2>/dev/null
        for i in $wrfileshm; do cp --parents $i $format/wr-files/ ; done 2>/dev/null
    else 
        :
    fi
  else
    :
fi

#lists current user's home directory contents
if [ "$thorough" = "1" ]; then
homedircontents=`ls -ahl ~ 2>/dev/null`
    if [ "$homedircontents" ] ; then
        echo -e "\e[00;31mHome directory contents:\e[00m\n$homedircontents" 
        echo -e "\n" 
    else 
        :
    fi
  else
    :
fi

#checks for if various ssh files are accessible - this can take some time so is only 'activated' with thorough scanning switch
if [ "$thorough" = "1" ]; then
sshfiles=`find / \( -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} 2>/dev/null \;`
    if [ "$sshfiles" ]; then
        echo -e "\e[00;31mSSH keys/host information found in the following locations:\e[00m\n$sshfiles" 
        echo -e "\n" 
    else 
        :
    fi
  else
  :
fi

if [ "$thorough" = "1" ]; then
    if [ "$export" ] && [ "$sshfiles" ]; then
        mkdir $format/ssh-files/ 2>/dev/null
        for i in $sshfiles; do cp --parents $i $format/ssh-files/; done 2>/dev/null
    else 
        :
    fi
  else
    :
fi

#is root permitted to login via ssh
sshrootlogin=`grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" | awk '{print  $2}'`
if [ "$sshrootlogin" = "yes" ]; then
  echo -e "\e[00;31mRoot is allowed to login via SSH:\e[00m" ; grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" 
  echo -e "\n" 
else 
  :
fi
}

environmental_info()
{
echo -e "\e[00;33m### ENVIRONMENTAL #######################################\e[00m" 

#env information
envinfo=`env 2>/dev/null | grep -v 'LS_COLORS' 2>/dev/null`
if [ "$envinfo" ]; then
  echo -e "\e[00;31m Environment information:\e[00m\n$envinfo" 
  echo -e "\n" 
else 
  :
fi

#check if selinux is enabled
sestatus=`sestatus 2>/dev/null`
if [ "$sestatus" ]; then
  echo -e "\e[00;31mSELinux seems present:\e[00m\n$sestatus"
  echo -e "\n"
fi

#phackt

#current path configuration
pathinfo=`echo $PATH 2>/dev/null`
if [ "$pathinfo" ]; then
  echo -e "\e[00;31mPath information:\e[00m\n$pathinfo" 
  echo -e "\n" 
else 
  :
fi

#lists available shells
shellinfo=`cat /etc/shells 2>/dev/null`
if [ "$shellinfo" ]; then
  echo -e "\e[00;31mAvailable shells:\e[00m\n$shellinfo" 
  echo -e "\n" 
else 
  :
fi

#current umask value with both octal and symbolic output
umask=`umask ...
