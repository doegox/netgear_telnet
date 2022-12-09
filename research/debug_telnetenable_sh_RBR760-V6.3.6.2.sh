#!/bin/sh
. /lib/config/uci.sh
. /usr/share/libubox/jshn.sh
interface_info=`cat /tmp/cache/systeminfo/ethinfo.info`
json_load "$interface_info"
json_get_var br_lan lan_net_if

update_user()
{
	password=$(uci get users.http.password)
	(echo $password;sleep 1;echo $password) | /bin/passwd root -a sha
	# adduser admin -G root -h "/" -D
	# for factory's demand, force admin to be root's uid, even it's inlegal.
	deluser admin
	echo "admin:x:0:0:Linux User,,,:/tmp/:/bin/ash" >> /etc/passwd
	(echo $password;sleep 1;echo $password) | /bin/passwd admin -a sha 
}

#Enable telnet
telnet_enable()
{
	if [ "$1" = "start" ];then
		update_user
		/usr/sbin/utelnetd -d -i $br_lan
	else
		killall utelnetd	
	fi
}

telnet_enable $1
 