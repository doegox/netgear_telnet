#!/bin/sh 
#START=92
#STOP=10

. /lib/config/uci.sh
. /usr/share/libubox/jshn.sh
interface_info=`cat /tmp/cache/project/network.json`
json_load "$interface_info"
json_get_var br_lan lan_bridge_name
UCI=/sbin/uci

update_user()
{
	password=$(uci get system.http.password)
	(echo $password;sleep 1;echo $password) | /bin/passwd root -a sha
	# adduser admin -G root -h "/" -D
	# for factory's demand, force admin to be root's uid, even it's inlegal.
	deluser admin
	echo "admin:x:0:0:Linux User,,,:/tmp/:/bin/ash" >> /etc/passwd
	(echo $password;sleep 1;echo $password) | /bin/passwd admin -a sha 
}

start()
{
	update_user
	if [ "x$($UCI get network.globals.operate_mode)" = "xfactory" ]; then
		/usr/sbin/utelnetd -d -i $br_lan
	else
		/usr/sbin/telnetenable

		telnet_enable=`cat /tmp/cache/debug/enable_telnet`
		if [ "x$telnet_enable" = "x1" ];then
			/sbin/debug_telnetenable.sh stop
			/sbin/debug_telnetenable.sh start
		fi
	fi
}

stop()
{
	killall -9 utelnetd
	killall -9 potval_dni
	killall -9 telnetenable
}

boot()
{
	mkdir /dev/pts
	mknod -m 666 /dev/ptmx c 5 2
	mknod -m 666 /dev/pts/0 c 136 0
	mknod -m 666 /dev/pts/1 c 136 1

	start
}
case $1 in
	boot)
		boot
		;;
	start)
		start
		;;
	stop)
		stop
		;;
	restart)
		stop
		start
		;;
esac
 