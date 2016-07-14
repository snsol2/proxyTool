#!/bin/bash 

TYPE=$1 
NAME=$2 
STATE=$3 
PRIO=$4 

event_fname="/var/log/haproxy/vrrp_event.$(date '+%Y-%m-%d').log" ;

if [ -e $event_fname ]; then
	echo "file: $event_fname already exist"
else
	touch $event_fname;
fi

echo "$(date '+%Y-%m-%d:%H:%M:%S')  $TYPE  $NAME   $STATE" >> $event_fname ;

status_fname="/var/log/haproxy/vrrp.status"
echo "$STATE" > $status_fname;
