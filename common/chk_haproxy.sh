#!/bin/bash
SERVICE='/usr/sbin/haproxy'
STATUS=$(ps -ef | grep -v grep | grep $SERVICE | wc -l)

if [ $STATUS == 0 ]
then
	exit 1
else
	exit 0
fi
