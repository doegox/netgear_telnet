#!/bin/sh

#Purpose:
#update telnet related parameters from uci
[ -d "/tmp/cache/telnetenable/" ] || mkdir -p "/tmp/cache/telnetenable" 
PASSWORD_FILE="/tmp/cache/telnetenable/httpwd"
uci get system.http.password >$PASSWORD_FILE

