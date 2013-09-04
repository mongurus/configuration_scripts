#!/bin/sh -e


apt-get install -y snmpd

theusername=`head -c 1200 /dev/urandom | md5sum | head -c 16`
thepassword=`head -c 1200 /dev/urandom | md5sum | head -c 16`

/etc/init.d/snmpd stop

test -e /etc/snmp/snmpd.conf && mv /etc/snmp/snmpd.conf /etc/snmp/snmpd.conf.monguru.backup-`date +%s`
wget -q -O - https://raw.github.com/monguru/configuration_scripts/master/snmpd.conf | sed -e "s/\[%REPLACE_ME%\]/${theusername}/g" > /etc/snmp/snmpd.conf


echo -n "-Setting new snmp login/password..."
echo "createUser $theusername SHA1 \"$thepassword\" AES
rouser $theusername" >> /var/lib/snmp/snmpd.conf
echo "done."

/etc/init.d/snmpd start
