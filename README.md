Auto - MonGuru's servers configurations scripts
=====================

Start monitoring your server using MonGuru Cloud Hosted Nagios.

What you will need:
-Debian/Ubuntu system
-Root access
-A MonGuru account
-Open SNMP (udp port 161) on firewall
-ICMP echo reply on firewall (type 0)

If you have all the ingredients all that you need to do is to type on
your servers the following command line:

curl -sL https://raw.github.com/monguru/configuration_scripts/master/add_new_server.sh | sudo bash -e

Follow the script instructions.
