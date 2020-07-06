# pihole-hostnames
Hosts file updater script for pi-hole, which associates mac addresses with custom hostnames

-----

This script assigns hostnames via your Pi-Hole's /etc/hosts file, so that Pi-Hole will show you hostnames instead of IP addresses. It does this by running an nmap scan of the network, parsing each device's macaddrs and ipaddrs, matching the macaddr to a hardcoded dictionary of macaddr:hostnames to associate a hostname to an IP address, and then updating the hosts file with the ipaddr:hostname pair.

This script was developed with some things in mind regarding my network:

* I use my router as a DHCP server
* Everything except a small number of devices are assigned dynamic addresses
* My router doesn't allow me to set a domain name & doesn't expose what it might be at default, so we can't use Conditional Forwarding
* Some of my devices have nonsensical hostnames that can't be changed

The 'original' script comes from here: https://gist.github.com/drath/07bdeef0259bd68747a82ff80a5e350c - it uses the device's actual hostname in combination with fingerprint data to further identify the device.

I found that approach gave me poor results - some of my devices' hostnames can't be changed, their fingerprint results were messy. I opted instead to just identify mac addresses in my network and associate them with recognizable names.
