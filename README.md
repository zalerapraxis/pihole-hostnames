# pihole-hostnames
Hosts file updater script for pi-hole, which associates mac addresses with (host)names

-----

In an environment where you use your router's DHCP server and it assigns dynamic addresses, and you cannot use conditional forwarding in Pi-Hole, these scripts can be used to assign hostnames via your Pi-Hole's /etc/hosts file, so that Pi-Hole will show you hostnames instead of IP addresses.

The 'original' script comes from here: https://gist.github.com/drath/07bdeef0259bd68747a82ff80a5e350c - it uses the device's actual hostname in combination with fingerprint data to further identify the device.

I found that approach gave me poor results - some of my devices' hostnames can't be changed, and their fingerprint results were messy. I opted instead to just identify mac addresses in my network and associate them with recognizable names. 
