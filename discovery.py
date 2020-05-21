#!/usr/bin/env python3.6

'''
Pihole is great, but the admin interface only displays device details 
by IP address which can be confusing. This script changes the display
from IP address to a more recognizable name, declared in an address list. 
We do this instead of grabbing the device's hostname as we can't change some
devices' hostnames.
Original script here: https://gist.github.com/drath/07bdeef0259bd68747a82ff80a5e350c
Usage notes
- sudo python3 discovery.py
- Displays log messages at appropriate times
- when running as a service, remember to add 'Environment=PYTHONUNBUFFERED=1' under '[Service]'
License: MIT.
'''

import os
from scapy.all import *
from python_hosts import Hosts, HostsEntry
from shutil import copyfile
import sys


'''
Global stuff
'''

interface = "eth0"
addressList =  {
  "70:85:c2:a1:ba:3f": "Dalamud",
  "20:39:56:dd:a6:a9": "Nokia-Android",
  "98:ee:cb:3a:9e:84": "Acer",
  "b0:c1:9e:fd:1c:b4": "ZTE-Android",
  "70:f1:a1:74:ad:97": "HP",
  "ac:ae:19:0c:11:6f": "Roku-Downstairs",
  "b8:3e:59:81:4e:4f": "Roku-Upstairs",
  "00:f6:20:45:6f:77": "Google-Home",
  "14:10:9f:03:22:dd": "iPod"
}

'''
Log message for troubleshooting
'''

def log_packet_info(packet):
    #print(packet.summary())
    #print(ls(packet))
    print('---')
    types = {
        1: "New DHCP Discover",
        2: "New DHCP Offer",
        3: "New DHCP Request",
        5: "New DHCP Ack",
        8: "New DHCP Inform"
    }
    if DHCP in packet:
        print(types.get(packet[DHCP].options[0][1], "Some Other DHCP Packet"))
    return


# https://jcutrer.com/howto/dev/python/python-scapy-dhcp-packets
def get_option(dhcp_options, key):
    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        for i in dhcp_options:
            if i[0] == key:
                # If DHCP Server Returned multiple name servers 
                # return all as comma seperated string.
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])
                # domain and hostname are binary strings,
                # decode to unicode string before returning
                elif key in must_decode:
                    return i[1].decode()
                else: 
                    return i[1]        
    except:
        pass

def handle_dhcp_packet(packet):
    log_packet_info(packet)
    if DHCP in packet:
        requested_addr = get_option(packet[DHCP].options, 'requested_addr')
        hostname = get_option(packet[DHCP].options, 'hostname')
        param_req_list = get_option(packet[DHCP].options, 'param_req_list')
        vendor_class_id = get_option(packet[DHCP].options, 'vendor_class_id')
        print(f"Host {hostname} ({packet[Ether].src}) requested {requested_addr}.")
        if (requested_addr):
            update_hosts_file(requested_addr, packet[Ether].src)
    return

'''
Update the hosts file with <hostname>-<profile> for hostname
'''

def update_hosts_file(address,macaddr):
    if macaddr in addressList:
        copyfile("/etc/hosts", "hosts")
        etchostname = addressList[macaddr]
        print(f"Updating hostname as: {etchostname} with {address}")

        hosts = Hosts(path='hosts')
        hosts.remove_all_matching(name=etchostname)
        new_entry = HostsEntry(entry_type='ipv4', address=address, names=[etchostname])
        hosts.add([new_entry])
        hosts.write()
        copyfile("hosts", "/etc/hosts")

        print(f"Updated Host name for hostsfile is {etchostname}")

            
print("Starting\n")
sniff(iface = interface, filter='udp and (port 67 or 68)', prn = handle_dhcp_packet, store = 0)
print("\n Shutting down...")

'''
End of file
'''
