#!/usr/bin/env python
"""
Network scanner to scan local networks, will respond with IP and mac address
"""

import scapy.all as scapy
import optparse


'''get arguments from terminal input'''
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Enter a target network to scan, ex: 192.168.1.1/24")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target to scan, use --help for more info")
    return options


'''create and send out a broadcast packet'''
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    client_list = []
    for line in answered:
        client_dict = {"ip": line[1].psrc, "mac": line[1].hwsrc}
        client_list.append(client_dict)
    return client_list


'''print all results in list returned by scan func'''
def print_result(results_list):
    print("IP\t\t\tMAC Address\n--------------------------------------------")
    for client in results_list:
        print(client['ip'] + "\t\t" + client['mac'])


options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)