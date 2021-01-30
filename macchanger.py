#!/usr/bin/env python


import subprocess
import optparse
import re

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC Address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC Address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info")
    elif not options.new_mac:
        perser.error("[-] Please specify a new MAC, use --help for more info")
    return options


def change_mac(interface, new_mac):
    print("*" * 50)
    print("[+] Changing MAC Address for " + interface + " to " + new_mac)
    print("*" * 50)
    print("\n")
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])

def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))
    if result:
        print("-" * 50)
        print("The current MAC is: " + result.group(0))
        print("-" * 50)
        print("\n")
        return result.group(0)
    else:
        print("Could not read the MAC Address")


options = get_arguments()
get_current_mac(options.interface)
change_mac(options.interface, options.new_mac)
cur_mac = get_current_mac(options.interface)
if cur_mac == options.new_mac:
    print("[+} The MAC Address was successfully changed to :" + cur_mac)
else:
    print("The MAC Address did not get changed")

