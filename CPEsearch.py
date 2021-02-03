#!/usr/bin/env python
"""
Tool to easily search for CPEs for any software used
"""

import optparse
from urllib.request import urlopen
import json


'''create variables'''
dict = {}
new_list = []


'''get arguments fron terminal input'''
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-s", "--search", dest="user_search", help="Enter an item in the format of vendor:product:version to search for CPE. Example: oracle:collaboration_suite:10.1.2")
    (options, arguments) = parser.parse_args()
    if not options.user_search:
        parser.error("[-] Please enter an item to scan, use --help for more info")
    return options


'''take user input and retrieve cpe values from json data'''
def get_cpe(options):
    url = ('https://services.nvd.nist.gov/rest/json/cpes/1.0?cpeMatchString=cpe:2.3:*:' + options.user_search)
    response = urlopen(url)
    dict = json.load(response)
    new_list = dict['result']['cpes']
    for entry in new_list:
        print(line['cpe23Uri'])

options = get_arguments()
get_cpe(options)



