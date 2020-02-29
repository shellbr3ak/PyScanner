#!/usr/bin/env python3

# pyscan.py v1.0
# Made by : Kai-Pro

## This scanner works with python3 ONLY
## scan types: ping, basic, advanced and massive
## Ping scan only gets the IP addresss of the accessible hosts on the network
## Basic scan gets the IP addresses of the accessible hosts and scans the first 5000 ports of each host
## Advanced scan in addition to the IPs it scans the first 10000 ports of each host
## Massive scan gets IPs and a full port scan (65535)

# Usage:
#   python3 pyscan.py -r netIP/range -s scan_type
# Example:
#   python3 pyscan.py -r 172.16.194.1/24 -s massive
# Scanning a single host is available too:
#   python3 pyscan.py -r ip -s scan_type

import socket
import sys
import argparse
import time
from concurrent.futures import ThreadPoolExecutor as executor
from scapy.all import *
from colorama import Fore, init

init()

print(f'''{Fore.YELLOW}

\t          +------------------------------------------------+
\t          |               Coded by : kai-pro               |
\t          |                                                |
\t          | https://github.com/shellbr3ak?tab=repositories |
\t          +------------------------------------------------+
\t            ____  _          _ _ ____                 _
\t           / ___|| |__   ___| | | __ ) _ __ ___  __ _| | __
\t           \___ \| '_ \ / _ \ | |  _ \| '__/ _ \/ _` | |/ /
\t            ___) | | | |  __/ | | |_) | | |  __/ (_| |   <
\t           |____/|_| |_|\___|_|_|____/|_|  \___|\__,_|_|\_|
\t   
\t                          offensive python
\t                          ----------------

{Fore.WHITE}''')

def single_host(ip):
    icmp = IP(dst=ip)/ICMP()
    resp = sr1(icmp, timeout=10,verbose=0)
    if resp != None:
        print(Fore.GREEN + 'Host is up\n' + Fore.WHITE)
        return True
    else:
        print(Fore.GREEN + 'Host is down\n' + Fore.WHITE)
        return False



def multi_hosts(ip):
    try:
        icmp = IP(dst=ip)/ICMP()
        resp = sr1(icmp, timeout=5, verbose=0)
        if resp != None:
            print(Fore.GREEN + ip + Fore.WHITE)
            hosts_up.append(ip)
        else:
            return
    except:
        print('Something went wrong with the multi_hosts scanning function')


def port_scan(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if s.connect_ex((ip,port)):
            return
        else:
            if len(str(port)) >= 4:
                print(f'{Fore.GREEN}{port}{Fore.WHITE}/tcp    open     ' + socket.getservbyport(port))
            else:
                print(f'{Fore.GREEN}{port}{Fore.WHITE}/tcp\t    open     ' + socket.getservbyport(port))
    except OSError:
        if len(str(port)) == 4:
            print(f'{Fore.GREEN}{port}{Fore.WHITE}/tcp    open     unknown_service') 
        elif len(str(port)) == 5:
            print(f'{Fore.GREEN}{port}{Fore.WHITE}/tcp   open     unknown_service')
    
    

parser = argparse.ArgumentParser(description="Usage: python3 pyscan.py -r NetIP/range -s scan_type(full/normal)")
parser.add_argument('-r', dest='range', help='The range of the network to scan')
parser.add_argument('-s', dest='scan', help='Scan type: \'full\' to include port scanning, \'normal\' to check connected hosts only')
parsed_args = parser.parse_args()

ip_range = parsed_args.range
scan_type = parsed_args.scan
hosts_up = []

try:
    if '/' not in ip_range:
        print(Fore.YELLOW + '\nYou entered IP address for one device\n' + Fore.WHITE)
        isUp = single_host(ip_range)
    else:
        print(Fore.BLUE + '\nStarting The Scan...\n' + Fore.WHITE)
        time.sleep(3)
        net_ip = ip_range[:11]
        with executor(max_workers=1000) as exe:
            for device in range(1,256):
                exe.submit(multi_hosts, (net_ip + str(device)))
        print()

except TypeError:
    print(Fore.RED + parser.description + Fore.WHITE)
    sys.exit(1)

except KeyboardInterrupt:
    print('\n')
    sys.exit(1)
finally:
    if '/' not in ip_range and isUp:
        if scan_type == 'ping':
            print(f'\n{Fore.YELLOW}Scan Finished!!{Fore.WHITE}')
            sys.exit(1)
        else:
            print(f'Scanning Host: {Fore.YELLOW}{ip_range}{Fore.WHITE}\n')
            print('Port\t   |Status  |Service')
            print('--------------------------')
            with executor(max_workers=1000) as exe:
                if scan_type == 'basic':
                    for port in range(1, 5000):
                        exe.submit(port_scan, ip_range, port)
                elif scan_type == 'advanced':
                    for port in range(1, 10000):
                        exe.submit(port_scan, ip_range, port)
                elif scan_type == 'massive':
                    for port in range(1, 65536):
                        exe.submit(port_scan, ip_range, port)
                else:
                    print(f'{Fore.RED}Available scan types: ping , basic , advanced , massive{Fore.WHITE}')
                    sys.exit(1)
            print(f'\n{Fore.YELLOW}Scan Finished!!{Fore.WHITE}\n')
            sys.exit(1)

    else:
        if scan_type == 'ping':
            print(f'\n{Fore.YELLOW}Scan Finished!!{Fore.WHITE}')
            sys.exit(1)
        else:
            for host in hosts_up:
                print(f'Scanning host: {Fore.YELLOW}{host}{Fore.WHITE}\n')
                if int(host[11:]) == 1 or int(host[11:]) == 2:
                    print(f'{Fore.RED}{host}{Fore.WHITE} is the default gateway and won\'t be scanned\n')
                    continue
                else:
                    print('Port\t   |Status  |Service')
                    print('--------------------------')
                    with executor(max_workers=1000) as exe:
                        if scan_type == 'basic':
                            for port in range(1, 5000):
                                exe.submit(port_scan, host, port)
                        elif scan_type == 'advanced':
                            for port in range(1, 10000):
                                exe.submit(port_scan, host, port)
                        elif scan_type == 'massive':
                            for port in range(1, 65536):
                                exe.submit(port_scan, host, port)
                        else:
                            print(f'{Fore.RED}Available scan types: ping , basic , advanced , massive{Fore.WHITE}')
                            sys.exit(1)
            print(f'\n{Fore.YELLOW}Scan Finished!!{Fore.WHITE}\n')
            sys.exit(1)
