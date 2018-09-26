#!/usr/bin/python

import glob
import os

from distutils.core import setup

PACKAGE_NAME = "PowerDNS"

setup(name = PACKAGE_NAME,
      version = "1.0.0",
      description = "A tool for performing Powershell DNS Delivery",
      url = "https://github.com/mdsecactivebreach/PowerDNS",
      author = "domchell",
      author_email = "dominic@mdsec.co.uk",
      maintainer = "domchell",
      maintainer_email = "dominic@mdsec.co.uk",
      platforms = ["Unix","Windows"],
      scripts = ['powerdns.py'],
      data_files = [(os.path.join('share', 'doc', PACKAGE_NAME), ['README.md'])],
      requires=['scapy (>=2.4.0)'],
      )

