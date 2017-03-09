#!/usr/bin/env python

# Basic implementation of a parser for the MCS sweep test results
# Decodes the embedded MAC address data

import sys
import subprocess


tshark = subprocess.Popen(["tshark", "-e", "wlan.ta", "-Tfields", "-r", sys.argv[1], "wlan.fc.type_subtype == 0x0020"],
        stdout=subprocess.PIPE, stdin=subprocess.PIPE)

for l in tshark.stdout:
    v = l.split(':');

    rawmcs = int(v[1], 16)

    ht = (rawmcs & (1 << 7))
    gi = (rawmcs & (1 << 6))
    mcs = (rawmcs & 0x3F)

    location = int(v[2]);

    # Convert to int, and endian flip
    lpacket = int("{}{}{}".format(v[3], v[4], v[5]), 16)

    if ht != 0:
        htstr = "40MHz"
    else:
        htstr = "20MHz"

    if gi != 0:
        gistr = " Short-GI"
    else:
        gistr = ""

    # Dump the basic location
    print "Packet {} Location {} MCS {} {}{}".format(lpacket, location, mcs, htstr, gistr)

