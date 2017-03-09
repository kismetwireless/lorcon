#!/usr/bin/env python

# Basic implementation of a parser for the MCS sweep test results
# Decodes the embedded MAC address data

import sys
import subprocess
import argparse

parser = argparse.ArgumentParser(description='MCS Sweep Processor')

parser.add_argument('--pcap', action="store", dest="pcap")
parser.add_argument('--count', action="store", dest="count")

results = parser.parse_args()

if results.pcap == None:
    print "ERROR: Expected --pcap"
    sys.exit(1)

if results.count == None:
    print "ERROR: Expected --count for total # of packets per test"
    sys.exit(1)

resultmap = {}

for m in range(0, 16):
    resultmap[m] = {}
    # HT
    resultmap[m][0] = {}
    resultmap[m][1] = {}
    # GI
    resultmap[m][0][0] = {}
    resultmap[m][0][1] = {}
    resultmap[m][1][0] = {}
    resultmap[m][1][1] = {}

tshark = subprocess.Popen(["tshark", "-e", "wlan.ta", "-Tfields", "-r", results.pcap, "wlan.fc.type_subtype == 0x0028"],
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
        ht = 1
    else:
        htstr = "20MHz"

    if gi != 0:
        gistr = " Short-GI"
        gi = 1
    else:
        gistr = ""

    #print "Packet {} Location {} MCS {} {}{}".format(lpacket, location, mcs, htstr, gistr)

    if not location in resultmap[mcs][ht][gi]:
        resultmap[mcs][ht][gi][location] = {}

    resultmap[mcs][ht][gi][location][lpacket] = 1

# Build the MCS rate table
ratemap = {}
for m in range(0, 16):
    ratemap[m] = {}
    # HT
    ratemap[m][0] = {}
    ratemap[m][1] = {}
    # GI
    ratemap[m][0][0] = {}
    ratemap[m][0][1] = {}
    ratemap[m][1][0] = {}
    ratemap[m][1][1] = {}

ratemap[0][0][0] = 6.5
ratemap[0][0][1] = 7.2
ratemap[0][1][0] = 13.5
ratemap[0][1][1] = 15

ratemap[1][0][0] = 13
ratemap[1][0][1] = 14.4
ratemap[1][1][0] = 27
ratemap[1][1][1] = 30

ratemap[2][0][0] = 19.5
ratemap[2][0][1] = 21.7
ratemap[2][1][0] = 40.5
ratemap[2][1][1] = 45

ratemap[3][0][0] = 26
ratemap[3][0][1] = 28.9
ratemap[3][1][0] = 54
ratemap[3][1][1] = 60

ratemap[4][0][0] = 39
ratemap[4][0][1] = 43.3
ratemap[4][1][0] = 81
ratemap[4][1][1] = 90

ratemap[5][0][0] = 52
ratemap[5][0][1] = 57.8
ratemap[5][1][0] = 108
ratemap[5][1][1] = 120

ratemap[6][0][0] = 58.5
ratemap[6][0][1] = 65
ratemap[6][1][0] = 121.5
ratemap[6][1][1] = 135

ratemap[7][0][0] = 65
ratemap[7][0][1] = 72.2
ratemap[7][1][0] = 135
ratemap[7][1][1] = 150

ratemap[8][0][0] = 13
ratemap[8][0][1] = 14.4
ratemap[8][1][0] = 27
ratemap[8][1][1] = 30

ratemap[9][0][0] = 26
ratemap[9][0][1] = 28.9
ratemap[9][1][0] = 54
ratemap[9][1][1] = 60

ratemap[10][0][0] = 39
ratemap[10][0][1] = 43.3
ratemap[10][1][0] = 81
ratemap[10][1][1] = 90

ratemap[11][0][0] = 52
ratemap[11][0][1] = 57.8
ratemap[11][1][0] = 108
ratemap[11][1][1] = 120

ratemap[12][0][0] = 78
ratemap[12][0][1] = 86.7
ratemap[12][1][0] = 162
ratemap[12][1][1] = 180

ratemap[13][0][0] = 105
ratemap[13][0][1] = 115.6
ratemap[13][1][0] = 216
ratemap[13][1][1] = 240

ratemap[14][0][0] = 117
ratemap[14][0][1] = 130.3
ratemap[14][1][0] = 243
ratemap[14][1][1] = 270

ratemap[15][0][0] = 130
ratemap[15][0][1] = 144.4
ratemap[15][1][0] = 270
ratemap[15][1][1] = 300

for m in range(0, 16):
    for ht in range(0, 2):
        for gi in range(0, 2):
            for l in resultmap[m][ht][gi]:
                if ht:
                    htstr = "40MHz"
                else:
                    htstr = "20MHz"

                if gi:
                    gistr = "Short-GI"
                else:
                    gistr = ""

                perc = (len(resultmap[m][ht][gi][l]) / int(results.count)) * 100

                print "MCS {:2} {:5} {:8} {:10} {:12} {:.2f}%".format(
                        m,
                        htstr,
                        gistr,
                        "{} mbit".format(ratemap[m][ht][gi]),
                        "Location {}".format(l),
                        perc)

sys.exit(1)


