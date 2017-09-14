#!/usr/bin/env python

# Basic implementation of a parser for the MCS sweep test results
# Decodes the embedded MAC address data

import sys
import subprocess
import argparse
import json
import pprint

parser = argparse.ArgumentParser(description='MCS Sweep Processor')

parser.add_argument('--pcap', action="store", dest="pcap", nargs="+")
parser.add_argument('--markdown', action="store_true", dest="markdown")
parser.add_argument('--csv', action="store_true", dest="csv")

results = parser.parse_args()

if results.pcap == None:
    print "ERROR: Expected --pcap"
    sys.exit(1)

# Build the results table
resultmap = {}
ratemap = {}

def build_empty_results(session, numtx):
    global resultmap

    resultmap[session] = {}

    for m in range(0, 16):
        resultmap[session][m] = {}
        # HT
        resultmap[session][m][0] = {}
        resultmap[session][m][1] = {}
        # GI
        resultmap[session][m][0][0] = {}
        resultmap[session][m][0][1] = {}
        resultmap[session][m][1][0] = {}
        resultmap[session][m][1][1] = {}

    # Calibration false MCS
    resultmap[session][63] = {}
    resultmap[session][63][1] = {}
    resultmap[session][63][1][1] = {}

    # Store # of packets
    resultmap[session][64] = numtx

def clean_state():
    global ratemap

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

    ratemap[13][0][0] = 104
    ratemap[13][0][1] = 115.6
    ratemap[13][1][0] = 216
    ratemap[13][1][1] = 240

    ratemap[14][0][0] = 117
    ratemap[14][0][1] = 130
    ratemap[14][1][0] = 243
    ratemap[14][1][1] = 270

    ratemap[15][0][0] = 130
    ratemap[15][0][1] = 144.4
    ratemap[15][1][0] = 270
    ratemap[15][1][1] = 300

#tshark -x -T ek -r 2.4_test_c6ht40plus -Y 'wlan.bssid == 00:de:ad:be:ef:00 and wlan.fc.type == 0 and wlan.fc.subtype == 8'

for pcap_file in results.pcap:
    clean_state()
    if not results.markdown and not results.csv:
        print "Launching tshark and analyzing packets, this may take some time."

    # We use tshark to get the packet contents
    # Elastic Search / EK mode gets us a JSON record per line instead of a
    # huge vector object we'd have to parse in ram
    tshark = subprocess.Popen(["tshark", "-x", "-T", "ek", "-Y", "wlan.bssid == 00:de:ad:be:ef:00 and wlan.fc.type == 0 and wlan.fc.subtype == 8", "-r", pcap_file],
             stdout=subprocess.PIPE, stdin=subprocess.PIPE)

    for l in tshark.stdout:
        try:
            j = json.loads(l)

            #pprint.pprint(j)

            # Extract the rtap signal
            pcap_signal = int(j['layers']['radiotap']['radiotap_radiotap_dbm_antsignal'])

            # Extract the all-tags record; we can't get the per-tag record easily
            # so we need to process the IE records manually; convert to ascii from utf-8 hex
            pcap_all_tags = j['layers']['wlan_mgt']['wlan_mgt_wlan_mgt_tagged_all_raw'].decode("utf-8")

            # Convert to binary
            bin_all_tags = pcap_all_tags.decode("hex")

            # Split the IE fields up
            tags = {}
            ie_pos = 0

            while ie_pos < len(bin_all_tags):
                tagno = ord(bin_all_tags[ie_pos])
                taglen = ord(bin_all_tags[ie_pos + 1])
                tagval = bin_all_tags[ie_pos + 2:ie_pos + 2 + taglen]
                ie_pos += taglen + 2

                tags[tagno] = [tagno, taglen, tagval]

            # Make sure we have the 2 MCS suite tags and validate the SSID
            if not 0 in tags or not 10 in tags or not 11 in tags:
                continue

            if tags[0][2].decode("ascii") != "MCS_TEST":
                print "mismatch ssid", tags[0]
                continue

            # Process the 'older' 10 byte version
            if tags[10][1] == 10:
                txflags = ord(tags[10][2][0])
                txloc = ord(tags[10][2][1])
                txpnum = ord(tags[10][2][2]) << 24 | ord(tags[10][2][3]) << 16 | ord(tags[10][2][4]) << 8 | ord(tags[10][2][5])
                txtnum = ord(tags[10][2][6]) << 24 | ord(tags[10][2][7]) << 16 | ord(tags[10][2][8]) << 8 | ord(tags[10][2][9])
                # No txid, set the txid to 0
                txid = 0
            elif tags[10][1] == 14:
                # Newer version with random TXID for this grouping
                txflags = ord(tags[10][2][0])
                txloc = ord(tags[10][2][1])
                txpnum = ord(tags[10][2][2]) << 24 | ord(tags[10][2][3]) << 16 | ord(tags[10][2][4]) << 8 | ord(tags[10][2][5])
                txtnum = ord(tags[10][2][6]) << 24 | ord(tags[10][2][7]) << 16 | ord(tags[10][2][8]) << 8 | ord(tags[10][2][9])
                txid = ord(tags[10][2][10]) << 24 | ord(tags[10][2][11]) << 16 | ord(tags[10][2][12]) << 8 | ord(tags[10][2][13])

            # Populate the resultmap for this session
            if not txid in resultmap:
                build_empty_results(txid, txtnum)

            # Calibration packet, it won't have the mcs data in the rtap header
            if txflags == 0xFF:
                if not txloc in resultmap[txid][63][1][1]:
                    resultmap[txid][63][1][1][txloc] = {}

                resultmap[txid][63][1][1][txloc][txpnum] = pcap_signal

                #print "Calibration:", txid, txflags, txloc, txpnum, txtnum, pcap_signal


            pcap_dr = float(j['layers']['radiotap']['radiotap_radiotap_datarate'])
            pcap_mcs_shortgi = int(j['layers']['radiotap']['radiotap_mcs_radiotap_mcs_gi'])
            pcap_mcs_bw = int(j['layers']['radiotap']['radiotap_mcs_radiotap_mcs_bw'])
            pcap_mcs_index = int(j['layers']['radiotap']['radiotap_mcs_radiotap_mcs_index'])

            ext_ht = (txflags & (1 << 7))
            ext_gi = (txflags & (1 << 6))
            ext_mcs = int(txflags & 0x3F)

            if ext_ht:
                ext_ht = 1

            if ext_gi:
                ext_gi = 1

            if ext_ht and not pcap_mcs_bw:
                print "HT mismatch", ext_ht, pcap_mcs_bw
                continue

            if ext_gi and not pcap_mcs_shortgi:
                print "GI mismatch"
                continue

            if ext_mcs != pcap_mcs_index:
                print "MCS index mismatch"
                continue

            if not txloc in resultmap[txid][ext_mcs][ext_ht][ext_gi]:
                resultmap[txid][ext_mcs][ext_ht][ext_gi][txloc] = {}

            resultmap[txid][ext_mcs][ext_ht][ext_gi][txloc][txpnum] = pcap_signal

            #print "MCS:", txid, ext_ht, ext_gi, ext_mcs, txloc, txpnum, txtnum, pcap_dr, pcap_mcs_index, pcap_mcs_shortgi, pcap_mcs_bw, pcap_signal

        except KeyError as e:
            #pprint.pprint(j)
            #print e
            pass
        except ValueError as e:
            #print e
            pass

    if results.markdown:
        print "## MCS pcap:", results.pcap
        print "Sessions found:", len(resultmap)
    elif results.csv:
        print "file,session,location,rate,seen,min,avg,max"

    # For each txsession
    for txs in resultmap:
        totalcount = float(resultmap[txs][64])

        if results.markdown:
            print "### Session", txs
            print "Packets per rate:", totalcount

            print "|Rate|Location                |% Seen|Min/Avg/Max|"
            print "|----|-----------------------|-------|-----------|"

        if 63 in resultmap[txs]:
            for loc in resultmap[txs][63][1][1]:
                minsig = 999
                maxsig = -999
                avgsig = 0

                for p in resultmap[txs][63][1][1][loc]:
                    sig = resultmap[txs][63][1][1][loc][p]

                    avgsig += sig

                    if sig < minsig:
                        minsig = sig
                    if sig > maxsig:
                        maxsig = sig

                perc = (float(len(resultmap[txs][63][1][1][loc])) / totalcount) * 100
                avgsig = avgsig / len(resultmap[txs][63][1][1][loc])

                if results.markdown:
                    print "|1mbit Non-MCS Calibration|Location {}|{:.2f}%|{} dBm/{} dBm/{} dBm|".format(
                            loc, perc, minsig, avgsig, maxsig)
                elif results.csv:
                    print "{},{},{},{},{},{},{},{}".format(results.pcap, txs, loc, "CAL", perc, minsig, avgsig, maxsig)
                else:
                    print "Calibration 1mbit                {:12} {:.2f}% {} dBm/{} dBm/{} dBm".format(
                            "Location {}".format(loc), perc, minsig, avgsig, maxsig)

        for m in range(0, 16):
            for ht in range(0, 2):
                for gi in range(0, 2):
                    if ht:
                        htstr = "40MHz"
                    else:
                        htstr = "20MHz"

                    if gi:
                        gistr = "Short-GI"
                    else:
                        gistr = ""

                    if (len(resultmap[txs][m][ht][gi]) == 0):
                        if results.markdown:
                            print "|{} {} {} {} mbit|Location {}|{:.2f}%|{} dBm/{} dBm/{} dBm|".format(
                                    m, htstr, gistr, ratemap[m][ht][gi], "--", 0, "--", "--", "--")
                        elif results.csv:
                            print "{},{},{},{},{},{},{},{}".format(results.pcap, txs, "--", ratemap[m][ht][gi], 0, 0, 0, 0)
                        else:
                            print "MCS {:2} {:5} {:8} {:10} {:12} {:.2f}%".format(
                                    m,
                                    htstr,
                                    gistr,
                                    "{} mbit".format(ratemap[m][ht][gi]),
                                    "Location --",
                                    0)

                    for loc in resultmap[txs][m][ht][gi]:
                        for loc in resultmap[txs][m][ht][gi]:
                            minsig = 999
                            maxsig = -999
                            avgsig = 0

                            for p in resultmap[txs][m][ht][gi][loc]:
                                sig = resultmap[txs][m][ht][gi][loc][p]

                                avgsig += sig

                                if sig < minsig:
                                    minsig = sig
                                if sig > maxsig:
                                    maxsig = sig

                        perc = (float(len(resultmap[txs][m][ht][gi][loc])) / totalcount) * 100
                        avgsig = avgsig / len(resultmap[txs][m][ht][gi][loc])

                        if results.markdown:
                            print "|{} {} {} {} mbit|Location {}|{:.2f}%|{} dBm/{} dBm/{} dBm|".format(
                                    m, htstr, gistr, ratemap[m][ht][gi], loc, perc, minsig, avgsig, maxsig)
                        elif results.csv:
                            print "{},{},{},{},{},{},{},{}".format(results.pcap, txs, loc, ratemap[m][ht][gi], perc, minsig, avgsig, maxsig)
                        else:
                            print "MCS {:2} {:5} {:8} {:10} {:12} {:.2f}% {} dBm/{} dBm/{} dBm".format(
                                    m,
                                    htstr,
                                    gistr,
                                    "{} mbit".format(ratemap[m][ht][gi]),
                                    "Location {}".format(loc),
                                    perc, minsig, avgsig, maxsig)

sys.exit(1)

# tshark = subprocess.Popen(["tshark", "-e", "wlan.ta", "-e", "radiotap.datarate", "-Tfields", "-E", "separator=,", "-r", results.pcap, "wlan.fc.type_subtype == 0x0028 && wlan.da == 00:de:ad:be:ef:00"],
#         stdout=subprocess.PIPE, stdin=subprocess.PIPE)
# 
# for l in tshark.stdout:
#     f = l.split(",");
#     v = f[0].split(':');
#     r = float(f[1])
# 
#     rawmcs = int(v[1], 16)
# 
#     ht = (rawmcs & (1 << 7))
#     gi = (rawmcs & (1 << 6))
#     mcs = (rawmcs & 0x3F)
# 
#     location = int(v[2], 16);
# 
#     # Convert to int, and endian flip
#     lpacket = int("{}{}{}".format(v[3], v[4], v[5]), 16)
# 
#     if ht != 0:
#         htstr = "40MHz"
#         ht = 1
#     else:
#         htstr = "20MHz"
# 
#     if gi != 0:
#         gistr = " Short-GI"
#         gi = 1
#     else:
#         gistr = ""
# 
#     # print "Packet {} Location {} MCS {} {}{}".format(lpacket, location, mcs, htstr, gistr)
# 
#     # Only accept packets received at the advertised rate
#     if mcs != 63 and round(r, 1) != float(ratemap[mcs][ht][gi]):
#         #print "rtap {} != mcs {} {} {} {}".format(round(r, 1), float(ratemap[mcs][ht][gi]), mcs, ht, gi)
#         continue
# 
#     if not location in resultmap[mcs][ht][gi]:
#         resultmap[mcs][ht][gi][location] = {}
# 
#     resultmap[mcs][ht][gi][location][lpacket] = 1
# 
# # Extract the calibration packets
# if 63 in resultmap:
#     for l in resultmap[63][1][1]:
#         perc = (float(len(resultmap[63][1][1][l])) / float(results.count)) * 100
# 
#         print "Calibration 1mbit                {:12} {:.2f}%".format(
#                 "Location {}".format(l),
#                 perc)
# 
# for m in range(0, 16):
#     for ht in range(0, 2):
#         for gi in range(0, 2):
#             if ht:
#                 htstr = "40MHz"
#             else:
#                 htstr = "20MHz"
# 
#             if gi:
#                 gistr = "Short-GI"
#             else:
#                 gistr = ""
# 
#             if (len(resultmap[m][ht][gi]) == 0):
#                 print "MCS {:2} {:5} {:8} {:10} {:12} {:.2f}%".format(
#                         m,
#                         htstr,
#                         gistr,
#                         "{} mbit".format(ratemap[m][ht][gi]),
#                         "Location --",
#                         0)
# 
#             for l in resultmap[m][ht][gi]:
#                 perc = (float(len(resultmap[m][ht][gi][l])) / float(results.count)) * 100
# 
#                 print "MCS {:2} {:5} {:8} {:10} {:12} {:.2f}%".format(
#                         m,
#                         htstr,
#                         gistr,
#                         "{} mbit".format(ratemap[m][ht][gi]),
#                         "Location {}".format(l),
#                         perc)
# 
# sys.exit(1)
# 
# 
