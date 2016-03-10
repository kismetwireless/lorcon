#!/usr/bin/env python

import sys
import PyLorcon2
import pprint
from scapy.all import *

lorcon = PyLorcon2.Context("./test.pcap")

lorcon.open_injmon()

lorcon.set_filter("host 192.168.11.24")

npackets = 0
try:
    while 1:
        p = lorcon.get_next()
        #print "Got packet, len %d dot11 len %d data len %d" % (p.get_length(), p.get_dot11_length(), p.get_data_length())
    
        #b = p.get_dot11()
        #scapypacket = Dot11(b)
    
        #pprint.pprint(scapypacket)
    
        npackets += 1
except:
    print "Could not read packet"

print npackets


