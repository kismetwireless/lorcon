#!/usr/bin/env python

import sys
import PyLorcon2
import pprint

lorcon = PyLorcon2.Context("./test.pcap", driver="file")

lorcon.open_injmon()

while 1:
    p = lorcon.get_next()
    print "Got packet, len %d dot11 len %d data len %d" % (p.get_length(), p.get_dot11_length(), p.get_payload_length())
    b = p.get_packet()

    pprint.pprint(b)


