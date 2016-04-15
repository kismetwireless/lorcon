import PyLorcon2, sys

if len(sys.argv) < 3:
    print "Expected pcapfile1, pcapfile2"
    sys.exit(1)


pcap1 = PyLorcon2.Context(sys.argv[1], "file")
pcap2 = PyLorcon2.Context(sys.argv[2], "file")

pcap1.open_monitor()
pcap2.open_monitor()

multi = PyLorcon2.Multi()
multi.add_interface(pcap1)
multi.add_interface(pcap2)

print multi.get_interfaces()

def MultiHandler(packet):
    print "Got packet from %s len %d" % (packet.get_interface().get_capiface(), packet.get_length())

multi.loop(0, MultiHandler)

