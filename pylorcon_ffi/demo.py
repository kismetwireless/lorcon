#!/usr/bin/env python2

import PylorconFFI
import sys
import time

if __name__ == "__main__":
    py = PylorconFFI.LorconFFI()
    print "Lorcon version", py.version()

    print "Testing channel parsing"
    print "6", PylorconFFI.LorconFFI_Channel(py.parse_channel("6"))
    print "6W5", PylorconFFI.LorconFFI_Channel(py.parse_channel("6W5"))
    print "5260HT40+", PylorconFFI.LorconFFI_Channel(py.parse_channel("5260HT40+"))
    print "int(10)", PylorconFFI.LorconFFI_Channel(py.parse_channel(10))


    intf = sys.argv[1]

    print "Available drivers:"
    drivers = py.list_drivers()
    for d in drivers:
        print d

    print "Auto-driver for {}".format(intf),
    driver = py.find_driver(intf)
    print PylorconFFI.LorconFFI_Driver(driver)

    print "Connecting to wlx4494fcf30eb3"
    py.connect("wlx4494fcf30eb3")
    print "Setting vif to mon0"
    py.set_vif("mon0")

    print "Opening for inject+monitor"
    py.open_injmon()
    print "OK"

    print "Bringing interface up"
    py.ifup();
    print "OK"

    print "Setting channel 1"
    py.set_channel("1")
    print "OK"

    print "Injecting"
    packet = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    while True:
        py.inject(packet)
        time.sleep(0.5)

