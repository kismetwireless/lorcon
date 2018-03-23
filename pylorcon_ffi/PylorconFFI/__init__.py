#!/usr/bin/env python2

from _pylorcon_ffi import ffi
from ctypes import util as ctypesutil

class LorconError(Exception):
    pass

class LorconDriverNotFoundError(LorconError):
    pass

class LorconChannelError(LorconError):
    pass

class LorconTransmitError(LorconError):
    pass

class LorconFFI_Driver:
    def __init__(self, driver):
        if driver == ffi.NULL:
            raise RuntimeError("driver record null")

        self.driver = driver
        self.name = ffi.string(driver.name)
        self.details = ffi.string(driver.details)

    def __str__(self):
        return "LorconDriver [{},{}]".format(self.name, self.details)

class LorconFFI_Channel:
    def __init__(self, complexchan):
        if complexchan == ffi.NULL:
            raise RuntimeError("channel null")

        self.complexchan = complexchan
        self.channel = complexchan.channel
        self.center_1 = complexchan.center_freq_1
        self.center_2 = complexchan.center_freq_2
        self.type = complexchan.type

        self.types = [
            "BASIC",
            "HT20",
            "HT40+",
            "HT40-",
            "W5",
            "W10",
            "VHT80",
            "VHT160",
            "VHT80+80"
            ]

    def __str__(self):
        return "LorconChannel [{}({},{}){}]".format(self.channel, self.center_1, self.center_2, self.types[self.type])

class LorconFFI:
    def __init__(self):
        self.lib = ffi.dlopen("liborcon2-2.0.0.so")

        self.interface = None
        self.driver = ffi.NULL
        self.context = ffi.NULL

    def version(self):
        return self.lib.lorcon_get_version()

    def error(self):
        if self.context == ffi.NULL:
            raise LorconError("not connected to lorcon context")

        return ffi.string(self.lib.lorcon_get_error(self.context))

    def find_driver(self, interface):
        d = self.lib.lorcon_auto_driver(interface)
        if d == ffi.NULL:
            raise LorconDriverNotFoundError("Could not find driver for interface {}".format(interface))
        return d

    def list_drivers(self):
        ret = []
        drivers = self.lib.lorcon_list_drivers()
        driveri = drivers
        while driveri != ffi.NULL:
            pdriver = LorconFFI_Driver(driveri)
            ret.append(pdriver)
            driveri = driveri.next
        self.lib.lorcon_free_driver_list(drivers)
        return ret

    def connect(self, interface, driver = ffi.NULL):
        self.interface = interface

        if driver == ffi.NULL:
            self.driver = self.find_driver(interface)
        else:
            self.driver = driver

        self.context = self.lib.lorcon_create(self.interface, self.driver)

        if self.context == ffi.NULL:
            raise LorconError("Could not connect Lorcon to {}, {}".format(interface, driver))

    def set_vif(self, vif):
        if self.context == ffi.NULL:
            raise LorconError("No open lorcon context")

        self.lib.lorcon_set_vap(self.context, vif)

    def get_vif(self):
        if self.context == ffi.NULL:
            raise LorconError("No open lorcon context")

        return ffi.string(self.lib.lorcon_get_vap(self.context))

    def get_capiface(self):
        if self.context == ffi.NULL:
            raise LorconError("No open lorcon context")

        return ffi.string(self.lib.lorcon_get_capiface(self.context))

    def open_inject(self, interface = None, driver = ffi.NULL):
        if self.context == ffi.NULL:
            self.connect(interface, driver)

        if self.lib.lorcon_open_inject(self.context) < 0:
            raise LorconError("Could not open {} for injection: {}".format(self.interface, self.error()))

    def open_monitor(self, interface = None, driver = ffi.NULL):
        if self.context == ffi.NULL:
            self.connect(interface, driver)

        if self.lib.lorcon_open_monitor(self.context) < 0:
            raise LorconError("Could not open {} for injection: {}".format(self.interface, self.error()))

    def open_injmon(self, interface = None, driver = ffi.NULL):
        if self.context == ffi.NULL:
            self.connect(interface, driver)

        if self.lib.lorcon_open_injmon(self.context) < 0:
            raise LorconError("Could not open {} for injection: {}".format(self.interface, self.error()))

    def ifup(self):
        if self.context == ffi.NULL:
            raise LorconError("No open lorcon context")

        if self.lib.lorcon_ifup(self.context) < 0:
            raise LorconError("Could not bring interface {} up: {}".format(self.interface, self.error()))

    def ifdown(self):
        if self.context == ffi.NULL:
            raise LorconError("No open lorcon context")

        if self.lib.lorcon_ifdown(self.context) < 0:
            raise LorconError("Could not bring interface {} down: {}".format(self.interface, self.error()))

    def parse_channel(self, channel):
        compchan = ffi.new("lorcon_channel_t *")
        ch = ""

        # handle string complex or simple
        if isinstance(channel, int):
            ch = "{}".format(channel)
        elif isinstance(ch, str):
            ch = channel
        else:
            raise LorconError("Expected int or str for channel")

        self.lib.lorcon_parse_ht_channel(ch, compchan)

        if compchan == ffi.NULL:
            raise LorconChannelError("Invalid channel {}: {}".format(channel, self.error()))

        return compchan

    def set_channel(self, channel):
        if self.context == ffi.NULL:
            raise LorconError("No open Lorcon context")

        ch = self.parse_channel(channel)

        if self.lib.lorcon_set_complex_channel(self.context, ch) < 0:
            raise LorconError("Could not set channel {}: {}".format(LorconFFI_Channel(ch), self.error()))

        return True

    def inject(self, data):
        if self.context == ffi.NULL:
            raise LorconError("No open Lorcon context")

        if self.lib.lorcon_send_bytes(self.context, len(data), data) < 0:
            raise LorconTransmitError("Could not tx {} bytes on {}: {}".format(len(data), self.interface, self.error()))

if __name__ == "__main__":
    py = LorconFFI()
    print "Lorcon version", py.version()

    drivers = py.list_drivers()
    for d in drivers:
        print d

    print "Auto-driver for wlx4494fcf30eb3",
    driver = py.find_driver("wlx4494fcf30eb3")
    print LorconFFI_Driver(driver)

    print "Testing channel parsing"
    print LorconFFI_Channel(py.parse_channel("6"))
    print LorconFFI_Channel(py.parse_channel("6W5"))
    print LorconFFI_Channel(py.parse_channel("5260HT40+"))
    print LorconFFI_Channel(py.parse_channel(10))


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

