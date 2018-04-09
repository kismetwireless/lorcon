#!/usr/bin/env python2

"""
PyLorcon FFI

A re-implementation of the PyLorcon API using the CFFI
layer, which should greatly simplify the translation
between C and Python.
"""

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
    """ 
    A python representation of a Lorcon Driver
    """
    def __init__(self, driver):
        if driver == ffi.NULL:
            raise RuntimeError("driver record null")

        self.driver = driver
        self.name = ffi.string(driver.name)
        self.details = ffi.string(driver.details)

    def __str__(self):
        return "LorconDriver [{},{}]".format(self.name, self.details)

    def get_driver(self):
        return self.driver


class LorconFFI_Channel:
    """
    A python instance of a complex Lorcon channel
    """
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

    def get_channel(self):
        return self.complexchan

class LorconFFI:
    """
    LorconFFI

    The main Lorcon interface bridge.

    Usage:

        l = LorconFFI()

        # Auto-driver matching
        l.connect("wlan0")

        # Open in injection+monitor
        l.open_injmon()

        # Set channel
        l.set_channel("6")

        # Set complex/HT channel
        l.set_channel("53HT40+")

        # Send some bytes
        l.inject("\x00\x01\x02\x03\x04")
    """

    def __init__(self):
        self.lib = ffi.dlopen("liborcon2-2.0.0.so")

        self.interface = None
        self.driver = ffi.NULL
        self.context = ffi.NULL

        if self.version() < 20180302:
            raise LorconError("The installed LORCON library is too old, make sure to update to the latest lorcon2 to use this API ({} < 20180302)".format(self.version()))

    def version(self):
        """
        Return lorcon library version

        :return: Version string
        """
        return self.lib.lorcon_get_version()

    def error(self):
        """
        Return lorcon error

        :return: Error string

        :throws LorconError: Not connected to Lorcon context
        """
        if self.context == ffi.NULL:
            raise LorconError("not connected to lorcon context")

        return ffi.string(self.lib.lorcon_get_error(self.context))

    def find_driver(self, interface):
        """
        Attempt to find a Lorcon driver for an interface

        :param interface: Wlan interface

        :return: FFI lorcon driver object, wrap with LorconFFI_Driver() to process

        :throws LorconDriverNotFoundError: Unable to find a Lorcon driver
        """
        d = self.lib.lorcon_auto_driver(interface)
        if d == ffi.NULL:
            raise LorconDriverNotFoundError("Could not find driver for interface {}".format(interface))
        return d

    def list_drivers(self):
        """
        List all drivers Lorcon has available

        :return: Array of LorconFFI_Driver objects
        """
        ret = []
        drivers = self.lib.lorcon_list_drivers()
        driveri = drivers
        while driveri != ffi.NULL:
            pdriver = LorconFFI_Driver(driveri)
            ret.append(pdriver)
            driveri = driveri.next
        self.lib.lorcon_free_driver_list(drivers)
        return ret

    def connect(self, interface, driver = None):
        """
        Connect to a Lorcon context; this must be called before setting
        mode, channel, or injecting.

        :param interface: Wlan interface
        :param driver: Optional Lorcon driver

        :returns: None

        :throws LorconError: Unable to connect to lorcon
        :throws LorconDriverNotFoundError: Unable to find a Lorcon driver
        """
        self.interface = interface

        if driver == None:
            self.driver = self.find_driver(interface)
        elif isinstance(driver, LorconFFI_Driver):
            self.driver = driver.get_driver()
        else:
            self.driver = driver

        self.context = self.lib.lorcon_create(self.interface, self.driver)

        if self.context == ffi.NULL:
            raise LorconError("Could not connect Lorcon to {}, {}".format(interface, driver))

    def set_vif(self, vif):
        """
        Set the virtual network interface to be used for monitor mode;
        Lorcon will attempt to figure this out but for extremely long
        interface names under the new naming scheme, a vif must be provided.

        Must be called AFTER connect()

        :param vif: Virtual device interface

        :return: None

        :throws LorconError: No open lorcon context
        """
        if self.context == ffi.NULL:
            raise LorconError("No open lorcon context")

        self.lib.lorcon_set_vap(self.context, vif)

    def get_vif(self):
        """
        Get the virtual network interface being used for monitor mode

        :return: Virtual device interface

        :throws LorconError: No open lorcon context
        """
        if self.context == ffi.NULL:
            raise LorconError("No open lorcon context")

        return ffi.string(self.lib.lorcon_get_vap(self.context))

    def get_capiface(self):
        """
        Get the capture interface being used for receiving packets.
        Typically this will be the same as the vif.

        :return: Capture device interface

        :throws LorconError: No open Lorcon context
        """
        if self.context == ffi.NULL:
            raise LorconError("No open lorcon context")

        return ffi.string(self.lib.lorcon_get_capiface(self.context))

    def open_inject(self, interface = None, driver = ffi.NULL):
        """
        Attempt to open the device in inject mode.  This will open in a
        mode where *at least* inject works; it MAY be possible to also 
        capture in monitor mode.

        :param interface: Optional interface; connect to this interface 
            if not connected to Lorcon already
        :param driver: Optional driver; use this driver if connecting to
            a new interface.
        """
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

