/*
    PyLorcon2 - Python bindings for Lorcon2 library
    Copyright (C) 2010  Core Security Technologies

    This file is part of PyLorcon2.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    Author: Andres Blanco (6e726d)     <6e726d@gmail.com>
    Author: Ezequiel Gutesman (gutes)  <egutesman@gmail.com>
*/


#include <python2.7/Python.h>
#include <lorcon2/lorcon.h>
#include <lorcon2/lorcon_packet.h>
#include <lorcon2/lorcon_multi.h>
#include "PyLorcon2.h"


/*
    ###########################################################################
    
    Module functions
    
    ###########################################################################
*/

PyDoc_STRVAR(PyLorcon2_get_version__doc__, 
    "get_version() -> integer\n\n"
    "Return the lorcon2-version in the format YYYYMMRR (year-month-release #)");

static PyObject*
PyLorcon2_get_version(PyObject *self, PyObject *args);


PyDoc_STRVAR(PyLorcon2_list_drivers__doc__, 
    "list_drivers() -> list\n\n"
    "Return a list of tuples describing the supported drivers");
static PyObject*
PyLorcon2_list_drivers(PyObject *self, PyObject *args);

PyDoc_STRVAR(PyLorcon2_find_driver__doc__, 
    "find_driver(string) -> tuple\n\n"
    "Return a tuple with driver name and description");

static PyObject*
PyLorcon2_find_driver(PyObject *self, PyObject *args);

PyDoc_STRVAR(PyLorcon2_auto_driver__doc__, 
    "auto_driver(string) -> tuple\n\n"
    "Return a tuple with the driver name and description");

static PyObject*
PyLorcon2_auto_driver(PyObject *self, PyObject *args);


/*
    ###########################################################################
    
    Class PyLorcon2
    
    ###########################################################################
*/

static void
PyLorcon2_Context_dealloc(PyLorcon2_Context *self);

static int
PyLorcon2_Context_init(PyLorcon2_Context *self, PyObject *args, PyObject *kwds);

PyDoc_STRVAR(PyLorcon2_Context_open_inject__doc__, 
    "open_inject() -> None\n\n"
    "Set context to injection-mode");
static PyObject*
PyLorcon2_Context_open_inject(PyLorcon2_Context *self);

PyDoc_STRVAR(PyLorcon2_Context_open_monitor__doc__, 
    "open_monitor() -> None\n\n"
    "Set context to monitor-mode");
static PyObject*
PyLorcon2_Context_open_monitor(PyLorcon2_Context *self);


PyDoc_STRVAR(PyLorcon2_Context_open_injmon__doc__, 
    "open_injmon() -> None\n\n"
    "Set context to injection- and monitor-mode");
static PyObject*
PyLorcon2_Context_open_injmon(PyLorcon2_Context *self);

PyDoc_STRVAR(PyLorcon2_Context_close__doc__, 
    "close() -> None\n\n"
    "Close context");
static PyObject*
PyLorcon2_Context_close(PyLorcon2_Context *self);

PyDoc_STRVAR(PyLorcon2_Context_get_error__doc__, 
    "get_error() -> string\n\n"
    "Return last error message generated for this context");
static PyObject*
PyLorcon2_Context_get_error(PyLorcon2_Context *self);

PyDoc_STRVAR(PyLorcon2_Context_get_capiface__doc__, 
    "get_capiface() -> string\n\n"
    "Return the interface for this context");
static PyObject*
PyLorcon2_Context_get_capiface(PyLorcon2_Context *self);

PyDoc_STRVAR(PyLorcon2_Context_send_bytes__doc__, 
    "send_bytes(object) -> integer\n\n"
    "Send the string-representation of the given object");
static PyObject*
PyLorcon2_Context_send_bytes(PyLorcon2_Context *self, PyObject *args, PyObject *kwds);

PyDoc_STRVAR(PyLorcon2_Context_set_timeout__doc__, 
    "set_timeout(integer) -> None\n\n"
    "Set the timeout for this context");
static PyObject*
PyLorcon2_Context_set_timeout(PyLorcon2_Context *self, PyObject *args, PyObject *kwds);

PyDoc_STRVAR(PyLorcon2_Context_get_timeout__doc__, 
    "get_timeout() -> integer\n\n"
    "Get the timeout for this context");
static PyObject*
PyLorcon2_Context_get_timeout(PyLorcon2_Context *self);

PyDoc_STRVAR(PyLorcon2_Context_set_vap__doc__, 
    "set_vap() -> string\n\n"
    "Set the vap for this context");
static PyObject*
PyLorcon2_Context_set_vap(PyLorcon2_Context *self, PyObject *args, PyObject *kwds);

PyDoc_STRVAR(PyLorcon2_Context_get_vap__doc__, 
    "get_vap() -> string\n\n"
    "Get the vap for this context");
static PyObject*
PyLorcon2_Context_get_vap(PyLorcon2_Context *self);

PyDoc_STRVAR(PyLorcon2_Context_get_driver_name__doc__, 
    "get_driver_name() -> string\n\n"
    "Get the driver-name for this context");
static PyObject*
PyLorcon2_Context_get_driver_name(PyLorcon2_Context *self);

PyDoc_STRVAR(PyLorcon2_Context_set_channel__doc__, 
    "set_channel(integer) -> None\n\n"
    "Set the channel for this context");
static PyObject*
PyLorcon2_Context_set_channel(PyLorcon2_Context *self, PyObject *args, PyObject *kwds);

PyDoc_STRVAR(PyLorcon2_Context_get_channel__doc__, 
    "get_channel() -> integer\n\n"
    "Get the channel for this context");
static PyObject*
PyLorcon2_Context_get_channel(PyLorcon2_Context *self);

PyDoc_STRVAR(PyLorcon2_Context_get_hwmac__doc__, 
    "get_hwmac() -> tuple\n\n"
    "Get the hardware MAC for this context");
static PyObject*
PyLorcon2_Context_get_hwmac(PyLorcon2_Context *self);

PyDoc_STRVAR(PyLorcon2_Context_set_hwmac__doc__, 
    "set_hwmac(tuple) -> None\n\n"
    "Set the hardware MAC for this context");
static PyObject*
PyLorcon2_Context_set_hwmac(PyLorcon2_Context *self, PyObject *args, PyObject *kwds);

PyDoc_STRVAR(PyLorcon2_Context_get_next__doc__, 
    "set_packet_callback() -> packet\n\n"
    "Fetch the next packet (blocking)");
static PyObject *
PyLorcon2_Context_get_next(PyLorcon2_Context *self);

PyDoc_STRVAR(PyLorcon2_Context_set_filter__doc__, 
    "set_filter(object) -> integer\n\n"
    "Set a pcap BPF filter");
static PyObject*
PyLorcon2_Context_set_filter(PyLorcon2_Context *self, PyObject *args, PyObject *kwds);

/*
    ###########################################################################
    
    Packet access
    
    ###########################################################################
*/

PyDoc_STRVAR(PyLorcon2Packet_get_time_sec__doc__, 
    "get_time_sec() -> integer\n\n"
    "Return the packet timestamp, seconds");
static PyObject*
PyLorcon2_Packet_get_time_sec(PyLorcon2_Packet *self);

PyDoc_STRVAR(PyLorcon2Packet_get_time_usec__doc__, 
    "get_time_usec() -> integer\n\n"
    "Return the packet timestamp, useconds");
static PyObject*
PyLorcon2_Packet_get_time_usec(PyLorcon2_Packet *self);

PyDoc_STRVAR(PyLorcon2Packet_get_length__doc__, 
    "get_length() -> integer\n\n"
    "Return the packet record total length including per-packet headers");
static PyObject*
PyLorcon2_Packet_get_length(PyLorcon2_Packet *self);

PyDoc_STRVAR(PyLorcon2Packet_get_dot11_length__doc__, 
    "get_header_length() -> integer\n\n"
    "Return the packet record length after removing per-packet headers");
static PyObject*
PyLorcon2_Packet_get_dot11_length(PyLorcon2_Packet *self);

PyDoc_STRVAR(PyLorcon2Packet_get_payload_length__doc__, 
    "get_payload_length() -> integer\n\n"
    "Return the packet record data component length");
static PyObject*
PyLorcon2_Packet_get_payload_length(PyLorcon2_Packet *self);

PyDoc_STRVAR(PyLorcon2Packet_get_packet__doc__, 
    "get_packet() -> array\n\n"
    "Return an array of the total packet as captured");
static PyObject*
PyLorcon2_Packet_get_packet(PyLorcon2_Packet *self);

PyDoc_STRVAR(PyLorcon2Packet_get_dot11__doc__, 
    "get_packet_dot11() -> array\n\n"
    "Return an array of the packet starting at the dot11 header");
static PyObject*
PyLorcon2_Packet_get_dot11(PyLorcon2_Packet *self);

PyDoc_STRVAR(PyLorcon2Packet_get_data_payload__doc__, 
    "get_packet_data_payload() -> array\n\n"
    "Return an array of the packet starting at the data payload");
static PyObject*
PyLorcon2_Packet_get_data_payload(PyLorcon2_Packet *self);

PyDoc_STRVAR(PyLorcon2Packet_get_interface__doc__,
    "get_interface() -> PyLorcon2.Context\n\n"
    "Return the context which saw this packet");
static PyObject*
PyLorcon2_Packet_get_interface(PyLorcon2_Packet *self);

/* Multi-cap */
static int PyLorcon2_Multi_init(PyLorcon2_Multi *self, PyObject *args, PyObject *kwds);
static void PyLorcon2_Multi_dealloc(PyLorcon2_Multi *self);

PyDoc_STRVAR(PyLorcon2Multi_get_error__doc__,
    "get_error() -> String\n\n"
    "Return last error");
static PyObject*
PyLorcon2_Multi_get_error(PyLorcon2_Multi *self);

PyDoc_STRVAR(PyLorcon2Multi_add_interface__doc__,
    "add_interface(Lorcon2.Context) -> None\n\n"
    "Add an (opened!) lorcon2 interface to the multicapture");
static PyObject*
PyLorcon2_Multi_add_interface(PyLorcon2_Multi *self, PyObject *args);

PyDoc_STRVAR(PyLorcon2Multi_del_interface__doc__,
    "del_interface(Lorcon2.Context) -> None\n\n"
    "Remove an interface from the multicapture");
static PyObject*
PyLorcon2_Multi_del_interface(PyLorcon2_Multi *self, PyObject *args);

PyDoc_STRVAR(PyLorcon2Multi_get_interfaces__doc__,
    "get_interfaces() -> vector<Lorcon2.Context>\n\n"
    "Return a list of interfaces in the multicapture");
static PyObject*
PyLorcon2_Multi_get_interfaces(PyLorcon2_Multi *self);

PyDoc_STRVAR(PyLorcon2Multi_loop__doc__,
    "loop(count, callback) -> Integer\n\n"
    "Loop on all interfaces, calling the callback function on each "
    "packet.  Callbacks should be:\n"
    "def MultiCallback(packet)\n"
    "Processes `count' packets (0 for infinite)");
static PyObject*
PyLorcon2_Multi_loop(PyLorcon2_Multi *self, PyObject *args);

PyDoc_STRVAR(PyLorcon2Multi_get_multi_ptr__doc__,
    "get_multi_ptr() -> Capsule Object\n\n"
    "Return a C pointer to the multicapture internal object.  This exists "
    "solely to integrate with other native libraries via python native "
    "glue and should not be called from Python code.");
static PyObject*
PyLorcon2_Multi_get_multi_ptr(PyLorcon2_Multi *self);

PyDoc_STRVAR(PyLorcon2Multi_set_interface_error_cb__doc__,
    "set_interface_error_cb(callback) -> None\n\n"
    "Set a callback function to be called if an interface encounters an "
    "error.  Callbacks should be:\n"
    "def ErrorCallback(Lorcon2.Multi, Lorcon2.Context)");
static PyObject *
PyLorcon2_Multi_set_interface_error_cb(PyLorcon2_Multi *self, PyObject *args);

PyDoc_STRVAR(PyLorcon2Multi_remove_interface_error_cb__doc__,
    "remove_interface_error_cb() -> None\n\n"
    "Remove error callback");
static PyObject *
PyLorcon2_Multi_remove_interface_error_cb(PyLorcon2_Multi *self, PyObject *args);

/*
    ###########################################################################
    
    Class PyLorcon2Packet
    
    ###########################################################################
*/

static void
PyLorcon2_Packet_dealloc(PyLorcon2_Packet *self);

static int
PyLorcon2_Packet_init(PyLorcon2_Packet *self, PyObject *args, PyObject *kwds);

/*
    ###########################################################################
    
    Packet Definitions
    
    ###########################################################################
*/
static PyMethodDef PyLorcon2_Packet_Methods[] =
{
    {"get_time_sec", (PyCFunction) PyLorcon2_Packet_get_time_sec, 
        METH_NOARGS, PyLorcon2Packet_get_time_sec__doc__},
    {"get_time_usec", (PyCFunction) PyLorcon2_Packet_get_time_usec, 
        METH_NOARGS, PyLorcon2Packet_get_time_usec__doc__},
    {"get_length", (PyCFunction) PyLorcon2_Packet_get_length, 
        METH_NOARGS, PyLorcon2Packet_get_length__doc__},
    {"get_dot11_length", (PyCFunction) PyLorcon2_Packet_get_dot11_length, 
        METH_NOARGS, PyLorcon2Packet_get_dot11_length__doc__},
    {"get_payload_length", (PyCFunction) PyLorcon2_Packet_get_payload_length, 
        METH_NOARGS, PyLorcon2Packet_get_payload_length__doc__},
    {"get_packet", (PyCFunction) PyLorcon2_Packet_get_packet, 
        METH_NOARGS, PyLorcon2Packet_get_packet__doc__},
    {"get_dot11", (PyCFunction) PyLorcon2_Packet_get_dot11, 
        METH_NOARGS, PyLorcon2Packet_get_dot11__doc__},
    {"get_data_payload", (PyCFunction) PyLorcon2_Packet_get_data_payload, 
        METH_NOARGS, PyLorcon2Packet_get_data_payload__doc__},
    {"get_interface", (PyCFunction) PyLorcon2_Packet_get_interface, 
        METH_NOARGS, PyLorcon2Packet_get_interface__doc__},
    { NULL, NULL, 0, NULL }
};

static PyTypeObject PyLorcon2_PacketType = {
    PyObject_HEAD_INIT(NULL)
    0,                                        /* ob_size */
    "PyLorcon2.Packet",                       /* tp_name */
    sizeof(PyLorcon2_Packet),                 /* tp_basic_size */
    0,                                        /* tp_itemsize */
    (destructor)PyLorcon2_Packet_dealloc,     /* tp_dealloc */
    0,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_compare */
    0,                                        /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash */
    0,                                        /* tp_call */
    0,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "PyLorcon2 Packet Object",                /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    PyLorcon2_Packet_Methods,                 /* tp_methods */
    0,                                        /* tp_members */
    0,                                        /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    (initproc)PyLorcon2_Packet_init,          /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};

/*
    ###########################################################################
    
    Packet Definitions
    
    ###########################################################################
*/
static PyMethodDef PyLorcon2_Multi_Methods[] =
{
    {"get_error", (PyCFunction) PyLorcon2_Multi_get_error,
        METH_NOARGS, PyLorcon2Multi_get_error__doc__},
    {"add_interface", (PyCFunction) PyLorcon2_Multi_add_interface,
        METH_VARARGS, PyLorcon2Multi_add_interface__doc__ },
    {"del_interface", (PyCFunction) PyLorcon2_Multi_del_interface,
        METH_VARARGS, PyLorcon2Multi_del_interface__doc__ },
    {"get_interfaces", (PyCFunction) PyLorcon2_Multi_get_interfaces,
        METH_NOARGS, PyLorcon2Multi_get_interfaces__doc__ },
    {"loop", (PyCFunction) PyLorcon2_Multi_loop,
        METH_VARARGS, PyLorcon2Multi_loop__doc__ },
    {"get_multi_ptr", (PyCFunction) PyLorcon2_Multi_get_multi_ptr,
        METH_NOARGS, PyLorcon2Multi_get_multi_ptr__doc__ },
    {"set_interface_error_cb", (PyCFunction) PyLorcon2_Multi_set_interface_error_cb,
        METH_VARARGS, PyLorcon2Multi_set_interface_error_cb__doc__ },
    {"remove_interface_error_cb", 
        (PyCFunction) PyLorcon2_Multi_remove_interface_error_cb,
        METH_VARARGS, PyLorcon2Multi_remove_interface_error_cb__doc__ },
    { NULL, NULL, 0, NULL }
};

static PyTypeObject PyLorcon2_MultiType = {
    PyObject_HEAD_INIT(NULL)
    0,                                        /* ob_size */
    "PyLorcon2.Multi",                        /* tp_name */
    sizeof(PyLorcon2_Multi),                  /* tp_basic_size */
    0,                                        /* tp_itemsize */
    (destructor)PyLorcon2_Multi_dealloc,      /* tp_dealloc */
    0,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_compare */
    0,                                        /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash */
    0,                                        /* tp_call */
    0,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "PyLorcon2 Multicap",                     /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    PyLorcon2_Multi_Methods,                  /* tp_methods */
    0,                                        /* tp_members */
    0,                                        /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    (initproc)PyLorcon2_Multi_init,           /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};

/*
    ###########################################################################
    
    Definitions
    
    ###########################################################################
*/

static PyMethodDef PyLorcon2Methods[] =
{
    {"get_version",  PyLorcon2_get_version,  
        METH_NOARGS,  PyLorcon2_get_version__doc__},
    {"list_drivers", PyLorcon2_list_drivers, 
        METH_NOARGS,  PyLorcon2_list_drivers__doc__},
    {"find_driver",  PyLorcon2_find_driver,  
        METH_VARARGS, PyLorcon2_find_driver__doc__},
    {"auto_driver",  PyLorcon2_auto_driver,  
        METH_VARARGS, PyLorcon2_auto_driver__doc__},
    {NULL, NULL, 0, NULL}
};

static PyMethodDef PyLorcon2_Context_Methods[] =
{
    {"open_inject",     (PyCFunction)PyLorcon2_Context_open_inject,     METH_NOARGS,  PyLorcon2_Context_open_inject__doc__},
    {"open_monitor",    (PyCFunction)PyLorcon2_Context_open_monitor,    METH_NOARGS,  PyLorcon2_Context_open_monitor__doc__},
    {"open_injmon",     (PyCFunction)PyLorcon2_Context_open_injmon,     METH_NOARGS,  PyLorcon2_Context_open_injmon__doc__},
    {"close",           (PyCFunction)PyLorcon2_Context_close,           METH_NOARGS,  PyLorcon2_Context_close__doc__},
    {"get_error",       (PyCFunction)PyLorcon2_Context_get_error,       METH_NOARGS,  PyLorcon2_Context_get_error__doc__},
    {"get_capiface",    (PyCFunction)PyLorcon2_Context_get_capiface,    METH_NOARGS,  PyLorcon2_Context_get_capiface__doc__},
    {"send_bytes",      (PyCFunction)PyLorcon2_Context_send_bytes,      METH_VARARGS, PyLorcon2_Context_send_bytes__doc__},
    {"set_filter",      (PyCFunction)PyLorcon2_Context_set_filter,      METH_VARARGS, PyLorcon2_Context_set_filter__doc__},
    {"set_timeout",     (PyCFunction)PyLorcon2_Context_set_timeout,
                        METH_VARARGS | METH_KEYWORDS, PyLorcon2_Context_set_timeout__doc__},
    {"get_timeout",     (PyCFunction)PyLorcon2_Context_get_timeout,     METH_NOARGS,  PyLorcon2_Context_get_timeout__doc__},
    {"set_vap",         (PyCFunction)PyLorcon2_Context_set_vap,
                        METH_VARARGS | METH_KEYWORDS, PyLorcon2_Context_set_vap__doc__},
    {"get_vap",         (PyCFunction)PyLorcon2_Context_get_vap,         METH_NOARGS,  PyLorcon2_Context_get_vap__doc__},
    {"get_driver_name", (PyCFunction)PyLorcon2_Context_get_driver_name, METH_NOARGS,  PyLorcon2_Context_get_driver_name__doc__},
    {"set_channel",     (PyCFunction)PyLorcon2_Context_set_channel,     METH_VARARGS, PyLorcon2_Context_set_channel__doc__},
    {"get_channel",     (PyCFunction)PyLorcon2_Context_get_channel,     METH_NOARGS,  PyLorcon2_Context_get_channel__doc__},
    {"set_hwmac",       (PyCFunction)PyLorcon2_Context_set_hwmac,       METH_VARARGS, PyLorcon2_Context_set_hwmac__doc__},
    {"get_hwmac",       (PyCFunction)PyLorcon2_Context_get_hwmac,       METH_NOARGS,  PyLorcon2_Context_get_hwmac__doc__},
    {"get_next",        (PyCFunction)PyLorcon2_Context_get_next,        METH_NOARGS,  PyLorcon2_Context_get_next__doc__},
    {NULL, NULL, 0, NULL}
};

static PyTypeObject PyLorcon2_ContextType = {
    PyObject_HEAD_INIT(NULL)
    0,                                        /* ob_size */
    "PyLorcon2.Context",                      /* tp_name */
    sizeof(PyLorcon2_Context),                /* tp_basic_size */
    0,                                        /* tp_itemsize */
    (destructor)PyLorcon2_Context_dealloc,    /* tp_dealloc */
    0,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_compare */
    0,                                        /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash */
    0,                                        /* tp_call */
    0,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "PyLorcon2 Context Object",               /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    PyLorcon2_Context_Methods,                /* tp_methods */
    0,                                        /* tp_members */
    0,                                        /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    (initproc)PyLorcon2_Context_init,         /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};


/*
    ###########################################################################
    
    Module initialization
    
    ###########################################################################
*/

PyMODINIT_FUNC
initPyLorcon2(void)
{
    PyObject *m;

    if(PyType_Ready(&PyLorcon2_ContextType) < 0)
        return;

    if(PyType_Ready(&PyLorcon2_PacketType) < 0)
        return;

    if(PyType_Ready(&PyLorcon2_MultiType) < 0)
        return;

    m = Py_InitModule3("PyLorcon2", PyLorcon2Methods, "Wrapper for the Lorcon2 library");

    if(m == NULL)
        return;

    /* Lorcon2 Exception */
    Lorcon2Exception = PyErr_NewException("PyLorcon2.Lorcon2Exception", NULL, NULL);
    Py_INCREF(Lorcon2Exception);
    PyModule_AddObject(m, "Lorcon2Exception", Lorcon2Exception);

    /* Lorcon2 Context Object */
    Py_INCREF(&PyLorcon2_ContextType);
    PyLorcon2_ContextType.tp_getattro = PyObject_GenericGetAttr;
    PyLorcon2_ContextType.tp_setattro = PyObject_GenericSetAttr;
    PyLorcon2_ContextType.tp_alloc  = PyType_GenericAlloc;
    PyLorcon2_ContextType.tp_new = PyType_GenericNew;
    PyLorcon2_ContextType.tp_free = _PyObject_Del;
    PyModule_AddObject(m, "Context", (PyObject*)&PyLorcon2_ContextType);

    /* Lorcon2 Multicap Object */
    Py_INCREF(&PyLorcon2_MultiType);
    PyLorcon2_MultiType.tp_getattro = PyObject_GenericGetAttr;
    PyLorcon2_MultiType.tp_setattro = PyObject_GenericSetAttr;
    PyLorcon2_MultiType.tp_alloc  = PyType_GenericAlloc;
    PyLorcon2_MultiType.tp_new = PyType_GenericNew;
    PyLorcon2_MultiType.tp_free = _PyObject_Del;
    PyModule_AddObject(m, "Multi", (PyObject*)&PyLorcon2_MultiType);

    /* Lorcon2 Packet Object */
    Py_INCREF(&PyLorcon2_PacketType);
    PyLorcon2_PacketType.tp_getattro = PyObject_GenericGetAttr;
    PyLorcon2_PacketType.tp_setattro = PyObject_GenericSetAttr;
    PyLorcon2_PacketType.tp_alloc  = PyType_GenericAlloc;
    PyLorcon2_PacketType.tp_new = PyType_GenericNew;
    PyLorcon2_PacketType.tp_free = _PyObject_Del;
    PyModule_AddObject(m, "Packet", (PyObject*)&PyLorcon2_PacketType);
}

static PyObject*
PyLorcon2_get_version(PyObject *self, PyObject *args)
{
    return PyInt_FromLong(lorcon_get_version());
}

static PyObject*
PyLorcon2_list_drivers(PyObject *self, PyObject *args)
{
    PyObject *retval, *entry;
    lorcon_driver_t *driver_list, *driver;
    
    driver = driver_list = lorcon_list_drivers();
    if (!driver) {
        PyErr_SetString(Lorcon2Exception, "Unable to get driver-list");
        return NULL;
    }

    retval = PyList_New(0);
    if (!retval) {
        lorcon_free_driver_list(driver_list);
        return PyErr_NoMemory();
    }

    while(driver) {
        entry = PyTuple_New(2);

        PyTuple_SetItem(entry, 0, PyString_FromString(driver->name));
        PyTuple_SetItem(entry, 1, PyString_FromString(driver->details));

        PyList_Append(retval, entry);
        Py_DECREF(entry);

        driver = driver->next;
    }

    lorcon_free_driver_list(driver_list);

    return retval;
}

static PyObject*
PyLorcon2_find_driver(PyObject *self, PyObject *args)
{
    char *name;
    PyObject* retval;
    lorcon_driver_t *driver;

    if (!PyArg_ParseTuple(args, "s", &name))
        return NULL;

    driver = lorcon_find_driver(name);
    if (!driver) {
        PyErr_SetString(Lorcon2Exception, "Unable to get driver-list");
        return NULL;
    }

    retval = PyTuple_New(2);
    if (!retval) {
        lorcon_free_driver_list(driver);
        return PyErr_NoMemory();
    }
    
    PyTuple_SetItem(retval, 0, PyString_FromString(driver->name));
    PyTuple_SetItem(retval, 1, PyString_FromString(driver->details));

    lorcon_free_driver_list(driver);

    return retval;
}

static PyObject*
PyLorcon2_auto_driver(PyObject *self, PyObject *args)
{
    char *iface;
    PyObject* retval;
    lorcon_driver_t *driver;

    if (!PyArg_ParseTuple(args, "s", &iface))
        return NULL;

    driver = lorcon_auto_driver(iface);
    if (!driver) {
        PyErr_SetString(Lorcon2Exception, "Unable to get driver");
        return NULL;
    }

    retval = PyTuple_New(2);
    if (!retval) {
        lorcon_free_driver_list(driver);
        return PyErr_NoMemory();
    }
    
    PyTuple_SetItem(retval, 0, PyString_FromString(driver->name));
    PyTuple_SetItem(retval, 1, PyString_FromString(driver->details));

    lorcon_free_driver_list(driver);

    return retval;
}

static void
PyLorcon2_Context_dealloc(PyLorcon2_Context *self)
{
    if(self->context != NULL && self->free_on_cleanup)
        lorcon_free(self->context);
    self->ob_type->tp_free((PyObject*)self);
}

static int
PyLorcon2_Context_init(PyLorcon2_Context *self, PyObject *args, PyObject *kwds)
{
    lorcon_driver_t *driver;
    static char *kwlist[] = {"iface", "driver", NULL};
    char *iface = NULL, *drivername = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|ss", kwlist, &iface, &drivername)) {
        self->context = NULL;
        self->monitored = 0;
        return -1;
    }

    /* If we didn't get an interface, make a stub context */
    if (iface == NULL) {
        self->context = NULL;
        self->monitored = 0;
        self->free_on_cleanup = 0;
        return 0;
    }

    if (drivername == NULL) {
        driver = lorcon_auto_driver(iface);
    } else {
        driver = lorcon_find_driver(drivername);
    }

    if (!driver) {
        PyErr_SetString(Lorcon2Exception, "Unable to get driver");
        return -1;
    }

    self->context = lorcon_create(iface, driver);

    lorcon_free_driver_list(driver);

    if (!self->context) {
        PyErr_SetString(Lorcon2Exception, "Unable to create lorcon context");
        return -1;
    }
    
    self->monitored = 0;
    lorcon_set_timeout(self->context, 100);

    self->free_on_cleanup = 1;

    return 0;
}

static PyObject*
PyLorcon2_Context_open_inject(PyLorcon2_Context *self)
{
    if (lorcon_open_inject(self->context) < 0) {
        PyErr_SetString(Lorcon2Exception, lorcon_get_error(self->context));
        return NULL;
    }

    self->monitored = 1;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject*
PyLorcon2_Context_open_monitor(PyLorcon2_Context *self)
{
    if (lorcon_open_monitor(self->context) < 0) {
        PyErr_SetString(Lorcon2Exception, lorcon_get_error(self->context));
        return NULL;
    }
    
    self->monitored = 1;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject*
PyLorcon2_Context_open_injmon(PyLorcon2_Context *self)
{
    if (lorcon_open_injmon(self->context) < 0) {
        PyErr_SetString(Lorcon2Exception, lorcon_get_error(self->context));
        return NULL;
    }
    
    self->monitored = 1;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject*
PyLorcon2_Context_close(PyLorcon2_Context *self)
{
    lorcon_close(self->context);
    
    self->monitored = 0;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject*
PyLorcon2_Context_get_error(PyLorcon2_Context *self)
{
    return PyString_FromString(lorcon_get_error(self->context));
}

static PyObject*
PyLorcon2_Context_get_capiface(PyLorcon2_Context *self)
{
    return PyString_FromString(lorcon_get_capiface(self->context));
}

static PyObject*
PyLorcon2_Context_send_bytes(PyLorcon2_Context *self, PyObject *args, PyObject *kwds)
{
    char *pckt_buffer;
    ssize_t pckt_size, sent;
    PyObject *pckt, *pckt_string;

    if (!PyArg_ParseTuple(args, "O", &pckt))
        return NULL;
    
    if (!self->monitored) {
        PyErr_SetString(PyExc_RuntimeError, "Context must be in monitor/injection-mode");
        return NULL;
    }

    pckt_string = PyObject_Str(pckt);
    if (!pckt_string) {
        PyErr_SetString(PyExc_ValueError, "Failed to get string-representation from object.");
        return NULL;
    }

    if (PyString_AsStringAndSize(pckt_string, &pckt_buffer, &pckt_size)) {
        Py_DECREF(pckt_string);
        return NULL;
    }

    sent = lorcon_send_bytes(self->context, pckt_size, (u_char*)pckt_buffer);
    if (sent < 0) {
        PyErr_SetString(Lorcon2Exception, lorcon_get_error(self->context));
        Py_DECREF(pckt_string);
        return NULL;
    }
    
    Py_DECREF(pckt_string);
    
    return PyInt_FromLong(sent);
}

static PyObject*
PyLorcon2_Context_set_filter(PyLorcon2_Context *self, PyObject *args, PyObject *kwds)
{
    char *filter_buffer;
    ssize_t filter_size;

    PyObject *filter, *filter_string;
    int ret;

    if (!PyArg_ParseTuple(args, "O", &filter))
        return NULL;
   
    filter_string = PyObject_Str(filter);
    if (!filter_string) {
        PyErr_SetString(PyExc_ValueError, "Failed to get string filter");
        return NULL;
    }

    if (PyString_AsStringAndSize(filter_string, &filter_buffer, &filter_size)) {
        Py_DECREF(filter_string);
        return NULL;
    }

    ret = lorcon_set_filter(self->context, filter_buffer);

    if (ret < 0) {
        PyErr_SetString(Lorcon2Exception, lorcon_get_error(self->context));
        Py_DECREF(filter_string);
        return NULL;
    }
    
    Py_DECREF(filter_string);
    
    return PyInt_FromLong(ret);
}

static PyObject*
PyLorcon2_Context_set_timeout(PyLorcon2_Context *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"timeout", NULL};
    int timeout;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist, &timeout))
        return NULL;

    lorcon_set_timeout(self->context, timeout);

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject*
PyLorcon2_Context_get_timeout(PyLorcon2_Context *self)
{
    return PyInt_FromLong(lorcon_get_timeout(self->context));
}

static PyObject*
PyLorcon2_Context_set_vap(PyLorcon2_Context *self, PyObject *args, PyObject *kwds)
{
    char *vap;
    static char *kwlist[] = {"vap", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &vap))
        return NULL;

    lorcon_set_vap(self->context, vap); 

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject*
PyLorcon2_Context_get_vap(PyLorcon2_Context *self)
{
    return PyString_FromString(lorcon_get_vap(self->context));
}

static PyObject*
PyLorcon2_Context_get_driver_name(PyLorcon2_Context *self)
{
    return PyString_FromString(lorcon_get_driver_name(self->context));
}

static PyObject*
PyLorcon2_Context_set_channel(PyLorcon2_Context *self, PyObject *args, PyObject *kwds)
{
    int channel;

    if (!PyArg_ParseTuple(args, "i", &channel))
        return NULL;

    if (!self->monitored) {
        PyErr_SetString(PyExc_RuntimeError, "Context must be in monitor/injection-mode");
        return NULL;
    }

    if (lorcon_set_channel(self->context, channel) != 0) {
        PyErr_SetString(Lorcon2Exception, lorcon_get_error(self->context));
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject*
PyLorcon2_Context_get_channel(PyLorcon2_Context *self)
{
    int channel;

    channel = lorcon_get_channel(self->context);
    if (channel < 0) {
        PyErr_SetString(Lorcon2Exception, lorcon_get_error(self->context));
        return NULL;
    }

    return PyInt_FromLong(channel);
}

static PyObject*
PyLorcon2_Context_get_hwmac(PyLorcon2_Context *self)
{
    int r;
    uint8_t *mac;
    PyObject *ret;

    r = lorcon_get_hwmac(self->context, &mac);
    if (r < 0) {
        PyErr_SetString(Lorcon2Exception, lorcon_get_error(self->context));
        ret = NULL;
    } else if (r == 0) {
        Py_INCREF(Py_None);
        ret = Py_None;
    } else {
        ret = Py_BuildValue("(i,i,i,i,i,i)", 
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        free(mac);
    }

    return ret;
}

static PyObject*
PyLorcon2_Context_set_hwmac(PyLorcon2_Context *self, PyObject *args, PyObject *kwds)
{
    PyObject *mac_tuple;
    uint8_t mac[6];
    int i;

    if (!PyArg_ParseTuple(args, "O!", &PyTuple_Type, &mac_tuple))
        return NULL;

    if (!self->monitored) {
        PyErr_SetString(PyExc_RuntimeError, "Context must be in monitor/injection-mode");
        return NULL;
    }
    
    if (PyTuple_Size(mac_tuple) != 6) {
        PyErr_SetString(PyExc_ValueError, "Parameter must be a tuple of 6 integers");
        return NULL;
    }
    
    for (i = 0; i < 6; i++) {
        mac[i] = (uint8_t)PyInt_AsLong(PyTuple_GetItem(mac_tuple, i));
        if (mac[i] == -1) {
            PyErr_SetString(PyExc_ValueError, "Tuple-entry is not convertible to integer");
            return NULL;
        }
    }
    
    if (lorcon_set_hwmac(self->context, 6, mac) < 0) {
        PyErr_SetString(Lorcon2Exception, lorcon_get_error(self->context));
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
PyLorcon2_Context_get_next(PyLorcon2_Context *self) {
    int ret;
    lorcon_packet_t *l_packet;
    PyObject *arg_tuple;

    ret = lorcon_next_ex(self->context, &l_packet);

    if (ret <= 0) {
        PyErr_SetString(PyExc_RuntimeError, "Could not get next packet");
        return NULL;
    }

    arg_tuple = PyTuple_New(0);

    PyObject *obj = PyObject_CallObject((PyObject *) &PyLorcon2_PacketType, arg_tuple);
    ((PyLorcon2_Packet *) obj)->packet = l_packet;

    Py_DECREF(arg_tuple);

    return obj;

}

static PyObject*
PyLorcon2_Packet_get_time_sec(PyLorcon2_Packet *self)
{
    long int timesec;
    if (self->packet == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Packet not built");
        return NULL;
    }
    timesec = self->packet->ts.tv_sec;
    return PyInt_FromLong(timesec);
}

static PyObject*
PyLorcon2_Packet_get_time_usec(PyLorcon2_Packet *self)
{
    long int timesec;
    if (self->packet == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Packet not built");
        return NULL;
    }
    timesec = self->packet->ts.tv_usec;
    return PyInt_FromLong(timesec);
}

static PyObject*
PyLorcon2_Packet_get_length(PyLorcon2_Packet *self)
{
    long int length;
    if (self->packet == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Packet not built");
        return NULL;
    }
    length = self->packet->length;
    return PyInt_FromLong(length);
}

static PyObject*
PyLorcon2_Packet_get_dot11_length(PyLorcon2_Packet *self)
{
    long int length;
    if (self->packet == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Packet not built");
        return NULL;
    }
    length = self->packet->length_header;
    return PyInt_FromLong(length);
}

static PyObject*
PyLorcon2_Packet_get_payload_length(PyLorcon2_Packet *self)
{
    long int length;
    if (self->packet == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Packet not built");
        return NULL;
    }
    length = self->packet->length_data;
    return PyInt_FromLong(length);
}

static void
PyLorcon2_Packet_dealloc(PyLorcon2_Packet *self)
{
    if(self->packet != NULL)
        lorcon_packet_free(self->packet);

    self->ob_type->tp_free((PyObject*)self);
}

static int
PyLorcon2_Packet_init(PyLorcon2_Packet *self, PyObject *args, PyObject *kwds)
{
    self->packet = NULL;
    
    return 0;
}

static PyObject*
PyLorcon2_Packet_get_packet(PyLorcon2_Packet *self) {

    if (self->packet == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Packet not built");
        return NULL;
    }

    return PyByteArray_FromStringAndSize((const char *) self->packet->packet_raw, 
            self->packet->length);
}

static PyObject*
PyLorcon2_Packet_get_dot11(PyLorcon2_Packet *self) {
    if (self->packet == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Packet not built");
        return NULL;
    }

    return PyByteArray_FromStringAndSize((const char *) self->packet->packet_header, 
            self->packet->length_header);
}

static PyObject*
PyLorcon2_Packet_get_data_payload(PyLorcon2_Packet *self) {
    if (self->packet == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Packet not built");
        return NULL;
    }

    return PyByteArray_FromStringAndSize((const char *) self->packet->packet_data, 
            self->packet->length_data);
}

static PyObject *
PyLorcon2_Packet_get_interface(PyLorcon2_Packet *self) {
    PyObject *arg_tuple, *obj;

    if (self->packet == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Packet not built");
        return NULL;
    }

    /* Make a context object that doesn't free its internal structure when the
     * python object goes away by wedging it */
    arg_tuple = PyTuple_New(0);
    obj = PyObject_CallObject((PyObject *) &PyLorcon2_ContextType, arg_tuple);
    ((PyLorcon2_Context *) obj)->context = lorcon_packet_get_interface(self->packet);
    ((PyLorcon2_Context *) obj)->free_on_cleanup = 0;

    Py_DECREF(arg_tuple);

    Py_INCREF(obj);

    return obj;
}

static int PyLorcon2_Multi_init(PyLorcon2_Multi *self, 
        PyObject *args, PyObject *kwds) {

    self->multi = lorcon_multi_create();

    if (self->multi == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Unable to allocate multicap");
        return -1;
    }

    self->cb_func = NULL;
    self->cb_aux = NULL;
    self->error_cb_func = NULL;
    
    return 1;
}

static void PyLorcon2_Multi_dealloc(PyLorcon2_Multi *self) {
    if (self->multi == NULL)
        return;

    self->multi = NULL;

    if (self->cb_func != NULL)
        Py_XDECREF(self->cb_func);
    if (self->cb_aux != NULL)
        Py_XDECREF(self->cb_aux);
    if (self->error_cb_func != NULL)
        Py_XDECREF(self->error_cb_func);

    self->ob_type->tp_free(self);
}

static PyObject* PyLorcon2_Multi_get_error(PyLorcon2_Multi *self) {
    if (self->multi == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Multicap not allocated");
        return NULL;
    }

    return PyString_FromString(lorcon_multi_get_error(self->multi));
}

void pylorcon2_multi_error_handler(lorcon_multi_t *ctx, lorcon_t *lorcon_interface,
        void *aux) {
    PyLorcon2_Multi *multi = (PyLorcon2_Multi *) aux;
    PyObject *arg_tuple, *lorcon_obj;
    PyObject *cb_arg;
    PyObject *pyresult;

    /* Do nothing if we don't have a callback function */
    if (multi->error_cb_func == NULL)
        return;
    
    /* Make a lorcon context object that doesn't free its internal structure when the
     * python object goes away by wedging it */
    arg_tuple = PyTuple_New(0);
    lorcon_obj = PyObject_CallObject((PyObject *) &PyLorcon2_ContextType, arg_tuple);
    ((PyLorcon2_Context *) lorcon_obj)->context = lorcon_interface;
    ((PyLorcon2_Context *) lorcon_obj)->free_on_cleanup = 0;
    Py_DECREF(arg_tuple);
    Py_INCREF(lorcon_obj);

    /* Call the error cb function */
    cb_arg = Py_BuildValue("(O)", lorcon_obj);
    pyresult = PyEval_CallObject(multi->error_cb_func, cb_arg);
    Py_DECREF(cb_arg);

    if (pyresult == NULL) {
        PyErr_Print();
        printf("*** pylorcon2.multi error callback handler error\n");
        exit(1);
    } 

    Py_DECREF(pyresult);
}

static PyObject* PyLorcon2_Multi_add_interface(PyLorcon2_Multi *self, 
        PyObject *args) {

    PyObject *intf_obj;

    if (self->multi == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Multicap not allocated");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "O", &intf_obj))
        return NULL;

    if (!PyObject_TypeCheck(intf_obj, &PyLorcon2_ContextType)) {
        PyErr_SetString(PyExc_RuntimeError, "Expected Lorcon2.Context");
        return NULL;
    }

    Py_INCREF(intf_obj);
    lorcon_multi_add_interface(self->multi, ((PyLorcon2_Context *) intf_obj)->context);
    lorcon_multi_set_interface_error_handler(self->multi, 
            ((PyLorcon2_Context *) intf_obj)->context, 
            pylorcon2_multi_error_handler, (void *) self);

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject* PyLorcon2_Multi_del_interface(PyLorcon2_Multi *self, 
        PyObject *args) {
    PyObject *intf_obj;

    if (self->multi == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Multicap not allocated");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "O", &intf_obj))
        return NULL;

    if (!PyObject_TypeCheck(intf_obj, &PyLorcon2_ContextType)) {
        PyErr_SetString(PyExc_RuntimeError, "Expected Lorcon2.Context");
        return NULL;
    }

    lorcon_multi_del_interface(self->multi, 
            ((PyLorcon2_Context *) intf_obj)->context, 0);
    Py_DECREF(intf_obj);

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject* PyLorcon2_Multi_get_interfaces(PyLorcon2_Multi *self) {
    PyObject *retlist;
    PyObject *stringobj;
    lorcon_multi_interface_t *interface = NULL;
    lorcon_t *lorcon;

    if (self->multi == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Multicap not allocated");
        return NULL;
    }

    retlist = PyList_New(0);

    while ((interface = lorcon_multi_get_next_interface(self->multi, interface))) {
        lorcon = lorcon_multi_interface_get_lorcon(interface);
        stringobj = PyString_FromString(lorcon_get_capiface(lorcon));
        PyList_Append(retlist, stringobj);
        Py_DECREF(stringobj);
    }

    return retlist;
}

void pylorcon2_multi_handler(lorcon_t *ctx, lorcon_packet_t *pkt, u_char *aux) {
    PyLorcon2_Multi *multi = (PyLorcon2_Multi *) aux;
    PyObject *pypacket, *cb_arg, *packet_tuple_arg;
    PyObject *pyresult;
    
    packet_tuple_arg = PyTuple_New(0);
    pypacket = PyObject_CallObject((PyObject *) &PyLorcon2_PacketType, 
            packet_tuple_arg);
    ((PyLorcon2_Packet *) pypacket)->packet = pkt;
    Py_DECREF(packet_tuple_arg);

    cb_arg = Py_BuildValue("(O)", pypacket);
    pyresult = PyEval_CallObject(multi->cb_func, cb_arg);
    Py_DECREF(cb_arg);

    if (pyresult == NULL) {
        PyErr_Print();
        printf("*** pylorcon2.multi callback handler error\n");
        exit(1);
    } 

    Py_DECREF(pyresult);
}

static PyObject* PyLorcon2_Multi_loop(PyLorcon2_Multi *self, PyObject *args) {
    PyObject *callback;
    int num, ret;
    
    if (self->multi == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Multicap not allocated");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "iO", &num, &callback))
        return NULL;

    if (!PyCallable_Check(callback)) {
        PyErr_SetString(PyExc_TypeError, "parameter must be callable");
        return NULL;
    }

    Py_XINCREF(callback);

    if (self->cb_func != NULL)
        Py_XDECREF(self->cb_func);

    self->cb_func = callback;

    ret = lorcon_multi_loop(self->multi, num, pylorcon2_multi_handler, (void *) self);

    return PyInt_FromLong(ret);
}

static PyObject* PyLorcon2_Multi_get_multi_ptr(PyLorcon2_Multi *self) {
    PyObject *ptrcapsule;
    
    if (self->multi == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Multicap not allocated");
        return NULL;
    }

    ptrcapsule = PyCapsule_New((void *) self->multi, "MULTI", NULL);

    return ptrcapsule;
}

static PyObject *PyLorcon2_Multi_set_interface_error_cb(PyLorcon2_Multi *self,
        PyObject *args) {
    PyObject *cb_obj;

    if (self->multi == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Multicap not allocated");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "O", &cb_obj))
        return NULL;

    if (!PyCallable_Check(cb_obj)) {
        PyErr_SetString(PyExc_TypeError, "parameter must be callable");
        return NULL;
    }

    Py_XINCREF(cb_obj);

    if (self->cb_func != NULL)
        Py_XDECREF(self->error_cb_func);

    self->error_cb_func = cb_obj;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *PyLorcon2_Multi_remove_interface_error_cb(PyLorcon2_Multi *self,
        PyObject *args) {

    if (self->multi == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Multicap not allocated");
        return NULL;
    }

    if (self->cb_func != NULL)
        Py_XDECREF(self->error_cb_func);

    self->error_cb_func = NULL;

    Py_INCREF(Py_None);
    return Py_None;
}

