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
#include <lorcon2/lorcon_multi.h>

#ifndef __PYLORCON2__
#define __PYLORCON2__

static PyObject *Lorcon2Exception;

typedef struct {
  PyObject_HEAD
  struct lorcon *context;
  char monitored;
  char free_on_cleanup;
} PyLorcon2_Context;

typedef struct {
    PyObject_HEAD
    struct lorcon_packet *packet;
} PyLorcon2_Packet;

typedef struct {
    PyObject_HEAD
    struct lorcon_multi *multi;

    PyObject *cb_func;
    PyObject *cb_aux;

    PyObject *error_cb_func;

} PyLorcon2_Multi;

#endif /* __PYLORCON2__ */
