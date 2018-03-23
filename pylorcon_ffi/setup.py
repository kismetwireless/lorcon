#!/usr/bin/env python2

from setuptools import setup

setup(name='PylorconFFI',
      version='2018.0.0',
      description='CFFI-based Lorcon2 wrapper',
      author='Mike Kershaw / Dragorn',
      author_email='dragorn@kismetwireless.net',
      url='https://www.kismetwireless.net/',
      install_requires=['cffi'],
      packages=['PylorconFFI'],
     )


