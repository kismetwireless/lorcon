#!/usr/bin/env ruby
require 'mkmf'

if (have_library("orcon", "lorcon_list_drivers", "lorcon.h") or find_library("orcon", "lorcon_list_drivers", "lorcon.h"))
	create_makefile("Lorcon2")
else
	puts "Error: the lorcon2 library was not found, please see the README"
end
