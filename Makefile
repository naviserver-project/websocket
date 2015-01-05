#
# Support for multiple NaviServer installations on a single host
#
ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

#
# Name of the modules
#
MODNAME = websocket

#
# List of components to be installed as the the Tcl module section
#
TCL =	websocket-procs.tcl \
	chat.adp chat.tcl \
	log-view.tcl log-view.adp \
	README

#
# Get the common Makefile rules
#
include  $(NAVISERVER)/include/Makefile.module

