#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
This module contains an example how to use the ofdpy use cases in combination
with an ODL controller.

@author: Karel van de Plassche
@licence: GPLv3
"""
import logging

from ofdpy import ofdpa
from ofdpy import usecase
from ofdpy import topology as topo

# Configure logging levels
# We only need to see warnings
logging.basicConfig(level=logging.WARN)
logger = logging.getLogger(__name__)
logging.getLogger("dicttoxml").setLevel(logging.WARN)

# But like some debug information from the messy ofdpy.odlparse
ch = logging.StreamHandler()
ch.setLevel(logging.WARN)
formatter = logging.Formatter('%(message)s')
ch.setFormatter(formatter)
logging.getLogger("ofdpy.odlparse").setLevel(logging.WARN)
logging.getLogger("ofdpy.odlparse").propagate = False
logging.getLogger("ofdpy.odlparse").addHandler(ch)

ofdpa_instance = ofdpa.OFDPA(mode="ODL", controller_ip="131.155.34.9")

# Configure topology. In this case, two servers with two NICs each, and one
# OFDPA switch
switch, nyx, ananke = topo.create_basic_tue_lab()

# Start up the dscp ping use case. After sending sending this to the ODL controller
# with .ODL/send.py, the clients should be able to send DHCP packets with tag
# 60 to the target output port.
usecase.dscp_vlan(ofdpa_instance, 10, 60,
              nyx.nics[0].connected_to.ofdpa_id,
             ananke.nics[0].connected_to.ofdpa_id)
ofdpa_instance.ODL_instance.write_to_file()

# Remove the fake datapath that got created earlier to be sure. If you keep
# opening a new python console to run, you shouldn't need this.
ofdpa._remove_fake_datapath()
