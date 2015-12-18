#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
This module contains classes and functions to conveniently define the
experimenters datacenter setup.

@author: Karel van de Plassche
@licence: GPLv3
"""


class Client():
    def __init__(self, name=None, nics=[]):
        self.nics = nics


class NIC():
    def __init__(self, name=None, mac=None, ip=None, connected_to=None):
        self.connected_to = connected_to
        self.name = name
        self.mac = mac
        self.ip = ip


class Switch():
    def __init__(self, ip, ports):
        self.ip = ip
        self.ports = ports

    def get_port_by_name(self, name):
        for port in self.ports:
            if port.name == name:
                return port


class OfdpaPort():
    def __init__(self, ofdpa_id, name=None):
        self.ofdpa_id = ofdpa_id
        self.name = name


def create_trident_1_switch():
    ports = []
    for i in xrange(64):
        ports.append(OfdpaPort(i + 1, name="xe" + str(i)))
    return Switch(None, ports)


def create_basic_tue_lab():
    switch = create_trident_1_switch()

    nic_1 = NIC(name="eth2",
                mac=0x001b21a5a2b0,
                ip="192.168.0.100",
                connected_to=switch.get_port_by_name("xe8"))
    nic_2 = NIC(name="eth3",
                mac=0x001b21a5a2b1,
                ip="192.168.0.101",
                connected_to=switch.get_port_by_name("xe3"))
    nyx = Client(name="nyx",
                      nics=[nic_1, nic_2])

    nic_1 = NIC(name="eth2",
                mac=0x001b21b12b14,
                ip="192.168.0.111",
                connected_to=switch.get_port_by_name("xe4"))
    nic_2 = NIC(name="eth3",
                mac=0x001b21b12b15,
                ip="192.168.0.110",
                connected_to=switch.get_port_by_name("xe7"))
    ananke = Client(name="ananke",
                         nics=[nic_1, nic_2])
    return switch, nyx, ananke
