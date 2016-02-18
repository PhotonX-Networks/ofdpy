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
        self.name = name
        self.mac = mac
        self.ip = ip
        self.connected_to = connected_to

    def __repr__(self):
        return "".join(["name: ",
                        str(self.name),
                        "\nmac: ",
                        str(self.mac),
                        "\nip: ",
                        str(self.ip),
                        "\nconnected: ",
                        str(self.connected_to)])
                    

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
    def __repr__(self):
        return self.name

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

def create_spirent_tue_lab():
    switch = create_trident_1_switch()
    nics = []
    for i in range(1, 9):
        nics.append(NIC(name="spi" + str(i),
                        mac=0x001094000000 + i,
                        ip="192.85.1." + str(2+i),
                        connected_to=switch.get_port_by_name("xe" + str(i - 1))))
    print(nics)
    nic_1 = NIC(name="spi1")
