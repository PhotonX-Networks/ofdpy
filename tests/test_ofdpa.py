#! /usr/bin/env
# -*- coding: utf-8 -*-
"""
This module is used to test all ofdpy.ofdpa functions and classes.

@author: Karel van de Plassche
"""
import pytest

import ryu

from ofdpy import ofdpa


@pytest.fixture(scope="function")
def datapath(request):
    def fin():
        ofdpa._remove_fake_datapath()
    request.addfinalizer(fin)
    return ofdpa._create_fake_datapath()


@pytest.fixture(scope="function")
def ofdpa_instance(datapath):
    return ofdpa.OFDPA(datapath=datapath, mode="ODL", controller_ip="127.0.0.1")


@pytest.fixture(scope="function")
def L2_interface_group(ofdpa_instance):
    return ofdpa.L2_Interface_Group(ofdpa_instance, 1, 1, pop_vlan=True)


def test_fake_datapath(datapath):
    assert datapath.__class__ == ryu.controller.controller.Datapath


def test_fake_ofdpa_instance(ofdpa_instance):
    assert ofdpa_instance.__class__ == ofdpa.OFDPA
    assert ofdpa_instance.datapath.__class__ == ryu.controller.controller.Datapath


def test_L2_Interface_Group(ofdpa_instance):
    ofdpa.L2_Interface_Group(ofdpa_instance, 1, 1, pop_vlan=True)


def test_L2_Unfiltered_Interface_Group(ofdpa_instance):
    ofdpa.L2_Unfiltered_Interface_Group(ofdpa_instance, 1)


def test_L2_Multicast_Group(ofdpa_instance):
    groups = [L2_interface_group(ofdpa_instance)]
    ofdpa.L2_Multicast_Group(ofdpa_instance, 1, groups)


def test_L2_Flood_Group(ofdpa_instance):
    groups = [L2_interface_group(ofdpa_instance)]
    ofdpa.L2_Flood_Group(ofdpa_instance, 1, groups)


def test_L3_Multicast_Group(ofdpa_instance):
    group = L2_interface_group(ofdpa_instance)
    ofdpa.L3_Multicast_Group(ofdpa_instance, 1, group)


def test_VLAN_Flow(ofdpa_instance):
    ofdpa.VLAN_Flow(ofdpa_instance, 1, 2)


def test_VLAN_Untagged_Packet_Port_VLAN_Assignment_Flow(ofdpa_instance):
    ofdpa.VLAN_Untagged_Packet_Port_VLAN_Assignment_Flow(ofdpa_instance, 1, 1)


def test_VLAN_Allow_All_VLANs_Flow(ofdpa_instance):
    ofdpa.VLAN_Allow_All_VLANs_Flow(ofdpa_instance, 1)


def test_VLAN_VLAN_Filtering_Flow(ofdpa_instance):
    ofdpa.VLAN_VLAN_Filtering_Flow(ofdpa_instance, 1, 1)


def test_Bridging_Flow(ofdpa_instance):
    pass


def test_Bridging_DLF_VLAN_Bridging_Flow(ofdpa_instance):
    groups = [L2_interface_group(ofdpa_instance)]
    group = ofdpa.L2_Flood_Group(ofdpa_instance, 1, groups)
    ofdpa.Bridging_DLF_VLAN_Bridging_Flow(ofdpa_instance,
                                          1,
                                          group,
                                          copy_controller=False)


def test_Bridging_Unicast_VLAN_Bridging_Flow(ofdpa_instance):
    group = L2_interface_group(ofdpa_instance)
    ofdpa.Bridging_Unicast_VLAN_Bridging_Flow(ofdpa_instance,
                                              1,
                                              0x000000000000,
                                              group,
                                              copy_controller=False)


def test_Policy_ACL_Flow(ofdpa_instance):
    ofdpa.Policy_ACL_Flow()


def test_Policy_ACL_VLAN_Flow_DSCP(ofdpa_instance):
    group = L2_interface_group(ofdpa_instance)
    group = ofdpa.L3_Multicast_Group(ofdpa_instance, 1, group)
    ofdpa.Policy_ACL_VLAN_Flow(ofdpa_instance,
                               group,
                               IP_DSCP=1,
                               ETH_TYPE=0x0800)
