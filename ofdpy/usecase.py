#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
This module contains tested use cases of the PhotonX/TUe ToR high radix
packet switch

@author: Karel van de Plassche
@licence: GPLv3
"""
import ofdpa


def one_way_bridge(ofdpa_instance, dummy_vlan, ofdpa_id_in,
                   (mac_out, ofdpa_id_out)):
    # Assign a VLAN tag to the unsigned packet from ofdpa_id_in
    ofdpa.VLAN_VLAN_Filtering_Flow(ofdpa_instance, ofdpa_id_in, dummy_vlan)
    ofdpa.VLAN_Untagged_Packet_Port_VLAN_Assignment_Flow(ofdpa_instance,
                                                         ofdpa_id_in,
                                                         dummy_vlan)
    # Create an l2 output group that pops the vlan tag on leaving the switch
    l2_interface_group = ofdpa.L2_Interface_Group(ofdpa_instance,
                                                  ofdpa_id_out,
                                                  dummy_vlan,
                                                  pop_vlan=True)
    # Bridge packets with a dest mac_out to the previously specified port
    ofdpa.Bridging_Unicast_VLAN_Bridging_Flow(ofdpa_instance,
                                              dummy_vlan,
                                              mac_out,
                                              l2_interface_group)
    return l2_interface_group


# Modification of the use case as found in OF-DPA GitHub documentation
# /doc/html/d4/d95/OFDPA_CLIENT_EXAMPLES.html
def bridging(ofdpa_instance, dummy_vlan,
             (mac_1, ofdpa_id_1),
             (mac_2, ofdpa_id_2)):
    """
    Bridges two clients not on a vlan together by adding a dummy VLAN tag, and
    removing the tag before the packet leaves the switch.
    """
    l2_interface_group_1 = one_way_bridge(ofdpa_instance,
                                          dummy_vlan,
                                          ofdpa_id_1,
                                          (mac_2, ofdpa_id_2))
    l2_interface_group_2 = one_way_bridge(ofdpa_instance,
                                          dummy_vlan,
                                          ofdpa_id_2,
                                          (mac_1, ofdpa_id_1))

    return [l2_interface_group_1, l2_interface_group_2]


def ping(ofdpa_instance, dummy_vlan,
         (mac_1, ofdpa_id_1),
         (mac_2, ofdpa_id_2)):
    """
    Extention of the bridging_use_case. By adding a rule for packets with
    ethernet destination 0xFFFFFFFFFFFF, clients are now able to ping.
    """
    groups = bridging(ofdpa_instance, dummy_vlan,
                      (mac_1, ofdpa_id_1),
                      (mac_2, ofdpa_id_2))
    flood_group = ofdpa.L2_Flood_Group(ofdpa_instance, 0, groups)
    ofdpa.Bridging_DLF_VLAN_Bridging_Flow(ofdpa_instance,
                                          dummy_vlan,
                                          flood_group,
                                          copy_controller=False)


def dscp_vlan(ofdpa_instance, dummy_vlan, dscp, ofdpa_id_in, ofdpa_id_out):
    """
    One way filtering/forwarding on DSCP tag
    """
    ofdpa.VLAN_VLAN_Filtering_Flow(ofdpa_instance, ofdpa_id_in, dummy_vlan)
    ofdpa.VLAN_Untagged_Packet_Port_VLAN_Assignment_Flow(ofdpa_instance,
                                                         ofdpa_id_in,
                                                         dummy_vlan)
    l2_Interface_group = ofdpa.L2_Interface_Group(ofdpa_instance,
                                                  ofdpa_id_out,
                                                  dummy_vlan)
    #l3_Interface_group = ofdpa.L3_Multicast_Group(ofdpa_instance, 0,
    #                                              l2_Interface_group)
    ofdpa.Policy_ACL_IPv4_VLAN_Flow(ofdpa_instance,
                               l2_Interface_group,
                               IP_DSCP=dscp)
