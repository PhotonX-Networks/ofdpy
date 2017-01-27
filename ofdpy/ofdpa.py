#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
This module contains classes and functions to interact with Broadcoms OF-DPA.
It is based on ofdpa-EA1-2.0.1.0.

@author: Karel van de Plassche
@licence: GPLv3
"""
import logging
import warnings

from ryu.ofproto import ofproto_v1_3 as ofproto
from ryu.ofproto import ofproto_v1_3_parser as parser
import odlparse

# To create a fake datapath
import socket
import ryu.base.app_manager
from ryu.controller.controller import Datapath

INGRESS_PORT_FLOW_TABLE = 0
VLAN_FLOW_TABLE = 10
VLAN_1_FLOW_TABLE = 11
INGRESS_MAINTENANCE_POINT_FLOW_TABLE = 12
MPLS_L2_PORT_FLOW_TABLE = 13
TERMINATION_MAC_FLOW_TABLE = 20
MPLS_0_FLOW_TABLE = 23
MPLS_1_FLOW_TABLE = 24
MPLS_2_FLOW_TABLE = 25
MPLS_TP_MAINTENANCE_POINT_FLOW_TABLE = 26
UNICAST_ROUTING_FLOW_TABLE = 30
MULTICAST_ROUTING_FLOW_TABLE = 40
BRIDGING_FLOW_TABLE = 50
POLICY_ACL_FLOW_TABLE = 60
COLOR_BASED_ACTIONS_FLOW_TABLE = 65
EGRESS_VLAN_FLOW_TABLE = 210
EGRESS_VLAN_1_FLOW_TABLE = 211
EGRESS_MAINTENANCE_POINT_FLOW_TABLE = 226
SOURCE_MAC_LEARNING_FLOW_TABLE = 254

L2_INTERFACE_GROUP = 0
L2_REWRITE_GROUP = 1
L3_UNICAST_GROUP = 2
L2_MULTICAST_GROUP = 3
L2_FLOOD_GROUP = 4
L3_INTERFACE_GROUP = 5
L3_MULTICAST_GROUP = 6
L3_ECMP_GROUP = 7
L2_DATA_CENTER_OVERLAY_GROUP = 8
MPLS_LABEL_GROUP = 9
MPLS_FORWARDING_GROUP = 10
L2_UNFILTERED_INTERFACE_GROUP = 11
L2_LOOPBACK_GROUP = 12

logging.captureWarnings(True)
logger = logging.getLogger(__name__)


def _create_fake_datapath():
    s = socket.socket()

    app = ryu.base.app_manager.RyuApp()
    app.name = 'ofp_event'
    ryu.base.app_manager.register_app(app)

    datapath = Datapath(s, '1')
    datapath.ofproto = ofproto
    datapath.ofproto_parser = parser
    return datapath


def _remove_fake_datapath():
    app = ryu.base.app_manager.RyuApp()
    app.name = 'ofp_event'
    ryu.base.app_manager.unregister_app(app)


class OFDPA():
    def __init__(self, datapath=None, mode='Ryu', controller_ip='127.0.0.1', controller_port='8181', ofdpa_id='openflow:55930', flow_start=None):
        self.mode = mode
        if self.mode == 'ODL':
            self.ODL_instance = odlparse.OpenDaylight(controller_ip, port=controller_port, node=ofdpa_id, flow_start=flow_start)

        if datapath is None:
            warnings.warn('No datapath defined, creating fake one')
            self.datapath = _create_fake_datapath()
        else:
            self.datapath = datapath

        if ((self.datapath.ofproto_parser != parser) |
           (self.datapath.ofproto != ofproto)):
            raise Exception('OF version incompatible with ofdpa!')

    def send(self, msg):
        if self.mode == 'Ryu':
            self.datapath.send_msg(msg)
        elif self.mode == 'ODL':
            msg.xid = 0
            msg.msg_type = 0
            msg.version = 0
            self.ODL_instance.msgs.append(msg)


class VLAN_Flow:
    def __init__(self, ofdpa_instance, IN_PORT, VLAN_VID):
        pass


class VLAN_Untagged_Packet_Port_VLAN_Assignment_Flow(VLAN_Flow):
    """
    IMPORTANT! To be able to add this flow, a VLAN_VLAN_Filtering_Flow needs
    to be added at the same port and VLAN first!

    See table 6 in chapter 3.2.2 VLAN Flow Table.

    Exact match on IN_PORT and VLAN ID == 0 (lower 12 bits of match field)
    value using a mask value of 0x0fff (masks off OFPVID_PRESENT).
    Action set must assign a VLAN_VID. The VLAN_VID cannot be one used in a
    VLAN Filtering rule.  If the packet does not have a VLAN tag,
    one will be pushed, if necessary, at packet egress. Rule must have a
    Goto-Table instruction specifyies the Termination MAC Flow Table.
    Untagged packets are dropped if there is no port VLAN assignment rule.
    """
    __OFDPA_VERSION__ = '2.3.0.0'
    def __init__(self, ofdpa_instance, IN_PORT, new_VLAN_VID):
        match = parser.OFPMatch(in_port=IN_PORT,
                                vlan_vid=(0x0000 & 0x0FFF))

        inst = []

        actions = [parser.OFPActionSetField(vlan_vid=(0x1000 | new_VLAN_VID))]
        inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions))
        inst.append(parser.OFPInstructionGotoTable(TERMINATION_MAC_FLOW_TABLE))
        msg = parser.OFPFlowMod(datapath=ofdpa_instance.datapath,
                                table_id=VLAN_FLOW_TABLE,
                                match=match,
                                instructions=inst)
        ofdpa_instance.send(msg)


class VLAN_Allow_All_VLANs_Flow(VLAN_Flow):
    """
    See Table 18 in chapter 4.1.3 VLAN Flow Table.

    Wildcard VLAN match for a specific IN_PORT. Essentially turns off VLAN
    filtering and/or assignment for a physical port, but must be programmed
    with both VLAN_VID and mask equal to OFPVID_PRESENT. Must have
    lower priority than any overlapping translation, filtering, MPLS, or VLAN
    assignment rule. A corresponding L2 Unfiltered Interface group entry
    should also be programmed for the port.
    """
    __OFDPA_VERSION__ = '2.3.0.0'
    def __init__(self, ofdpa_instance, IN_PORT):
        match = parser.OFPMatch(in_port=IN_PORT, vlan_vid=(0x0000 | 0x1000, 0x1000))
                                
        inst = []
        inst.append(parser.OFPInstructionGotoTable(TERMINATION_MAC_FLOW_TABLE))

        mod = parser.OFPFlowMod(datapath=ofdpa_instance.datapath,
                                table_id=VLAN_FLOW_TABLE,
                                match=match, instructions=inst)

        ofdpa_instance.send(mod)


class VLAN_VLAN_Filtering_Flow(VLAN_Flow):
    """
    See table 6 in chapter 3.2.2 VLAN Flow Table.

    Exact match on IN_PORT and VLAN_VID parsed from the packet. For tagged
    packets with a VLAN tag containing a VLAN_VID greater than zero.
    Cannot be masked. VLAN_VID cannot be used in a Port VLAN Assignment rule
    for untagged packets. The only instruction is Goto-Table and must specifies
    the Termination MAC Flow Table.
    Tagged packets that miss are considered VLAN_VIDs that are not allowed
    on the port and are dropped.
    """
    __OFDPA_VERSION__ = '2.3.0.0'
    def __init__(self, ofdpa_instance, IN_PORT, VLAN_VID):
        match = parser.OFPMatch(in_port=IN_PORT,
                                vlan_vid=(ofproto.OFPVID_PRESENT |
                                          VLAN_VID, 0x1FFF))
        inst = []
        inst.append(parser.OFPInstructionGotoTable(TERMINATION_MAC_FLOW_TABLE))

        mod = parser.OFPFlowMod(datapath=ofdpa_instance.datapath,
                                table_id=VLAN_FLOW_TABLE,
                                match=match,
                                instructions=inst)
        ofdpa_instance.send(mod)


class Termination_MAC_IPv4_Multicast_MAC_Flow():
    """
    See table 63 in chapter 4.1.10 Termination MAC Flow Table.

    Wildcard rule that recognizes all IPv4 multicast MAC addresses
    specified in RFC 1112 [39]. This must be ETH_DST = 01-00-5e-00-
    00-00 with mask ff-ff-ff-80-00-00. There can only be one flow entry
    of this type. Must have a Goto-Table instruction specifying the
    Multicast Routing Flow Table.
    """
    __OFDPA_VERSION__ = '2.3.0.0'
    def __init__(self, ofdpa_instance, IN_PORT=None, VLAN_VID=None, copy_controller=False):
        match = parser.OFPMatch(eth_dst=(0x01005E000000, 0xffffff800000), eth_type=0x0800)
        match_dict = {'eth_dst':(0x01005E000000, 0xffffff800000), 'eth_type':0x0800}
        if IN_PORT:
            raise Exception('Currently not supported')    
            match_dict['in_phy_port'] = IN_PORT
        if VLAN_VID:
            match_dict['vlan_vid'] = VLAN_VID
        match = parser.OFPMatch(**match_dict)

        print(match)
        inst = []
        if copy_controller:
            action_1 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
            inst_1 = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                  action_1)
            inst.append(inst_1)

        inst.append(parser.OFPInstructionGotoTable(MULTICAST_ROUTING_FLOW_TABLE))

        # Installing flows to Bridge table..
        mod = parser.OFPFlowMod(datapath=ofdpa_instance.datapath,
                                table_id=TERMINATION_MAC_FLOW_TABLE,
                                match=match, instructions=inst)

        ofdpa_instance.send(mod)


class Termination_MAC_IPv4_Unicast_MAC_Flow():
    """
    See table 63 in chapter 4.1.10 Termination MAC Flow Table.

    Used to identify an IPv4 router MAC address. Relative priority must
    be assigned so as to be lower than any multicast MAC rule. Must
    have a Goto-Table instruction specifying the Unicast Routing Flow
    Table or the L3 Type Flow Table.
    """

    def __init__(self, ofdpa_instance, MAC_DST, IN_PORT=None, VLAN_VID=None, copy_controller=False):
        match_dict = {'eth_dst': (MAC_DST, 0xFFFFFFFFFFFF), 'eth_type':0x0800}
        if IN_PORT:
            raise Exception('Currently not supported')
            match_dict['in_phy_port'] = IN_PORT
        if VLAN_VID:
            match_dict['vlan_vid'] = VLAN_VID
        match = parser.OFPMatch(**match_dict)
        print match

        inst = []
        if copy_controller:
            action_1 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
            inst_1 = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                  action_1)
            inst.append(inst_1)

        inst.append(parser.OFPInstructionGotoTable(UNICAST_ROUTING_FLOW_TABLE))

        # Installing flows to Bridge table..
        mod = parser.OFPFlowMod(datapath=ofdpa_instance.datapath,
                                table_id=TERMINATION_MAC_FLOW_TABLE,
                                match=match, instructions=inst)

        ofdpa_instance.send(mod)


class Bridging_Flow(object):
    def __init__(self, ofdpa_instance, group, inst, match,
                 copy_controller=False):
        if copy_controller:
            action_1 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
            inst_1 = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                  action_1)
            inst.append(inst_1)

        action_2 = [parser.OFPActionGroup(group.encode_id())]
        inst_2 = parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS,
                                              action_2)
        inst.append(inst_2)
        inst.append(parser.OFPInstructionGotoTable(POLICY_ACL_FLOW_TABLE))

        # Installing flows to Bridge table..
        mod = parser.OFPFlowMod(datapath=ofdpa_instance.datapath,
                                table_id=BRIDGING_FLOW_TABLE,
                                match=match, instructions=inst)
        ofdpa_instance.send(mod)


class Bridging_DLF_VLAN_Bridging_Flow(Bridging_Flow):
    """
    See table 33 in chapter 4.1.6 Bridging Flow Table.

    Matches switched Ethernet frames by VLAN id only. MAC_DST
    must be field masked and match any destination. Must have
    lower relative priority than any unicast or multicast flow entries
    that specify this VLAN. VLAN id must be present and nonzero.
    Tunnel id must be masked or omitted.
    """
    def __init__(self, ofdpa_instance, VLAN_VID, group,
                 copy_controller=False):
        if group.__class__ != L2_Flood_Group:
            raise Exception('Must be L2_Flood_Group')
        inst = []
        match = parser.OFPMatch(vlan_vid=ofproto.OFPVID_PRESENT | VLAN_VID)

        super(Bridging_DLF_VLAN_Bridging_Flow, self).__init__(
            ofdpa_instance, group, inst, match,
            copy_controller=copy_controller)


class Bridging_Unicast_VLAN_Bridging_Flow(Bridging_Flow):
    """
    See table 33 in chapter 4.1.6 Bridging Flow Table.

    Matches switched unicast Ethernet frames by VLAN id and
    MAC_DST. MAC_DST must be unicast and cannot be masked.
    VLAN id must be present and nonzero. Tunnel id must be
    masked or omitted.
    """
    def __init__(self, ofdpa_instance, VLAN_VID, MAC_DST, group,
                 copy_controller=False):
        if group.__class__ != L2_Interface_Group:
            raise Exception('Must be L2_Interface_Group')
        inst = []
        match = []
        match = parser.OFPMatch(vlan_vid=ofproto.OFPVID_PRESENT | VLAN_VID,
                                eth_dst=MAC_DST)

        super(Bridging_Unicast_VLAN_Bridging_Flow, self).__init__(
            ofdpa_instance, group, inst, match,
            copy_controller=copy_controller)


class Bridging_Multicast_VLAN_Bridging_Flow(Bridging_Flow):
    """
    See table 93 in chapter 4.1.16 Bridging Flow Table

    Matches switched multicast Ethernet frames by VLAN Id and
    MAC_DST. MAC_DST must be multicast and cannot be masked.
    VLAN Id must be present and non-zero. Tunnel Id must be
    masked or omitted.
    """
    __OFDPA_VERSION__ = "2.3.0.0"
    def __init__(self, ofdpa_instance, VLAN_VID, group,
                 copy_controller=False):
        if group.__class__ != L2_Multicast_Group:
            raise Exception('Must be L2_Multicast_Group')
        inst = []
        match = []
        match = parser.OFPMatch(vlan_vid=ofproto.OFPVID_PRESENT | VLAN_VID,
                                eth_dst=0xffffffffffff)

        super(Bridging_Multicast_VLAN_Bridging_Flow, self).__init__(
            ofdpa_instance, group, inst, match,
            copy_controller=copy_controller)
# Untested
class Policy_ACL_Flow:
    def __init__(self):
        pass


class Policy_ACL_IPv4_VLAN_Flow(Policy_ACL_Flow):
    def __init__(self, ofdpa_instance, group=None, IN_PORT=None, ETH_SRC=None, ETH_DST=None, VLAN_VID=None, IP_DSCP=None, priority=None, copy_controller=None ):
        __OFDPA_VERSION__ = '2.3.0.0'
        match_dict = {'eth_type': 0x0800}
        if IN_PORT:
            match_dict['in_port'] = IN_PORT
        if ETH_SRC: 
            match_dict['eth_src'] = ETH_SRC
        if ETH_DST: 
            match_dict['eth_dst'] = ETH_DST
        if VLAN_VID:
            match_dict['vlan_vid'] = VLAN_VID
        if IP_DSCP:
            match_dict['ip_dscp'] = IP_DSCP
        match = parser.OFPMatch(**match_dict)
	inst = []
        if copy_controller:
            action = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
            inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                     action))

        if group:
            action = [parser.OFPActionGroup(group.encode_id())]
            inst.append(parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS,
                                                     action))
        if inst == []:
            raise Exception('Empty instruction set')
        mod = parser.OFPFlowMod(datapath=ofdpa_instance.datapath,
                                table_id=POLICY_ACL_FLOW_TABLE,
                                match=match, instructions=inst, priority=priority)
        ofdpa_instance.send(mod)


class L2_Interface_Group():
    """
    See chapter 4.3.1 OF-DPA L2 Interface Group Entries.

    L2 Interface Group entries are of OpenFlow indirect type, with a single
    action bucket. OF-DPA L2 Interface group entries are used for egress
    VLAN filtering and tagging. The identifier convention is shown in Table 94.
    If a specific set of VLANs is allowed on a port, appropriate group entries
    must be defined for the VLAN and port combinations.
    Note: OF-DPA uses the L2 Interface group declaration to configure the port
    VLAN filtering behavior. This approach was taken since OpenFlow does not
    support configuring VLANs on physical ports.
    """
    __OFDPA_VERSION__ = '2.3.0.0'
    def __init__(self, ofdpa_instance, out_port, vlan, pop_vlan=False):
        if out_port > 0xFFFF:
            raise Exception('Port can not be bigger than 0xFFFF')
        if vlan > 0xFFFF:
            raise Exception('Vlan can not be bigger than 0xFFF')

        self.out_port = out_port
        self.vlan = vlan
        self.pop_vlan = pop_vlan

        actions = [parser.OFPActionOutput(self.out_port)]
        if self.pop_vlan:
            actions.append(parser.OFPActionPopVlan())

        weight = 0
        watch_port = ofproto.OFPP_ANY
        watch_group = ofproto.OFPP_ANY
        buckets = [parser.OFPBucket(weight, watch_port, watch_group, actions)]

        msg = parser.OFPGroupMod(ofdpa_instance.datapath,
                                 ofproto.OFPFC_ADD,
                                 ofproto.OFPGT_INDIRECT,
                                 self.encode_id(),
                                 buckets)

        ofdpa_instance.send(msg)

    def encode_id(self):
        if self.out_port > 0xFFFF:
            raise Exception('Port can not be bigger than 0xFFFF')
        if self.vlan > 0xFFF:
            raise Exception('Vlan can not be bigger than 0xFFF')
        type_byte = L2_INTERFACE_GROUP << 28
        vlan_byte = self.vlan << 16
        port_byte = self.out_port
        return type_byte | vlan_byte | port_byte

    @classmethod
    def decode_id(self, id_):
        vlan = (id_ & 0x0FFF0000) >> 16
        out_port = id_ & 0x0000FFFF
        return out_port, vlan


class L2_Unfiltered_Interface_Group():
    """
    See chapter 4.3.2 OF-DPA L2 Unfiltered Interface Group Entries.

    L2 Unfiltered Interface Group entries are of OpenFlow indirect type, with a
    single action bucket. OF-DPA L2 Unfiltered Interface group entries are
    similar to L2 Interface group entries except that they are used for
    forwarding to ports where VLAN filtering and tagging is not required on the
    egress port.  As with L2 Interface group entries, OF-DPA uses the L2
    Unfiltered Interface groups to configure the port to not do VLAN filtering.
    Thus an output port cannot have both L2 Interface and L2 Unfiltered
    Interface groups defined for it.
    """
    __OFDPA_VERSION__ = '2.3.0.0'

    def __init__(self, ofdpa_instance, out_port):
        self.out_port = out_port

        actions = [parser.OFPActionOutput(out_port)]
        weight = 0
        watch_port = ofproto.OFPP_ANY
        watch_group = ofproto.OFPP_ANY
        buckets = [parser.OFPBucket(weight, watch_port, watch_group, actions)]

        grp_mod = parser.OFPGroupMod(ofdpa_instance.datapath,
                                     ofproto.OFPFC_ADD,
                                     ofproto.OFPGT_INDIRECT,
                                     self.encode_id(),
                                     buckets)
        ofdpa_instance.send(grp_mod)

    def encode_id(self):
        if self.out_port > 0xFFFF:
            raise Exception('Port can not be bigger than 0xFFFF')
        type_byte = L2_UNFILTERED_INTERFACE_GROUP << 28
        port_byte = self.out_port
        return type_byte | port_byte

    @classmethod
    def decode_id(self, id_):
        out_port = id_ & 0x0000FFFF
        return out_port


class L2_Multicast_Group:
    __OFDPA_VERSION__ = '2.3.0.0'
    def __init__(self, ofdpa_instance, index, groups):
        if ((groups[0].__class__ != L2_Interface_Group) &
           (groups[0].__class__ != L2_Unfiltered_Interface_Group) &
           (groups[0].__class__ != L2_Interface_Group)):
            raise Exception('Wrong group type')

        self.index = index
        self.vlan = groups[0].vlan

        buckets = []
        for group in groups:
            if group.vlan != self.vlan:
                raise Exception('All vlan_ids in all groups should match')
            group_id = group.encode_id()
            actions = [parser.OFPActionGroup(group_id)]

            weight = 0
            watch_port = ofproto.OFPP_ANY
            watch_group = ofproto.OFPP_ANY
            buckets.append(parser.OFPBucket(weight, watch_port,
                                            watch_group, actions))

        grp_mod = parser.OFPGroupMod(ofdpa_instance.datapath,
                                     ofproto.OFPFC_ADD,
                                     ofproto.OFPGT_INDIRECT,
                                     self.encode_id(),
                                     buckets)
        ofdpa_instance.send(grp_mod)

    def encode_id(self):
        if self.index > 0xFFFF:
            raise Exception('Id can not be bigger than 0xFFFF')
        if self.vlan > 0xFFF:
            raise Exception('Vlan can not be bigger than 0xFFF')
        type_byte = L2_MULTICAST_GROUP << 28
        vlan_byte = self.vlan << 16
        index_byte = self.index
        return type_byte | vlan_byte | index_byte


class L2_Flood_Group:
    """
    See chapter 4.3.6 OF-DPA L2 Flood Group Entries.

    The OF-DPA L2 Flood Group entries are used by VLAN Flow Table wildcard
    (destination location forwarding, or DLF) rules. Like
    OF-DPA L2 Multicast group entry types they are of OpenFlow ALL type. The
    action buckets each encode an output port. Each OF-DPA L2 Flood Group entry
    bucket forwards a replica to an output port, except for packet IN_PORT.
    The main difference from OF-DPA L2 Multicast Group entries is how they are
    processed in the hardware. All of the OF-DPA L2 Interface Group entries
    referenced by the OF-DPA Flood Group entry, and the OF-DPA Flood Group
    entry itself, must be in the same VLAN.

    Note: There can only be one OF-DPA L2 Flood Group entry defined per VLAN.
    """

    def __init__(self, ofdpa_instance, index, groups):
        if (groups[0].__class__ != L2_Interface_Group):
            raise Exception('Wrong group type')
        self.index = index
        self.vlan = groups[0].vlan
        buckets = []
        for group in groups:
            if group.vlan != self.vlan:
                raise Exception('All vlan_ids in all groups should match')
            group_id = group.encode_id()
            actions = [parser.OFPActionGroup(group_id)]

            weight = 0
            watch_port = ofproto.OFPP_ANY
            watch_group = ofproto.OFPP_ANY
            buckets.append(parser.OFPBucket(weight, watch_port,
                                            watch_group, actions))

        grp_mod = parser.OFPGroupMod(ofdpa_instance.datapath,
                                     ofproto.OFPFC_ADD,
                                     ofproto.OFPGT_ALL,
                                     self.encode_id(),
                                     buckets)
        ofdpa_instance.send(grp_mod)

    def encode_id(self):
        if self.index > 0xFFFF:
            raise Exception('Id can not be bigger than 0xFFFF')
        if self.vlan > 0xFFF:
            raise Exception('Vlan can not be bigger than 0xFFF')
        type_byte = L2_FLOOD_GROUP << 28
        vlan_byte = self.vlan << 16
        index_byte = self.index
        return type_byte | vlan_byte | index_byte


# Untested
class L3_Multicast_Group:
    """
    See chapter 4.3.8 OF-DPA L3 Multicast Group Entries

    OF-DPA L3 Multicast group entries are of OpenFlow ALL type. The action
    buckets describe the interfaces to which multicast packet replicas are
    forwarded.

    IP multicast packets are forwarded differently depending on whether they
    are switched or routed. Packets must be switched in the VLAN in which
    they came in, and cannot be output to IN_PORT. Packets that are multicast
    in other VLANs or MPLS L3 VPNs must be routed and must be allowed to
    egress via IN_PORT. This difference is reflected in the actions that are
    programmed in the action buckets.

    Note that any chained OF-DPA L2 Interface Group entries must be in the
    same VLAN as the OF-DPA L3 Multicast group entry. However chained
    OF-DPA L3 Interface Group entries must be in different VLANs from the
    OF-DPA L3 Multicast Group entry, and from each other.
    """

    def __init__(self, ofdpa_instance, index, group):
        if ((group.__class__ != L2_Interface_Group) &
           (group.__class__ != L2_Interface_Group) &
           (group.__class__ != L2_Interface_Group)):
            raise Exception('Wrong group type')

        self.index = index
        group_id = group.encode_id()
        self.vlan = group.vlan

        actions = [parser.OFPActionGroup(group_id)]

        weight = 0
        watch_port = ofproto.OFPP_ANY
        watch_group = ofproto.OFPP_ANY
        buckets = [parser.OFPBucket(weight, watch_port, watch_group, actions)]

        grp_mod = parser.OFPGroupMod(ofdpa_instance.datapath,
                                     ofproto.OFPFC_ADD,
                                     ofproto.OFPGT_INDIRECT,
                                     self.encode_id(),
                                     buckets)
        ofdpa_instance.send(grp_mod)

    def encode_id(self):
        if self.index > 0xFFFF:
            raise Exception('Id can not be bigger than 0xFFFF')
        if self.vlan > 0xFFF:
            raise Exception('Vlan can not be bigger than 0xFFF')
        type_byte = L3_MULTICAST_GROUP << 28
        vlan_byte = self.vlan << 16
        index_byte = self.index
        return type_byte | vlan_byte | index_byte
