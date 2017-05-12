# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link, get_host
import mpld3

from IPython import embed
import networkx as nx
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
#plt.ion()

from ofdpy import ofdpa
from ofdpy import usecase

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def ls(self,obj):
        print("\n".join([x for x in dir(obj) if x[0] != "_"]))

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.mac_to_port = {}
        self.switches = {}
        self.dummy_vlan = 10
        self.net=nx.DiGraph()
        self.nodes = {}
        self.links = {}
        self.no_of_nodes = 0
        self.no_of_links = 0
        self.i=0
        self.graphfig, self.graphax = plt.subplots()
        

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg

        try:
            switches.LLDPPacket.lldp_parse(msg.data)
        except switches.LLDPPacket.LLDPUnknownFormat as e:
            if str(e) != switches.LLDPPacket.LLDPUnknownFormat.message: 
                return
        else:
            # ignore lldp packet
            return

        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src
        if not src in self.net:
            raise Exception('Could not determine path. Source' + str(src) + ' unknown')
        if not dst in self.net:
            raise Exception('Could not determine path. Destination ' + str(dst) + ' unknown')
        path = nx.shortest_path(self.net, src, dst)
        print path

        ## install a flow to avoid packet_in next time
        #ofdpa_instance = ofdpa.OFDPA(ev.msg.datapath)
        #try:
        #    self.mac_to_port[dpid][src]
        #except KeyError:
        #    self.mac_to_port[dpid][src] = in_port

        #    l2_interface_group = ofdpa.L2_Interface_Group(ofdpa_instance,
        #                                                  in_port,
        #                                                  self.dummy_vlan,
        #                                                  pop_vlan=True)
        #    # Bridge packets with a dest mac_out to the previously specified port
        #    ofdpa.Bridging_Unicast_VLAN_Bridging_Flow(ofdpa_instance,
        #                                                  self.dummy_vlan,
        #                                                  src,
        #                                                  l2_interface_group)

        #    #self.add_flow(datapath, msg.in_port, dst, actions)


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)

    # If a switch connects
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # Initialize an ofdpa instance
        dp = ev.msg.datapath
        try:
            self.switches[dp.id]
        except KeyError:
            self.switches[dp.id] = {}
        else:
            raise Exception('Switch dpid already registered!')
        self.switches[dp.id]['ofdpa'] = ofdpa_instance = ofdpa.OFDPA(dp)
        # Ask how many ports are available
        req = ofdpa.parser.OFPPortDescStatsRequest(
            ofdpa_instance.datapath, 0)
        ofdpa_instance.datapath.send_msg(req)

    # If a switch replies
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, CONFIG_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        dp = ev.msg.datapath
        ofdpa_instance = self.switches[dp.id]['ofdpa']
        # Allow traffic on all ports
        self.dummy_vlan = 10
        for p in ev.msg.body:
            #port_ids.append(p.port_no)
            ofdpa.VLAN_VLAN_Filtering_Flow(ofdpa_instance, p.port_no, self.dummy_vlan)
            ofdpa.VLAN_Untagged_Packet_Port_VLAN_Assignment_Flow(ofdpa_instance,
                                                                 p.port_no,
                                                                 self.dummy_vlan)


    @set_ev_cls([event.EventSwitchEnter, event.EventSwitchLeave, event.EventHostAdd])
    def get_switch_topology(self, ev):
        # Rebuild topology
        self.net=nx.DiGraph()
        switch_list = get_switch(self.topology_api_app, None)
        switches=[switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        self.net.add_nodes_from(switches)
        self.net.add_edges_from(links)
        host_list = get_host(self.topology_api_app, None)
        hosts = [host.mac for host in host_list]
        host_to_switch = [(host.mac, host.port.dpid) for host in host_list]
        switch_to_host = [(host.port.dpid, host.mac, {'port':host.port.port_no}) for host in host_list]
        self.net.add_nodes_from(hosts)
        self.net.add_edges_from(host_to_switch)
        self.net.add_edges_from(switch_to_host)
        #print switch_list
        #print links_list
        self.draw_graph()
    def draw_graph(self):
        self.graphax.clear()
        nx.draw_spring(self.net, ax=self.graphax, with_labels=True)
        mpld3.display(self.graphfig)
        html = mpld3.fig_to_html(self.graphfig)
        with open('/var/www/html/index.html', 'w') as file:
            file.write(html)
