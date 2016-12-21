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
        return
        #msg = ev.msg
        #datapath = msg.datapath
        #ofproto = datapath.ofproto

        #pkt = packet.Packet(msg.data)
        #eth = pkt.get_protocol(ethernet.ethernet)

        #if eth.ethertype == ether_types.ETH_TYPE_LLDP or eth.dst == '01:80:c2:00:00:0e':
        #    # ignore lldp packet
        #    print 'Ignoring'
        #    return
        #dst = eth.dst
        #src = eth.src

        #dpid = datapath.id
        #self.mac_to_port.setdefault(dpid, {})

        #if 'in_port' in msg.match:
        #    for f in msg.match.fields:
        #        if f.header == ofproto_v1_3.OXM_OF_IN_PORT:
        #            in_port = f.value
        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        ## learn a mac address to avoid FLOOD next time.

        ##if dst in self.mac_to_port[dpid]:
        ##    out_port = self.mac_to_port[dpid][dst]
        ##else:
        ##    out_port = ofproto.OFPP_FLOOD

        ##actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

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
        ofdpa_instance = ofdpa.OFDPA(ev.msg.datapath)
        try:
            self.switches[ev.msg.datapath.id]['ofdpa'] = ofdpa_instance
        except KeyError:
            self.switches[ev.msg.datapath.id] = {}
            self.switches[ev.msg.datapath.id]['ofdpa'] = ofdpa_instance
        # Ask how many ports are available
        req = ofdpa.parser.OFPPortDescStatsRequest(
            ofdpa_instance.datapath, 0)
        ofdpa_instance.datapath.send_msg(req)

    # If a switch replies to a port request
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        recieved_datapath = ev.msg.datapath
        # Check if the response is from the device we asked it to
        dpid = ev.msg.datapath.id
        port_ids = []
        ofdpa_instance = self.switches[ev.msg.datapath.id]['ofdpa']
        self.dummy_vlan = 10
        for p in ev.msg.body:
            port_ids.append(p.port_no)
            ofdpa.VLAN_VLAN_Filtering_Flow(ofdpa_instance, p.port_no, self.dummy_vlan )
            ofdpa.VLAN_Untagged_Packet_Port_VLAN_Assignment_Flow(ofdpa_instance,
                                                                 p.port_no,
                                                                 self.dummy_vlan)
        self.switches[ev.msg.datapath.id][dpid] = port_ids
        self.logger.debug('OFPPortDescStatsReply received: %s', port_ids)

    @set_ev_cls(event.EventSwitchEnter, event.EventSwitchLeave, event.EventHostAdd)
    def get_switch_topology(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches=[switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        host_list = get_host(self.topology_api_app, None)
        print self.ls(host_list[0])
        #hosts=[(,{'port':link.src.port_no}) for link in links_list]
        self.net.add_nodes_from(switches)
        #self.net.add_nodes_from(hosts)
        self.net.add_edges_from(links)
        print switch_list
        print links_list
        #print self.net.nodes()
        #print self.net.edges()
        self.graphax.clear()
        nx.draw_spring(self.net, ax=self.graphax, with_labels=True)
        #labels=nx.draw_networkx_labels(self.net,pos=nx.spring_layout(self.net), ax=self.graphax)
        #edlabels=nx.draw_networkx_edge_labels(self.net,pos=nx.spring_layout(self.net), ax=self.graphax)
        #plt.draw()
        mpld3.display(self.graphfig)
        html = mpld3.fig_to_html(self.graphfig)
        with open('/var/www/html/index.html', 'w') as file:
            file.write(html)
