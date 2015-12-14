#! /usr/bin/env
# -*- coding: utf-8 -*-
"""
This module contains an example how to use the ofdpy use cases in combination
with an ODL controller.

@author: Karel van de Plassche
"""
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.utils as utils
from ryu.ofproto import ofproto_v1_3

from ofdpy import ofdpa
from ofdpy import usecase
from ofdpy import topology as topo


class L2Switch(app_manager.RyuApp):
    # We know the version OF the TUe TOR speaks
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        # Initialize Ryu App
        super(L2Switch, self).__init__(*args, **kwargs)

    # If a switch connects
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # Initialize an ofdpa instance
        self.ofdpa_instance = ofdpa.OFDPA(ev.msg.datapath)
        print self.ofdpa_instance
        # Ask how many ports are available
        req = ofdpa.parser.OFPPortDescStatsRequest(
            self.ofdpa_instance.datapath, 0)
        self.ofdpa_instance.datapath.send_msg(req)

    # If a switch replies to a port request
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        recieved_datapath = ev.msg.datapath
        # Check if the response is from the device we asked it to
        if self.ofdpa_instance.datapath == recieved_datapath:
            port_ids = []
            # Print available ports
            for p in ev.msg.body:
                port_ids.append(p.port_no)
            self.logger.debug('OFPPortDescStatsReply received: %s', port_ids)

            # Configure topology. In this case, two servers with two NICs each,
            # and one OFDPA switch.
            switch, nyx, ananke = topo.create_basic_tue_lab()

            # And send our use case
            usecase.ping(self.ofdpa_instance, 10,
                         (nyx.nics[0].mac,
                          nyx.nics[0].connected_to.ofdpa_id),
                         (ananke.nics[0].mac,
                          ananke.nics[0].connected_to.ofdpa_id))

    # Display any packet recieved by the controller
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPR_NO_MATCH:
            reason = 'NO MATCH'
        elif msg.reason == ofp.OFPR_ACTION:
            reason = 'ACTION'
        elif msg.reason == ofp.OFPR_INVALID_TTL:
            reason = 'INVALID TTL'
        else:
            reason = 'unknown'

        self.logger.debug('OFPPacketIn received: '
                          'buffer_id=%x total_len=%d reason=%s '
                          'table_id=%d cookie=%d match=%s data=%s',
                          msg.buffer_id, msg.total_len, reason,
                          msg.table_id, msg.cookie, msg.match,
                          utils.hex_array(msg.data))
