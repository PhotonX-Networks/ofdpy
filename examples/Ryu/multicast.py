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
            switch, spirent = topo.create_spirent_tue_lab()

            # And send our use case
            #for port in switch.ports:
            #     ofdpa.L2_Unfiltered_Interface_Group(self.ofdpa_instance, port.ofdpa_id)
            #     ofdpa.VLAN_Allow_All_VLANs_Flow(self.ofdpa_instance, port.ofdpa_id) 
            ## Create Multicast groups to duplicate traffic
            L2_groups = []
            vlan = 10
            for i in range(1,5):
                ofdpa.VLAN_VLAN_Filtering_Flow(self.ofdpa_instance, i, vlan)
                ofdpa.VLAN_Untagged_Packet_Port_VLAN_Assignment_Flow(self.ofdpa_instance, i, vlan)
            for i in range(1,65):
                L2_groups.append(ofdpa.L2_Interface_Group(self.ofdpa_instance, i, vlan, pop_vlan=True))
            for i in range(4):
                multicast_group = ofdpa.L2_Multicast_Group(self.ofdpa_instance, i, L2_groups[12 + i::4] + [L2_groups[4 + i]])
                ofdpa.Policy_ACL_IPv4_VLAN_Flow(self.ofdpa_instance, multicast_group, IN_PORT=1 + i)
               # ofdpa.Policy_ACL_IPv4_VLAN_Flow(self.ofdpa_instance, multicast_group, ETH_DST=spirent.nics[0])
               

