from ryu.base import app_manager
from ryu.controller import ofp_event

from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

from ryu.ofproto import ofproto_v1_3
from ryu.lib import stplib
from ryu.lib import dpid as dpid_lib

from ryu.lib.packet import ethernet, packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types

from ryu.app import simple_switch_13


class SwitchTest3(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    
    def __init__(self, *args, **kwargs):
        super(SwitchTest3, self).__init__(*args, **kwargs)
        # self.ipv4_to_port{}
        self.dpid_list = ('0000000000000001', '0000000000000002', '0000000000000003')
        # self.ipv4_list = ['10.0.0.251', '10.0.0.252', '10.0.0.253', '10.0.0.254']
        self.mac_list = ('00:00:00:00:00:21', '00:00:00:00:00:22', '00:00:00:00:00:23', '00:00:00:00:00:24')


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = dpid_lib.dpid_to_str(datapath.id) 
        self.logger.info("switch:%s connected", dpid)

        match = parser.OFPMatch()    # openflow packet match
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,       
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def get_switches(self):
        return self.dpid_list

    def get_hosts(self):
        return self.mac_list
    
    # flow_info = (dpid, src, dst, in_port)
    def add_flow_mod(self, datapath, buffer_id, ofproto, flow_info, parser, out_port):
        self.logger.info("packet in %s %s %s in_port= %s out_port= %s", flow_info[0], flow_info[1], flow_info[2], flow_info[3], out_port)
        match = parser.OFPMatch(in_port=flow_info[3], eth_dst=flow_info[2], eth_src=flow_info[1])
        actions = [parser.OFPActionOutput(out_port)]
        if buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 1, match, actions, buffer_id)
            return
        else:
            self.add_flow(datapath, 1, match, actions)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = dpid_lib.dpid_to_str(datapath.id)

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst = eth.dst
        src = eth.src
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        flow_info = (dpid, src, dst, in_port)

        switches = self.get_switches()
        hosts = self.get_hosts()

        buffer_id = msg.buffer_id
        out_port = ofproto.OFPP_FLOOD

        if dpid == switches[1]:
            if(src == hosts[0] and dst == hosts[1]):
                out_port = 3
                self.add_flow_mod(self, datapath, buffer_id, ofproto, flow_info, parser, out_port)
                return
            if((src == hosts[0] or src == hosts[1]) and (dst == hosts[2] or dst == hosts[3])):
                out_port = 1
                self.add_flow_mod(self, datapath, buffer_id, ofproto, flow_info, parser, out_port)
                return
            if(src == hosts[1] and dst == hosts[0]):
                out_port = 2
                self.add_flow_mod(self, datapath, buffer_id, ofproto, flow_info, parser, out_port)
                return
            if((src == hosts[2] or src == hosts[3]) and dst == hosts[0]):
                out_port = 2
                self.add_flow_mod(self, datapath, buffer_id, ofproto, flow_info, parser, out_port)
                return
            if((src == hosts[2] or src == hosts[3]) and dst == hosts[1]):
                out_port = 3
                self.add_flow_mod(self, datapath, buffer_id, ofproto, flow_info, parser, out_port)
                return
        elif dpid == switches[0]:
            if((src == hosts[0] or src == hosts[1]) and (dst == hosts[2] or dst == hosts[3])):
                out_port = 2
                self.add_flow_mod(self, datapath, buffer_id, ofproto, flow_info, parser, out_port)
                return
            if((src == hosts[2] or src == hosts[3]) and (dst == hosts[0] or dst == hosts[1])):
                out_port = 1
                self.add_flow_mod(self, datapath, buffer_id, ofproto, flow_info, parser, out_port)
                return
        elif dpid == switches[2]:
            if((src == hosts[0] or src == hosts[1]) and dst == hosts[2]):
                out_port = 2
                self.add_flow_mod(self, datapath, buffer_id, ofproto, flow_info, parser, out_port)
                return
            if((src == hosts[0] or src == hosts[1]) and dst == hosts[3]):
                out_port = 3
                self.add_flow_mod(self, datapath, buffer_id, ofproto, flow_info, parser, out_port)
                return
            if(src == hosts[2] and dst == hosts[3]):
                out_port = 3
                self.add_flow_mod(self, datapath, buffer_id, ofproto, flow_info, parser, out_port)
                return
            if(src == hosts[3] and dst == hosts[2]):
                out_port = 2
                self.add_flow_mod(self, datapath, buffer_id, ofproto, flow_info, parser, out_port)
                return
            if((src == hosts[2] or src == hosts[3]) and (dst == hosts[0] or dst == hosts[1])):
                out_port = 1
                self.add_flow_mod(self, datapath, buffer_id, ofproto, flow_info, parser, out_port)
                return

        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)




