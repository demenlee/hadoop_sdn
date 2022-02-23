
from ryu.base import app_manager
from ryu.controller import ofp_event

from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet.ethernet import ethernet

from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ipv4, ethernet, arp
from ryu.lib.packet import ether_types
from ryu.lib import dpid as dpid_lib

from ryu.app import simple_switch_13

class SimpleSwitchL3(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *_args, **_kwargs):
        super(SimpleSwitchL3, self).__init__(*_args, **_kwargs)

        self.mac_to_port = {}
        '''
        {dpid: {src: in_port, dst: out_put}}
        '''
        self.ipv4_to_mac = {}
        '''
        arp {ip: mac}
        '''
    
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

    # def arp_forwarding(self)
        
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
        # ip_pkt = pkt.get_protocol(ipv4.ipv4)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        eth_type = eth.ethertype

        if eth_type == ether_types.ETH_TYPE_LLDP:
            self.logger.info("link discover protology")
            return

        src = eth.src
        dst = eth.dst   # 广播(ff)； reply(src );  send
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port  
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        ip_src = None
        ip_dst = None
        if isinstance(arp_pkt, arp.arp):
            self.logger.info("ARP processing: arp_forwarding, flood")
            ip_src = arp_pkt.src_ip
            ip_dst = arp_pkt.dst_ip
            self.ipv4_to_mac.setdefault(ip_src, src)
            self.logger.info("packet in %s %s %s %s", dpid, ip_src, ip_dst, in_port)  

            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]
            
            msg_data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                msg_data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg_data)
            datapath.send_msg(out)

        
        # self.logger.info("packet in %s %s %s %s %s %s", dpid, src, ip_src, dst, ip_dst, in_port)
        # UnboundLocalError: local variable 'ip_src' referenced before assignment
        

        if isinstance(ipv4_pkt, ipv4.ipv4):
            self.logger.info("IPV4 processing: install flow entry")
            ip_src = ipv4_pkt.src
            ip_dst = ipv4_pkt.dst
            self.ipv4_to_mac.setdefault(ip_src, src)
            self.ipv4_to_mac.setdefault(ip_dst, dst)

            if dst == self.ipv4_to_mac[ip_dst] and dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, ipv4_src=ip_src, ipv4_dst=ip_dst, eth_type=eth_type)
                self.logger.info("packet out %s %s %s %s", dpid, ip_src, ip_dst, out_port)
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 2, match, actions, msg.buffer_id)
                    return
                else:  # msg.buffer_id == ofproto.OFP_NO_BUFFER
                    self.add_flow(datapath, 2, match, actions)               
            else:
                out_port = ofproto.OFPP_FLOOD
                actions = [parser.OFPActionOutput(out_port)]

            msg_data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                msg_data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg_data)
            datapath.send_msg(out)

    