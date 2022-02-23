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

from ryu.base import app_manager
from ryu.controller import ofp_event

from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib import dpid as dpid_lib


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}            # {dpid: {mac_src: in_port, mac_dst: out_put}, dpid: }


    # 将交换机的包发送到控制器（switch启动时没有任何条目：添加一个流条目：packet进来，不知道如何处理它，将它发送到控制器）
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        '''
            CONFIG阶段（交换机与控制器handshake连接后的初始阶段：下发一个优先级为0的流条目，用来处理匹配不到任何流条目的包，即直接发到控制器上）
        '''
        datapath = ev.msg.datapath    #捕捉event的信息
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()    # openflow packet match
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,         # 发送到控制器
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)   #添加流条目

    # 使用 OFPFlowMod( ) 下发流表
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        '''
        默认：  cookie=0, cookie_mask=0, table_id=0, command=ofproto.OFPFC_ADD,
        idle_timeout=0, hard_timeout=0, flags=0,
        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]    # actions 动作指导
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)  # 向交换机发送一条信息

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        '''
            MAIN阶段， 编写路由转发的关键部分
        '''
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        # ipv4_src = msg.match['ipv4_src']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]  # 获取数据包的网络信息（MAC地址， ether类型）

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)    # zfill() 方法返回指定长度的字符串，原字符串右对齐，前面填充0
        # dpid = dpid_lib.dpid_to_str(datapath.id)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        # 显示： 
        # packet in  switch_id  src_mac  dst_mac  port_id

        # learn a mac address to avoid FLOOD next time.   # 正确 泛洪
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]   # 特定端口
        else:
            out_port = ofproto.OFPP_FLOOD   # 不知道特定端口， 则进行 flood

        actions = [parser.OFPActionOutput(out_port)]   # 输出端口

        # install a flow to avoid packet_in next time
        # OFPP_FLOOD： All physical ports except input port and those disabled by STP.
        if out_port != ofproto.OFPP_FLOOD:    # 非泛洪端口
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)  # 默认 OFP_NO_BUFFER
        
        ## 有buffer_id 的 通过下发流表转发数据
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:    # 如果有buffer_id,则data=None（避免同时发送flow_mod & packet_out）
            data = msg.data
        # 控制器使用此消息 通过交换机发送数据包
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
