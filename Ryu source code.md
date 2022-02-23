# Ryu source code

```
Threads, events, and event queues
```

RYU应用程序是在RYU中实现各种功能的单线程实体。事件是它们之间的消息。

每个RYU应用程序都有一个接收事件的队列queue(event)。队列是FIFO，并保留事件的顺序。

每个RYU应用程序都有一个用于事件处理的线程。线程通过将事件出队并调用该事件类型的相应事件处理程序来持续清空接收队列。因为 event handler 是在事件处理线程的上下文中调用的，所以在阻塞时应该小心。



有几类事件用于同步 应用间调用。虽然 requests 和原始事件机制一样，但其 replies 被放在专用事务的队列中以避免死锁。

```python
Contexts: 上下文是在Ryu应用程序之间共享的普通Python对象。 不鼓励在新代码中使用上下文。
```

Ryu 的官方文档网站： https://ryu.readthedocs.io/

openflow protocol API参考（重点）：https://ryu.readthedocs.io/en/latest/ofproto_ref.html

（可重点参考一些ofproto_v1_3_parser源代码，来帮助编写自定义ryu app）

[百度](www.baidu.com)

### handler

```python
from ryu.controller import handler

#  类似 observe_event 
def set_ev_cls(ev_cls, dispatchers=None):
    '''
    装饰器： 声明 时间处理程序。
    修饰的方法将成为事件处理程序。ev_cls 是该RyuApp想要接收的实例的 事件类。
    参数 dispatchers 指定 生成的待处理事件 的 一个紧接着的协商阶段（a list）
    如果事件改变了阶段，则使用改变前的阶段来检查 目标。
    '''
'''
dispatchers 参数:  仅代表 OF dp的状态
HANDSHAKE_DISPATCHER    发送 并等待 hello message
CONFIG_DISPATCHER    版本协商 和 发送 功能-请求 信息
MAIN_DISPATCHER      交换机-功能 信息接收 和 发送 set-config 信息
DEAD_DISPATCHER      断开对等设备的连接； 或者 由于不可恢复错误 断开连接。
'''
######################################重点###################  
## 控制器与交换机之间的 几个状态阶段：
#The state transition: HANDSHAKE -> CONFIG -> MAIN
# HANDSHAKE: 如果收到有效OFP版本的Hello消息，则Send Feature Request(发送功能请求)消息将转到CONFIG(配置)。
# CONFIG: 它接收要素回复消息并移动到 MAIN
# MAIN: it does nothing. 应用程序需要注册它们自己的处理程序。 (重点)
# 请注意，在任何状态下，当我们收到Echo Request消息时，都会发送回 Echo Reply消息。


def register_service(service)
'''
将‘service’指定的RYU应用程序 注册为 调用模块中定义的事件 提供程序。
如果正在加载的应用程序使用由“服务”应用程序提供的事件(在set_ev_cls意义上)， 则将自动加载后一个应用程序。
这个机制用在： 如果有应用程序使用OFP事件，则自动启动ofp_handler。 
'''
from ryu.controller import ofp_handler
```

### stplib

```python
from ryu.lib import stplib
## 生成树协议库
# 继承 EventBase
class EventTopologyChange(event.EventBase)  拓扑改变

class EventPortStateChange(event.EventBase)  端口状态改变

class EventPacketIn(event.EventBase)     packet_in  


class Stp(app_manager.RyuApp)
class Bridge(object)
class Port(object)

class PortThread(object)
class BridgeId(object)
class Priority(object)
class Times(object)
class OfCtl_v1_0(object)
class OfCtl_v1_2later(OfCtl_v1_0)  # 
```

### event

#### EventBase

```python
from ryu.controller import event
class EventBase(object)
class EventRequestBase(EventBase)
 	"""
    The base class for synchronous request for RyuApp.send_request.
    """
    
class EventReplyBase(EventBase)
	"""
    The base class for synchronous request reply for RyuApp.send_reply.
    """
```

#### swicth_event

```python
from ryu.topology import event
class EventSwitchBase(event.EventBase)
class EventSwitchEnter(EventSwitchBase)
class EventSwitchLeave(EventSwitchBase)

class EventPortBase(event.EventBase)
class EventPortAdd(EventPortBase)
class EventPortDelete(EventPortBase)
class EventPortModify(EventPortBase)

class EventSwitchRequest(event.EventRequestBase)
class EventSwitchReply(event.EventReplyBase)

class EventLinkBase(event.EventBase)
class EventLinkAdd(EventLinkBase)
class EventLinkDelete(EventLinkBase)
class EventLinkRequest(event.EventRequestBase)
class EventLinkReply(event.EventReplyBase)
```

### ofp_handler

```python
##
HANDSHAKE          -->  CONFIG
CONFIG:
OFPFeaturesRequest --> OFPSwitchFeatures

#
CONFIG：
OFPPortDescStatsRequest --> OFPPortDescStatsReply

##
CONFIG          -->  MAIN
#
MAIN:
OFPPortStatus
OFPPacketIn

##
HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER:
OFPEchoRequest  -->  OFPEchoReply
```



```python
from ryu.controller.ofp_handler import OFPHandler

class OFPHandler(ryu.base.app_manager.RyuApp)
	###
	@set_ev_handler(ofp_event.EventOFPHello, HANDSHAKE_DISPATCHER)
    def hello_handler(self, ev):
        .....
        # Move on to config state
        self.logger.debug('move onto config mode')
        datapath.set_state(CONFIG_DISPATCHER)
        # Finally, send feature request
        features_request = datapath.ofproto_parser.OFPFeaturesRequest(datapath)
        datapath.send_msg(features_request)
    ###
    # The switch responds with a features reply message to a features request.
    @set_ev_handler(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        if datapath.ofproto.OFP_VERSION < 0x04:  # ox04: ofproto_v1_3
            datapath.ports = msg.ports
        else:
            datapath.ports = {}
        if datapath.ofproto.OFP_VERSION < 0x04:
            self.logger.debug('move onto main mode')
            ev.msg.datapath.set_state(MAIN_DISPATCHER)
        else:
            port_desc = datapath.ofproto_parser.OFPPortDescStatsRequest(
                datapath, 0)
            datapath.send_msg(port_desc)
    
    # The switch responds with this message to a port description request.
    @set_ev_handler(ofp_event.EventOFPPortDescStatsReply, CONFIG_DISPATCHER)
    def multipart_reply_handler(self, ev):
        self.logger.debug('move onto main mode')
        ev.msg.datapath.set_state(MAIN_DISPATCHER)
    ###
    @set_ev_handler(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        self.send_event_to_observers(
            ofp_event.EventOFPPortStateChange(
                datapath, msg.reason, msg.desc.port_no),
            datapath.state)
    ### 
    @set_ev_handler(ofp_event.EventOFPEchoRequest,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def echo_request_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        echo_reply = datapath.ofproto_parser.OFPEchoReply(datapath)   # 请求 -> 回复
        echo_reply.xid = msg.xid
        echo_reply.data = msg.data
        datapath.send_msg(echo_reply)
    
    @set_ev_handler(ofp_event.EventOFPEchoReply,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def echo_reply_handler(self, ev)
    
    @set_ev_handler(ofp_event.EventOFPErrorMsg,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev)
```

### ofp_event

```python
from ryu.controller import ofp_event
from ryu.controller.controller import Datapath 

# ofp_event.py 
def _ofp_msg_name_to_ev_name(msg_name):
    return 'Event' + msg_name

### 重要类   ev 一般是  EventOFPMsgBase 
class EventOFPMsgBase(event.EventBase)
'''
OpenFlow事件类至少具有以下属性:
msg  :  描述相应OpenFlow消息的对象。
msg.datapath : 描述我们从中接收到此OpenFlow消息的OpenFlow交换机的  ryu.controler.controler.Datapath  实例。
timestamp  : datapath实例生成此事件的时间戳。
'''
'''  msg对象还有一些其他成员，它们的值是从原始OpenFlow消息中提取的。（重要）例如：
  msg_len
  total_len
  data
  match['in_port']
  等等
'''
ryu.controller.controller.Datapath

class EventOFPStateChange(event.EventBase)
# 用于协商阶段更改通知的事件类。
'''
更改协商阶段后，此类的实例将发送给观察者; 实例至少具有以下属性:
datapath :  (ryu.controller.controller.Datapath)  交换机的实例
'''


class EventOFPPortStateChange(event.EventBase)
'''
用于通知Dtalapath实例的端口状态更改的事件类。
'''
```

### controller

```python
from ryu.controller import controller

class OpenFlowController(object)


### 重要
class Datapath(ofproto_protocol.ProtocolDesc)
'''
描述 连接到此控制器的 OpenFlow交换机的类;  实例至少有以下属性：
id : datapathID; 只适用于 handler的 MAIN_DISPATCHER阶段
ofproto :  提取除of协议； 主要常量在规范中。
ofproto_parser ：为协商的 OpenFlow版本导出 OpenFlow 有线消息编码器和解码器的模块
ofproto_parser.OFPxxxx(datapath,...) ：为 给定交换机 准备OpenFlow消息的可调用函数（如， OFPFlowMod : flow-mod message)
set_xid(self, msg)
send_msg(self, msg)  :将OpenFlow消息排队以发送到相应的交换机。
send_packet_out   deprecated 反对
send_flow_mod
send_flow_del
send_delete_all_flows
send_barrier            将OpenFlow屏障消息排队以发送到交换机。
send_nxt_set_flow_format
is_reserved_port
'''
def send_msg(self, msg)

##### Utility methods for convenience
## ofproto_v1_0
def send_packet_out(self, buffer_id=0xffffffff, in_port=None, actions=None, data=None)

def send_flow_mod(self, rule, cookie, command, idle_timeout, hard_timeout,
                      priority=None, buffer_id=0xffffffff,
                      out_port=None, flags=0, actions=None)

def send_flow_del(self, rule, cookie, out_port=None)

def send_nxt_set_flow_format(self, flow_format)

def is_reserved_port(self, port_no)


```

```python
datapath :  ofproto ; ofproto_parser


from ryu.ofproto import ofproto_protocol
from ryu.ofproto import ofproto_parser

from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
```

### ofproto_parser

```python
from ryu.ofproto import ofproto_parser

# 装饰器 函数
def register_msg_parser(version)
def create_list_of_base_attributes(f)

def ofp_msg_from_jsondict(dp, jsondict)
'''
此函数从给定的JSON样式字典实例化适当的OpenFlow消息类。
'''
# 例如：
jsonstr = '{ "OFPSetConfig": { "flags": 0, "miss_send_len": 128 } }'
jsondict = json.loads(jsonstr)
o = ofp_msg_from_jsondict(dp, jsondict)  # 或者
o = dp.ofproto_parser.OFPSetConfig(flags=0, miss_send_len=128)

def ofp_instruction_from_jsondict
'''
此函数旨在与 ryu.lib.ofctl_string.ofp_instruction_from_str 配合使用
works on a list of OFPInstructions/OFPActions; 且将OFPAction 封装进 OFPInstructionActions
属性： dp:ryu.controller.Datapath实例；  jsonlist;  encap: 封装
'''
```

```python
from ryu.lib.ofctl_string import ofp_instruction_from_str
def ofp_instruction_from_str(ofproto, action_str)
'''
解析ovs-ofctl样式的 操作字符串 并返回 OFPInstructionActions 的 jsondict 表示列表
请在编写新代码时考虑使用 OFPAction 构造函数。
属性： ofproto;  action_str
'''
```

```python
class StringifyMixin(stringify.StringifyMixin)

class MsgBase(StringifyMixin)  # 继承上面的类
# xid：  Transaction id

class MsgInMsgBase(MsgBase)  # 继承上面的类

```





### ofproto_v1_3_parser

#### 消息 请求和回复

```python
from ryu.ofproto import ofproto_v1_3 as ofproto
from ryu.ofproto import ofproto_v1_3_parser

@_register_parser
@_set_msg_type(ofproto.OFPT_HELLO)
class OFPHello(MsgBase)
'''
Hello message: 当连接开始时，问候消息在交换机和控制器之间交换。(此消息由Ryu框架处理，因此Ryu应用程序通常不需要处理此消息。)
'''
class OFPHelloElemVersionBitmap(StringifyMixin)


@_register_parser
@_set_msg_type(ofproto.OFPT_ERROR)
class OFPErrorMsg(MsgBase)
'''
交换机 通过此消息通知控制器问题。
属性： type; code; data.    type 和 code 定义在'ryu.ofproto.ofproto' 里面
'''
# 例如：
@set_ev_cls(ofp_event.EventOFPErrorMsg,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
def error_msg_handler(self, ev):
	msg = ev.msg
	self.logger.debug('OFPErrorMsg received: type=0x%02x code=0x%02x '
                   'message=%s',msg.type, msg.code, utils.hex_array(msg.data))
    
@_register_parser
@_set_msg_type(ofproto.OFPT_ECHO_REQUEST)
class OFPEchoRequest(MsgBase)
'''
回显请求消息(此消息由Ryu框架处理，因此Ryu应用程序通常不需要处理此消息。)  属性：data
'''
# 例如：
def send_echo_request(self, datapath, data):
	ofp_parser = datapath.ofproto_parser
	req = ofp_parser.OFPEchoRequest(datapath, data)
	datapath.send_msg(req)
@set_ev_cls(ofp_event.EventOFPEchoRequest,
[HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
def echo_request_handler(self, ev):
	self.logger.debug('OFPEchoRequest received: data=%s',utils.hex_array(ev.msg.data))
    

@_register_parser
@_set_msg_type(ofproto.OFPT_ECHO_REPLY)
class OFPEchoReply(MsgBase)
'''
回显回复消息(此消息由Ryu框架处理，因此Ryu应用程序通常不需要处理此消息。)  属性：data
'''  # 代码实例：
def send_echo_reply(self, datapath, data):
	ofp_parser = datapath.ofproto_parser
	reply = ofp_parser.OFPEchoReply(datapath, data)
	datapath.send_msg(reply)
@set_ev_cls(ofp_event.EventOFPEchoReply,
[HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
def echo_reply_handler(self, ev):
	self.logger.debug('OFPEchoReply received: data=%s',utils.hex_array(ev.msg.data))

    
    
@_register_parser
@_set_msg_type(ofproto.OFPT_EXPERIMENTER)
class OFPExperimenter(MsgBase)
'''
属性： experimenter(实验ID)； exp_type; data
'''


@_set_msg_type(ofproto.OFPT_FEATURES_REQUEST)
class OFPFeaturesRequest(MsgBase)
'''
功能请求消息:在会话建立时，控制器向交换机发送功能请求。(此消息由Ryu框架处理，因此Ryu应用程序通常不需要处理此消息。)
'''  #代码实例：
def send_features_request(self, datapath):
	ofp_parser = datapath.ofproto_parser
	req = ofp_parser.OFPFeaturesRequest(datapath)
	datapath.send_msg(req)


###################重点##############################
@_register_parser
@_set_msg_type(ofproto.OFPT_FEATURES_REPLY)
class OFPSwitchFeatures(MsgBase)    
'''
功能回复消息: 交换机以功能 回复消息响应功能请求。(此消息由Ryu框架处理，因此Ryu应用程序通常不需要处理此消息。)
'''  #代码实例：
@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
def switch_features_handler(self, ev):
	msg = ev.msg
	self.logger.debug('OFPSwitchFeatures received: '
                      'datapath_id=0x%016x n_buffers=%d '
                       'n_tables=%d auxiliary_id=%d '
                       'capabilities=0x%08x',
                        msg.datapath_id, msg.n_buffers, msg.n_tables,
                        msg.auxiliary_id, msg.capabilities)
   

@_set_msg_type(ofproto.OFPT_GET_CONFIG_REQUEST)
class OFPGetConfigRequest(MsgBase)
'''
获取配置请求消息: 控制器发送 一个 get config 请求以查询交换机中的配置参数。
''' #代码实例：
def send_get_config_request(self, datapath):
	ofp_parser = datapath.ofproto_parser
	req = ofp_parser.OFPGetConfigRequest(datapath)
	datapath.send_msg(req)
    
@_register_parser
@_set_msg_type(ofproto.OFPT_GET_CONFIG_REPLY)
class OFPGetConfigReply(MsgBase)
'''
获取配置回复消息： 交换机使用 GET CONFIG REPLY 消息响应配置请求。
'''   # 代码实例：
@set_ev_cls(ofp_event.EventOFPGetConfigReply, MAIN_DISPATCHER)
def get_config_reply_handler(self, ev):
	msg = ev.msg
	dp = msg.datapath
	ofp = dp.ofproto
	flags = []
	if msg.flags & ofp.OFPC_FRAG_NORMAL:
		flags.append('NORMAL')
	if msg.flags & ofp.OFPC_FRAG_DROP:
		flags.append('DROP')
	if msg.flags & ofp.OFPC_FRAG_REASM:
		flags.append('REASM')
	self.logger.debug('OFPGetConfigReply received: flags=%s miss_send_len=%d',
 					 ','.join(flags), msg.miss_send_len)
    
@_set_msg_type(ofproto.OFPT_SET_CONFIG)
class OFPSetConfig(MsgBase)
'''
设置配置请求消息: 控制器发送一个 set config 请求消息 以设置配置参数。
'''  # 代码实例：
def send_set_config(self, datapath):
	ofp = datapath.ofproto
	ofp_parser = datapath.ofproto_parser
	req = ofp_parser.OFPSetConfig(datapath, ofp.OFPC_FRAG_NORMAL, 256)
	datapath.send_msg(req)

    
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPMultipartRequest(MsgBase)

@_register_parser
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPMultipartReply(MsgBase)
```

##### 统计信息

```python
class OFPDescStats(ofproto_parser.namedtuple('OFPDescStats', (
        'mfr_desc', 'hw_desc', 'sw_desc', 'serial_num', 'dp_desc')))
''' 消息回复实例'''
@_set_stats_type(ofproto.OFPMP_DESC, OFPDescStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPDescStatsRequest(OFPMultipartRequest)
'''
描述统计请求消息: 控制器使用此消息来 查询 交换机的描述。   属性：
flags： 0 或者 OFPMPF_REQ_MORE
'''  # 代码实例：
		def send_desc_stats_request(self, datapath):
            ofp_parser = datapath.ofproto_parser
            req = ofp_parser.OFPDescStatsRequest(datapath, 0)
            datapath.send_msg(req)

@OFPMultipartReply.register_stats_type(body_single_struct=True)
@_set_stats_type(ofproto.OFPMP_DESC, OFPDescStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPDescStatsReply(OFPMultipartReply)
'''
描述统计回复消息：交换机使用此消息响应描述统计请求。   属性：body：OFPDescStats的实例
'''  #代码实例：
		@set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER)
        def desc_stats_reply_handler(self, ev):
            body = ev.msg.body
            self.logger.debug('DescStats: mfr_desc=%s hw_desc=%s sw_desc=%s '
                              'serial_num=%s dp_desc=%s',
                              body.mfr_desc, body.hw_desc, body.sw_desc,
                              body.serial_num, body.dp_desc)
    
class OFPAggregateStats(ofproto_parser.namedtuple('OFPAggregateStats', (
        'packet_count', 'byte_count', 'flow_count')))  
''' 消息回复实例 '''
@_set_stats_type(ofproto.OFPMP_AGGREGATE, OFPAggregateStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPAggregateStatsRequest(OFPFlowStatsRequestBase)
'''
聚合流量统计请求消息: 控制器使用此消息来查询聚合流量静态信息。  属性：
flags; table_id;  out_port;  out_group;  cookie;  cookie_mask; match
'''  
		def send_aggregate_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            cookie = cookie_mask = 0
            match = ofp_parser.OFPMatch(in_port=1)
            req = ofp_parser.OFPAggregateStatsRequest(datapath, 0,
                                                      ofp.OFPTT_ALL,
                                                      ofp.OFPP_ANY,
                                                      ofp.OFPG_ANY,
                                                      cookie, cookie_mask,
                                                      match)
            datapath.send_msg(req)
            
@OFPMultipartReply.register_stats_type(body_single_struct=True)
@_set_stats_type(ofproto.OFPMP_AGGREGATE, OFPAggregateStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPAggregateStatsReply(OFPMultipartReply)
'''
聚合流量统计回复消息: 交换机使用此消息响应聚合流统计请求。  属性：OFPAggregateStats 的实例
''' 
		@set_ev_cls(ofp_event.EventOFPAggregateStatsReply, MAIN_DISPATCHER)
        def aggregate_stats_reply_handler(self, ev):
            body = ev.msg.body

            self.logger.debug('AggregateStats: packet_count=%d byte_count=%d '
                              'flow_count=%d',
                              body.packet_count, body.byte_count,
                              body.flow_count)
            
class OFPTableStats(ofproto_parser.namedtuple('OFPTableStats', (
        'table_id', 'active_count', 'lookup_count',
        'matched_count')))    
''' 消息回复实例 '''
@_set_stats_type(ofproto.OFPMP_TABLE, OFPTableStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPTableStatsRequest(OFPMultipartRequest)
'''
表统计请求消息: 控制器使用该消息来查询流表统计信息。   属性： flags
'''    
		def send_table_stats_request(self, datapath):
            ofp_parser = datapath.ofproto_parser
            req = ofp_parser.OFPTableStatsRequest(datapath, 0)
            datapath.send_msg(req)
            
@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_TABLE, OFPTableStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPTableStatsReply(OFPMultipartReply)
''' 
表统计回复消息: 交换机使用此消息响应表统计信息请求。   属性： body
'''
		@set_ev_cls(ofp_event.EventOFPTableStatsReply, MAIN_DISPATCHER)
        def table_stats_reply_handler(self, ev):
            tables = []
            for stat in ev.msg.body:
                tables.append('table_id=%d active_count=%d lookup_count=%d '
                              ' matched_count=%d' %
                              (stat.table_id, stat.active_count,
                               stat.lookup_count, stat.matched_count))
            self.logger.debug('TableStats: %s', tables)

class OFPPortStats(ofproto_parser.namedtuple('OFPPortStats', (
        'port_no', 'rx_packets', 'tx_packets', 'rx_bytes', 'tx_bytes',
        'rx_dropped', 'tx_dropped', 'rx_errors', 'tx_errors',
        'rx_frame_err', 'rx_over_err', 'rx_crc_err', 'collisions',
        'duration_sec', 'duration_nsec')))
''' 消息回复实例 '''
@_set_stats_type(ofproto.OFPMP_PORT_STATS, OFPPortStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPPortStatsRequest(OFPMultipartRequest)
'''
端口统计请求消息: 控制器使用此消息来查询有关端口统计信息的信息。  属性： flags; port_no
'''  # 代码实例：
		def send_port_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            req = ofp_parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY)
            datapath.send_msg(req)
            
@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_PORT_STATS, OFPPortStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPPortStatsReply(OFPMultipartReply)
'''
端口统计回复消息: 交换机使用此消息响应端口统计请求。    body
'''
		@set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
        def port_stats_reply_handler(self, ev):
            ports = []
            for stat in ev.msg.body:
                ports.append('port_no=%d '
                             'rx_packets=%d tx_packets=%d '
                             'rx_bytes=%d tx_bytes=%d '
                             'rx_dropped=%d tx_dropped=%d '
                             'rx_errors=%d tx_errors=%d '
                             'rx_frame_err=%d rx_over_err=%d rx_crc_err=%d '
                             'collisions=%d duration_sec=%d duration_nsec=%d' %
                             (stat.port_no,
                              stat.rx_packets, stat.tx_packets,
                              stat.rx_bytes, stat.tx_bytes,
                              stat.rx_dropped, stat.tx_dropped,
                              stat.rx_errors, stat.tx_errors,
                              stat.rx_frame_err, stat.rx_over_err,
                              stat.rx_crc_err, stat.collisions,
                              stat.duration_sec, stat.duration_nsec))
            self.logger.debug('PortStats: %s', ports)
            
class OFPQueueStats(ofproto_parser.namedtuple('OFPQueueStats', (
        'port_no', 'queue_id', 'tx_bytes', 'tx_packets', 'tx_errors',
        'duration_sec', 'duration_nsec')))    
''' 消息回复实例 '''
@_set_stats_type(ofproto.OFPMP_QUEUE, OFPQueueStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPQueueStatsRequest(OFPMultipartRequest)
'''
队列统计请求消息:控制器使用此消息来查询队列统计信息。  # 属性：flags; port_no; queue_id
'''  
def send_queue_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            req = ofp_parser.OFPQueueStatsRequest(datapath, 0, ofp.OFPP_ANY,ofp.OFPQ_ALL)
            datapath.send_msg(req)
            
@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_QUEUE, OFPQueueStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPQueueStatsReply(OFPMultipartReply)    
'''
队列统计回复消息: 交换机使用此消息响应聚合流统计请求。   body
'''  
		@set_ev_cls(ofp_event.EventOFPQueueStatsReply, MAIN_DISPATCHER)
        def queue_stats_reply_handler(self, ev):
            queues = []
            for stat in ev.msg.body:
                queues.append('port_no=%d queue_id=%d '
                              'tx_bytes=%d tx_packets=%d tx_errors=%d '
                              'duration_sec=%d duration_nsec=%d' %
                              (stat.port_no, stat.queue_id,
                               stat.tx_bytes, stat.tx_packets, stat.tx_errors,
                               stat.duration_sec, stat.duration_nsec))
            self.logger.debug('QueueStats: %s', queues)
            
class OFPBucketCounter(StringifyMixin)
class OFPGroupStats(StringifyMixin)
''' 消息回复实例 '''
@_set_stats_type(ofproto.OFPMP_GROUP, OFPGroupStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPGroupStatsRequest(OFPMultipartRequest)
'''
组统计请求消息: 控制器使用此消息查询一个或多个组的统计信息。   属性： flags; group_id(OFPG_ALL表全部)
'''
		def send_group_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            req = ofp_parser.OFPGroupStatsRequest(datapath, 0, ofp.OFPG_ALL)
            datapath.send_msg(req)
            
@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_GROUP, OFPGroupStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPGroupStatsReply(OFPMultipartReply)
'''
群统计回复消息: 交换机使用此消息响应组统计请求。      body
'''
		@set_ev_cls(ofp_event.EventOFPGroupStatsReply, MAIN_DISPATCHER)
        def group_stats_reply_handler(self, ev):
            groups = []
            for stat in ev.msg.body:
                groups.append('length=%d group_id=%d '
                              'ref_count=%d packet_count=%d byte_count=%d '
                              'duration_sec=%d duration_nsec=%d' %
                              (stat.length, stat.group_id,
                               stat.ref_count, stat.packet_count,
                               stat.byte_count, stat.duration_sec,
                               stat.duration_nsec))
            self.logger.debug('GroupStats: %s', groups)
            
class OFPGroupDescStats(StringifyMixin)
''' 消息回复实例 '''
@_set_stats_type(ofproto.OFPMP_GROUP_DESC, OFPGroupDescStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPGroupDescStatsRequest(OFPMultipartRequest)
'''
组描述请求消息: 控制器使用此消息列出交换机上的组集。    flags
'''
		def send_group_desc_stats_request(self, datapath):
            ofp_parser = datapath.ofproto_parser
            req = ofp_parser.OFPGroupDescStatsRequest(datapath, 0)
            datapath.send_msg(req)
            
@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_GROUP_DESC, OFPGroupDescStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPGroupDescStatsReply(OFPMultipartReply)
''' body'''
		@set_ev_cls(ofp_event.EventOFPGroupDescStatsReply, MAIN_DISPATCHER)
        def group_desc_stats_reply_handler(self, ev):
            descs = []
            for stat in ev.msg.body:
                descs.append('length=%d type=%d group_id=%d '
                             'buckets=%s' %
                             (stat.length, stat.type, stat.group_id,
                              stat.bucket))
            self.logger.debug('GroupDescStats: %s', descs)
            
class OFPGroupFeaturesStats(ofproto_parser.namedtuple('OFPGroupFeaturesStats',
                           ('types', 'capabilities','max_groups', 'actions')))
''' 消息回复实例 '''
@_set_stats_type(ofproto.OFPMP_GROUP_FEATURES, OFPGroupFeaturesStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPGroupFeaturesStatsRequest(OFPMultipartRequest)
'''  
组功能请求消息: 控制器使用此消息列出交换机上组的功能。   flags
'''
		def send_group_features_stats_request(self, datapath):
            ofp_parser = datapath.ofproto_parser
            req = ofp_parser.OFPGroupFeaturesStatsRequest(datapath, 0)
            datapath.send_msg(req)
            
@OFPMultipartReply.register_stats_type(body_single_struct=True)
@_set_stats_type(ofproto.OFPMP_GROUP_FEATURES, OFPGroupFeaturesStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPGroupFeaturesStatsReply(OFPMultipartReply)
		@set_ev_cls(ofp_event.EventOFPGroupFeaturesStatsReply, MAIN_DISPATCHER)
        def group_features_stats_reply_handler(self, ev):
            body = ev.msg.body
            self.logger.debug('GroupFeaturesStats: types=%d '
                              'capabilities=0x%08x max_groups=%s '
                              'actions=%s',
                              body.types, body.capabilities,
                              body.max_groups, body.actions)
            
class OFPMeterBandStats(StringifyMixin)
class OFPMeterStats(StringifyMixin)
''' 消息回复实例 '''
@_set_stats_type(ofproto.OFPMP_METER, OFPMeterStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPMeterStatsRequest(OFPMultipartRequest) 
'''
仪表统计请求消息: 控制器使用此消息查询一个或多个仪表的统计信息。
'''
		def send_meter_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            req = ofp_parser.OFPMeterStatsRequest(datapath, 0, ofp.OFPM_ALL)
            datapath.send_msg(req)
            
@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_METER, OFPMeterStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPMeterStatsReply(OFPMultipartReply)
''' body'''
		@set_ev_cls(ofp_event.EventOFPMeterStatsReply, MAIN_DISPATCHER)
        def meter_stats_reply_handler(self, ev):
            meters = []
            for stat in ev.msg.body:
                meters.append('meter_id=0x%08x len=%d flow_count=%d '
                              'packet_in_count=%d byte_in_count=%d '
                              'duration_sec=%d duration_nsec=%d '
                              'band_stats=%s' %
                              (stat.meter_id, stat.len, stat.flow_count,
                               stat.packet_in_count, stat.byte_in_count,
                               stat.duration_sec, stat.duration_nsec,
                               stat.band_stats))
            self.logger.debug('MeterStats: %s', meters)

class OFPMeterBand(StringifyMixin)
class OFPMeterBandHeader(OFPMeterBand)
@OFPMeterBandHeader.register_meter_band_type(
    ofproto.OFPMBT_DROP, ofproto.OFP_METER_BAND_DROP_SIZE)
class OFPMeterBandDrop(OFPMeterBandHeader)
@OFPMeterBandHeader.register_meter_band_type(
    ofproto.OFPMBT_DSCP_REMARK,
    ofproto.OFP_METER_BAND_DSCP_REMARK_SIZE)
class OFPMeterBandDscpRemark(OFPMeterBandHeader)
@OFPMeterBandHeader.register_meter_band_type(
    ofproto.OFPMBT_EXPERIMENTER,
    ofproto.OFP_METER_BAND_EXPERIMENTER_SIZE)
class OFPMeterBandExperimenter(OFPMeterBandHeader)
class OFPMeterConfigStats(StringifyMixin)
''' 消息回复实例 '''
@_set_stats_type(ofproto.OFPMP_METER_CONFIG, OFPMeterConfigStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPMeterConfigStatsRequest(OFPMultipartRequest)
'''
仪表配置统计请求消息: 控制器使用此消息查询一个或多个仪表的配置。   flags; meter_id
'''
		def send_meter_config_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            req = ofp_parser.OFPMeterConfigStatsRequest(datapath, 0,
                                                        ofp.OFPM_ALL)
            datapath.send_msg(req)
            
@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_METER_CONFIG, OFPMeterConfigStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPMeterConfigStatsReply(OFPMultipartReply)   
''' body'''
		@set_ev_cls(ofp_event.EventOFPMeterConfigStatsReply, MAIN_DISPATCHER)
        def meter_config_stats_reply_handler(self, ev):
            configs = []
            for stat in ev.msg.body:
                configs.append('length=%d flags=0x%04x meter_id=0x%08x '
                               'bands=%s' %
                               (stat.length, stat.flags, stat.meter_id,
                                stat.bands))
            self.logger.debug('MeterConfigStats: %s', configs)
            
class OFPMeterFeaturesStats(ofproto_parser.namedtuple('OFPMeterFeaturesStats',
        ('max_meter', 'band_types', 'capabilities','max_bands', 'max_color')))   
''' 消息回复实例 '''
@_set_stats_type(ofproto.OFPMP_METER_FEATURES, OFPMeterFeaturesStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPMeterFeaturesStatsRequest(OFPMultipartRequest)
'''
仪表功能统计请求消息: 控制器使用该消息来查询计量子系统的特征集。  flags
'''
		def send_meter_features_stats_request(self, datapath):
            ofp_parser = datapath.ofproto_parser
            req = ofp_parser.OFPMeterFeaturesStatsRequest(datapath, 0)
            datapath.send_msg(req)
            
@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_METER_FEATURES, OFPMeterFeaturesStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPMeterFeaturesStatsReply(OFPMultipartReply)
''' body'''
		@set_ev_cls(ofp_event.EventOFPMeterFeaturesStatsReply, MAIN_DISPATCHER)
        def meter_features_stats_reply_handler(self, ev):
            features = []
            for stat in ev.msg.body:
                features.append('max_meter=%d band_types=0x%08x '
                                'capabilities=0x%08x max_bands=%d '
                                'max_color=%d' %
                                (stat.max_meter, stat.band_types,
                                 stat.capabilities, stat.max_bands,
                                 stat.max_color))
            self.logger.debug('MeterFeaturesStats: %s', features)
            
class OFPTableFeaturesStats(StringifyMixin)
class OFPTableFeatureProp(OFPPropBase)
class OFPTableFeaturePropUnknown(OFPTableFeatureProp)
class OFPInstructionId(StringifyMixin)

@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_INSTRUCTIONS)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_INSTRUCTIONS_MISS)
class OFPTableFeaturePropInstructions(OFPTableFeatureProp)

@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_NEXT_TABLES)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_NEXT_TABLES_MISS)
class OFPTableFeaturePropNextTables(OFPTableFeatureProp)

class OFPActionId(StringifyMixin)

@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_WRITE_ACTIONS)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_WRITE_ACTIONS_MISS)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_APPLY_ACTIONS)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_APPLY_ACTIONS_MISS)
class OFPTableFeaturePropActions(OFPTableFeatureProp)

class OFPOxmId(StringifyMixin)
class OFPExperimenterOxmId(OFPOxmId)

@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_MATCH)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_WILDCARDS)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_WRITE_SETFIELD)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_WRITE_SETFIELD_MISS)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_APPLY_SETFIELD)
@OFPTableFeatureProp.register_type(ofproto.OFPTFPT_APPLY_SETFIELD_MISS)
class OFPTableFeaturePropOxm(OFPTableFeatureProp)

@_set_stats_type(ofproto.OFPMP_TABLE_FEATURES, OFPTableFeaturesStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPTableFeaturesStatsRequest(OFPMultipartRequest)
'''
表功能统计请求消息: 控制器使用此消息查询表格功能。  body:OFPTableFeaturesStats实例
'''
@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_TABLE_FEATURES, OFPTableFeaturesStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPTableFeaturesStatsReply(OFPMultipartReply)
'''
body
'''

@_set_stats_type(ofproto.OFPMP_PORT_DESC, OFPPort)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPPortDescStatsRequest(OFPMultipartRequest)
'''
端口描述请求消息: 控制器使用此消息查询所有端口的描述。
'''
		def send_port_desc_stats_request(self, datapath):
            ofp_parser = datapath.ofproto_parser
            req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
            datapath.send_msg(req)
@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_PORT_DESC, OFPPort)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPPortDescStatsReply(OFPMultipartReply)
'''body : OFPPort 实例'''
		@set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
        def port_desc_stats_reply_handler(self, ev):
            ports = []
            for p in ev.msg.body:
                ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x '
                             'state=0x%08x curr=0x%08x advertised=0x%08x '
                             'supported=0x%08x peer=0x%08x curr_speed=%d '
                             'max_speed=%d' %
                             (p.port_no, p.hw_addr,
                              p.name, p.config,
                              p.state, p.curr, p.advertised,
                              p.supported, p.peer, p.curr_speed,
                              p.max_speed))
            self.logger.debug('OFPPortDescStatsReply received: %s', ports)

            
class ONFFlowMonitorRequest(StringifyMixin)

@_set_stats_type(ofproto.OFPMP_EXPERIMENTER, OFPExperimenterMultipart)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class ONFFlowMonitorStatsRequest(OFPExperimenterStatsRequestBase)
''' flags ; body'''

```

#### OFP 匹配

```python
class Flow(object)

class FlowWildcards(object)

### 重点
from ryu.ofproto.ofproto_parser import StringifyMixin
class OFPMatch(StringifyMixin)
'''
流匹配结构：该类是具有编写/查询API的流匹配结构的实现。  可以通过以下 关键字参数 定义流匹配： （ofproto.oxm_types）
in_port

eth_dst:  MAC 地址
eth_src:
eth_type: Integer 16bit (Ethernet frame type)
ip_proto : Integer 8bit    IP protocol
ipv4_src
ipv4_dst
	tcp_src          Integer 16bit   TCP source port
    tcp_dst          Integer 16bit   TCP destination port
    udp_src          Integer 16bit   UDP source port
    udp_dst          Integer 16bit   UDP destination port
    sctp_src         Integer 16bit   SCTP source port
    sctp_dst         Integer 16bit   SCTP destination port
    icmpv4_type      Integer 8bit    ICMP type
    icmpv4_code      Integer 8bit    ICMP code
    arp_op           Integer 16bit   ARP opcode
    arp_spa          IPv4 address    ARP source IPv4 address
    arp_tpa          IPv4 address    ARP target IPv4 address
    arp_sha          MAC address     ARP source hardware address
    arp_tha          MAC address     ARP target hardware address
    tunnel_id        Integer 64bit   Logical Port Metadata
    tcp_flags
    actset_output
'''  # 代码实例：
match = parser.OFPMatch(in_port=1, eth_type=0x86dd,
       ipv6_src=('2001:db8:bd05:1d2:288a:1fc0:1:10ee'，'ffff:ffff:ffff:ffff::'),
       ipv6_dst='2001:db8:bd05:1d2:288a:1fc0:1:10ee')

# query
if 'ipv6_src' in match:
	print match['ipv6_src']
# 有关支持的Nicira实验者匹配的列表，参考 `ryu.ofproto.nx_match <nx_match_structures>`


class OFPPropUnknown(StringifyMixin)
class OFPPropBase(StringifyMixin)
class OFPPropCommonExperimenter4ByteData(StringifyMixin)

class OFPMatchField(StringifyMixin)

@OFPMatchField.register_field_header([ofproto.OXM_OF_IN_PORT])
class MTInPort(OFPMatchField)

@OFPMatchField.register_field_header([ofproto.OXM_OF_METADATA,ofproto.OXM_OF_METADATA_W])
class MTMetadata(OFPMatchField)

@OFPMatchField.register_field_header([ofproto.OXM_OF_ETH_DST, ofproto.OXM_OF_ETH_DST_W])
class MTEthDst(OFPMatchField)

@OFPMatchField.register_field_header([ofproto.OXM_OF_ETH_SRC, ofproto.OXM_OF_ETH_SRC_W])
class MTEthSrc(OFPMatchField)

OFPMatchField.register_field_header([ofproto.OXM_OF_ETH_TYPE])
class MTEthType(OFPMatchField)

@OFPMatchField.register_field_header([ofproto.OXM_OF_IP_PROTO])
class MTIPProto(OFPMatchField)

@OFPMatchField.register_field_header([ofproto.OXM_OF_IPV4_SRC,ofproto.OXM_OF_IPV4_SRC_W])
class MTIPV4Src(OFPMatchField)

@OFPMatchField.register_field_header([ofproto.OXM_OF_IPV4_DST,ofproto.OXM_OF_IPV4_DST_W])
class MTIPV4Dst(OFPMatchField)

@OFPMatchField.register_field_header([ofproto.OXM_OF_TCP_SRC])
class MTTCPSrc(OFPMatchField)

@OFPMatchField.register_field_header([ofproto.OXM_OF_TCP_DST])
class MTTCPDst(OFPMatchField)

@OFPMatchField.register_field_header([ofproto.OXM_OF_UDP_SRC])
class MTUDPSrc(OFPMatchField)
@OFPMatchField.register_field_header([ofproto.OXM_OF_UDP_DST])
class MTUDPDst(OFPMatchField)

@OFPMatchField.register_field_header([ofproto.OXM_OF_SCTP_SRC])
class MTSCTPSrc(OFPMatchField)
@OFPMatchField.register_field_header([ofproto.OXM_OF_SCTP_DST])
class MTSCTPDst(OFPMatchField)
...
```

#### 包处理 和 流处理  （重点）

```python
@_register_parser
@_set_msg_type(ofproto.OFPT_PACKET_IN)
class OFPPacketIn(MsgBase)
'''
packet-in报文：  交换机通过 该报文 将接收到的数据包发送给控制器。  属性：
buffer_id:  由 datapath 分配的ID;   total_len: 帧的全长； reason： 发送数据包的原因
table_id;   cookie;  match;     data: ethernet frame
'''   # 代码实例：
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
        reason = 'INVALID TTL'          # TTL, time to live, TTL是IPv4报头的一个8 bit字段
    else:         #  TTL的作用是限制IP数据包在计算机网络中的存在的时间
        reason = 'unknown'
	self.logger.debug('OFPPacketIn received: '
                      'buffer_id=%x total_len=%d reason=%s '
                      'table_id=%d cookie=%d match=%s data=%s',
                      msg.buffer_id, msg.total_len, reason, 
                       msg.table_id, msg.cookie, msg.match,
                       utils.hex_array(msg.data))
    
@_register_parser
@_set_msg_type(ofproto.OFPT_FLOW_REMOVED)
class OFPFlowRemoved(MsgBase)
'''
流删除报文：  当 流条目超时 或 被删除 时，交换机会用此消息通知控制器。   拥有以下属性：
cookie; priority;  reason;  table_id;  
duration_sec:  流处于活动状态的时间，单位为秒;  duration_sec:  流处于活动状态的时间，单位为纳秒
idle_timeout: 从原始流模式的 空闲 超时；  hard_timeout
packet_count；  byte_count;    match
'''  # 代码实例：
		@set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
        def flow_removed_handler(self, ev):
            msg = ev.msg
            dp = msg.datapath
            ofp = dp.ofproto
            if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
                reason = 'IDLE TIMEOUT'     # 超时
            elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
                reason = 'HARD TIMEOUT'
            elif msg.reason == ofp.OFPRR_DELETE:
                reason = 'DELETE'          # 流表被删除
            elif msg.reason == ofp.OFPRR_GROUP_DELETE:
                reason = 'GROUP DELETE'    # 组表被删除
            else:
                reason = 'unknown'
            self.logger.debug('OFPFlowRemoved received: '
                              'cookie=%d priority=%d reason=%s table_id=%d '
                              'duration_sec=%d duration_nsec=%d '
                              'idle_timeout=%d hard_timeout=%d '
                              'packet_count=%d byte_count=%d match.fields=%s',
                              msg.cookie, msg.priority, reason, msg.table_id,
                              msg.duration_sec, msg.duration_nsec,
                              msg.idle_timeout, msg.hard_timeout,
                              msg.packet_count, msg.byte_count, msg.match)    
            
@_set_msg_type(ofproto.OFPT_PACKET_OUT)
class OFPPacketOut(MsgBase)   
'''
packet-out报文： 控制器使用此消息通过交换机发送数据包。    有以下属性：
buffer_id:  datapath 分配的ID（如果没有则为 OFP_NO_BUFFER
in_port;        actions;        data( 二进制类型值的数据包数据或 packet.Packet的实例)
'''   #代码实例：
        def send_packet_out(self, datapath, buffer_id, in_port):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD, 0)]
            req = ofp_parser.OFPPacketOut(datapath, buffer_id, in_port, actions)
            datapath.send_msg(req)
            
@_register_parser
@_set_msg_type(ofproto.OFPT_FLOW_MOD)
class OFPFlowMod(MsgBase)
	def __init__(self, datapath, cookie=0, cookie_mask=0, table_id=0,
                 command=ofproto.OFPFC_ADD,
                 idle_timeout=0, hard_timeout=0,
                 priority=ofproto.OFP_DEFAULT_PRIORITY,
                 buffer_id=ofproto.OFP_NO_BUFFER,
                 out_port=0, out_group=0, flags=0,
                 match=None,
                 instructions=None)
'''
修改流条目消息:  控制器发送该消息以修改流表。    拥有以下属性：
cookie; cookie_mask;   table_id;   
command(命令值： ADD\MODIFY\MODIFY_STRICT\DELETE\DELETE_STRICT )
idle_timeout;  hard_timeout;   priority;  buffer_id;   
out_port: 对于``OFPFC_DELETE*``命令，要求匹配条目 将其包括 作为输出端口
out_group： 对于``OFPFC_DELETE*``命令， 要求匹配条目 包括它 作为输出组
flags(SEND_FLOW_REM\CHECK_OVERLAP\RESET_COUNTS\NO_PKT_COUNTS\NO_BYT_COUNTS)
match;    instructions
'''   #代码实例：    ## 重点 match;  actions;  inst(instructions)
		def send_flow_mod(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            cookie = cookie_mask = 0
            table_id = 0
            idle_timeout = hard_timeout = 0
            priority = 32768
            buffer_id = ofp.OFP_NO_BUFFER
            match = ofp_parser.OFPMatch(in_port=1, eth_src='00:00:00:00:00:0`', ipv4_src='10.0.0.201', tcp_src='50070', eth_dst='00:00:00:00:00:03', ipv4_dst='10.0.0.203', tcp_dst='50070')
            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL, 0)]
            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                        table_id, ofp.OFPFC_ADD,
                                        idle_timeout, hard_timeout,
                                        priority, buffer_id,
                                        ofp.OFPP_ANY, ofp.OFPG_ANY,
                                        ofp.OFPFF_SEND_FLOW_REM,
                                        match, inst)
            datapath.send_msg(req)
            
            
@_set_msg_type(ofproto.OFPT_TABLE_MOD)
class OFPTableMod(MsgBase)
'''
流表配置消息: 控制器发送此消息以配置表状态。   属性： table_id(OFPTT_ALL 表示所有tables);  config(3)
'''   # 代码实例：
		def send_table_mod(self, datapath):
            ofp_parser = datapath.ofproto_parser
            req = ofp_parser.OFPTableMod(datapath, 1, 3)
            datapath.send_msg(req) 
```

##### 流信息

```python
class OFPFlowStats(StringifyMixin)    # 作为消息回复实例的类

class OFPFlowStatsRequestBase(OFPMultipartRequest)

@_set_stats_type(ofproto.OFPMP_FLOW, OFPFlowStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REQUEST)
class OFPFlowStatsRequest(OFPFlowStatsRequestBase)
'''
单个流量统计请求消息: 控制器使用此消息来查询单个流统计信息。   属性：
flags(0或者OFPMPF_REQ_MORE)  ； table_id;  out_put; out_group;  cookie; cookie_mask; match
'''   #代码实例：
		def send_flow_stats_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            cookie = cookie_mask = 0
            match = ofp_parser.OFPMatch(in_port=1)
            req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                                 ofp.OFPTT_ALL,
                                                 ofp.OFPP_ANY, ofp.OFPG_ANY,
                                                 cookie, cookie_mask,
                                                 match)
            datapath.send_msg(req)
            
@OFPMultipartReply.register_stats_type()
@_set_stats_type(ofproto.OFPMP_FLOW, OFPFlowStats)
@_set_msg_type(ofproto.OFPT_MULTIPART_REPLY)
class OFPFlowStatsReply(OFPMultipartReply)
'''
个别流量统计回复消息: 交换机使用此消息响应单个流统计请求。   属性： body(OFPFLOWStats的实例)
'''  # 代码实例：
		@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
        def flow_stats_reply_handler(self, ev):
            flows = []
            for stat in ev.msg.body:
                flows.append('table_id=%s '
                             'duration_sec=%d duration_nsec=%d '
                             'priority=%d '
                             'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                             'cookie=%d packet_count=%d byte_count=%d '
                             'match=%s instructions=%s' %
                             (stat.table_id,
                              stat.duration_sec, stat.duration_nsec,
                              stat.priority,
                              stat.idle_timeout, stat.hard_timeout, stat.flags,
                              stat.cookie, stat.packet_count, stat.byte_count,
                              stat.match, stat.instructions))
            self.logger.debug('FlowStats: %s', flows)
```

#### 端口

```python
class OFPPort(ofproto_parser.namedtuple('OFPPort', (
        'port_no', 'hw_addr', 'name', 'config', 'state', 'curr',
        'advertised', 'supported', 'peer', 'curr_speed', 'max_speed')))
'''
hw_addr: 端口的MAC地址；  
name： 包含 可读名称接口 的以Null结尾的字符串。
config： 端口配置标志的 Bitmap（位图）。
state： 端口 状态标志 的 Bitmap。
curr: 当前功能；     advertised: 端口正通告的功能；   supported: 端口支持的功能；
curr_speed: 当前端口比特率(以kbps为单位);  max_speed
'''

@_register_parser
@_set_msg_type(ofproto.OFPT_PORT_STATUS)
class OFPPortStatus(MsgBase)
'''
端口状态信息： 交换机将 端口更改 通知控制器；  属性： reason; desc(OFPPort的实例)
'''   #代码实例：
		@set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
        def port_status_handler(self, ev):
            msg = ev.msg
            dp = msg.datapath
            ofp = dp.ofproto
            if msg.reason == ofp.OFPPR_ADD:
                reason = 'ADD'
            elif msg.reason == ofp.OFPPR_DELETE:
                reason = 'DELETE'
            elif msg.reason == ofp.OFPPR_MODIFY:
                reason = 'MODIFY'
            else:
                reason = 'unknown'
            self.logger.debug('OFPPortStatus received: reason=%s desc=%s',
                              reason, msg.desc)
      
@_set_msg_type(ofproto.OFPT_PORT_MOD)
class OFPPortMod(MsgBase)
'''
端口修改消息: 控制器 发送此消息以 修改端口 的行为。      属性：、
port_no;    hw_addr:硬件地址必须与'OFPSwitchFeatures'的'OFPPort'的 hw_addr 相同。
config: 配置标志的位图(DOWN/RECV/FWD/PACKET_IN)
mask: 要更改的上述配置标志的位图;  advertise: (10M_HD/...)
'''   # 代码实例：
		def send_port_mod(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            port_no = 3
            hw_addr = 'fa:c8:e8:76:1d:7e'
            config = 0
            mask = (ofp.OFPPC_PORT_DOWN | ofp.OFPPC_NO_RECV |
                    ofp.OFPPC_NO_FWD | ofp.OFPPC_NO_PACKET_IN)
            advertise = (ofp.OFPPF_10MB_HD | ofp.OFPPF_100MB_FD |
                         ofp.OFPPF_1GB_FD | ofp.OFPPF_COPPER |
                         ofp.OFPPF_AUTONEG | ofp.OFPPF_PAUSE |
                         ofp.OFPPF_PAUSE_ASYM)
            req = ofp_parser.OFPPortMod(datapath, port_no, hw_addr, config,
                                        mask, advertise)
            datapath.send_msg(req)
```

#### Instructions、Actions

```python
class OFPInstruction(StringifyMixin)

@OFPInstruction.register_instruction_type([ofproto.OFPIT_GOTO_TABLE])
class OFPInstructionGotoTable(OFPInstruction)
'''
Goto table instruction: 此指令指示处理流水线中的下一个表。  属性： table_id: next table
'''

@OFPInstruction.register_instruction_type([ofproto.OFPIT_WRITE_METADATA])
class OFPInstructionWriteMetadata(OFPInstruction)
'''
写入元数据指令：  此指令将屏蔽的元数据值写入元数据字段。  属性： metadata;  metadata_mask
'''

### 重点
@OFPInstruction.register_instruction_type([ofproto.OFPIT_WRITE_ACTIONS,
                                           ofproto.OFPIT_APPLY_ACTIONS,
                                           ofproto.OFPIT_CLEAR_ACTIONS])
class OFPInstructionActions(OFPInstruction)
'''
actions instruction: 此指令写入/应用/清除操作。  属性：
type ： 有三种类型；   actions:  list of OpenFlow action class
'''

@OFPInstruction.register_instruction_type([ofproto.OFPIT_METER])
class OFPInstructionMeter(OFPInstruction)
'''
meter instruction :  该指定应用于 计数器meter。   属性： meter_id (meter实例)
'''


class OFPActionHeader(StringifyMixin)
class OFPAction(OFPActionHeader)   
## 重点#########################################
@OFPAction.register_action_type(ofproto.OFPAT_OUTPUT,
                                ofproto.OFP_ACTION_OUTPUT_SIZE)
class OFPActionOutput(OFPAction)
'''
输出操作: 此操作表示将数据包输出到交换机端口。   属性：
port： 输出端口；     max_len: 发送到控制器的最大长度(默认值 ofproto.OFPCML_MAX)
'''

@OFPAction.register_action_type(ofproto.OFPAT_GROUP,
                                ofproto.OFP_ACTION_GROUP_SIZE)
class OFPActionGroup(OFPAction)
'''
 Group action: 此操作指示用于处理数据包的组。   属性： group_id
'''

@OFPAction.register_action_type(ofproto.OFPAT_SET_QUEUE,
                                ofproto.OFP_ACTION_SET_QUEUE_SIZE)
class OFPActionSetQueue(OFPAction)
'''
设置队列操作： 此操作设置队列ID，该队列ID将用于将流映射到 端口上 已配置的队列。(队列 需要提前配置好)
属性： queue_id: Queue ID for the packets
'''

## 非重点
@OFPAction.register_action_type(ofproto.OFPAT_SET_MPLS_TTL,
                                ofproto.OFP_ACTION_MPLS_TTL_SIZE)
class OFPActionSetMplsTtl(OFPAction)
'''
Set MPLS TTL action
属性： mpls_ttl
'''

@OFPAction.register_action_type(ofproto.OFPAT_DEC_MPLS_TTL,
                                ofproto.OFP_ACTION_HEADER_SIZE)
class OFPActionDecMplsTtl(OFPAction)
''' 减少MPLS TTL操作 '''

@OFPAction.register_action_type(ofproto.OFPAT_SET_NW_TTL,
                                ofproto.OFP_ACTION_NW_TTL_SIZE)
class OFPActionSetNwTtl(OFPAction)
''' 设置IP TTL操作.   属性： nw_ttl '''

@OFPAction.register_action_type(ofproto.OFPAT_DEC_NW_TTL,
                                ofproto.OFP_ACTION_HEADER_SIZE)
class OFPActionDecNwTtl(OFPAction)
''' 减少 IP TTL操作.  '''

@OFPAction.register_action_type(ofproto.OFPAT_COPY_TTL_OUT,
                                ofproto.OFP_ACTION_HEADER_SIZE)
class OFPActionCopyTtlOut(OFPAction)
''' 
复制TTL输出操作: 此操作将TTL从具有TTL的倒数第二个标头复制到具有TTL的最外面的标头。
'''

@OFPAction.register_action_type(ofproto.OFPAT_COPY_TTL_IN,
                                ofproto.OFP_ACTION_HEADER_SIZE)
class OFPActionCopyTtlIn(OFPAction)

@OFPAction.register_action_type(ofproto.OFPAT_PUSH_VLAN,
                                ofproto.OFP_ACTION_PUSH_SIZE)
class OFPActionPushVlan(OFPAction)
'''
推送VLAN操作：此操作会将新的VLAN标签推送到数据包。  属性：ethertype （ 默认802.1Q. (0x8100)）
'''

@OFPAction.register_action_type(ofproto.OFPAT_PUSH_MPLS,
                                ofproto.OFP_ACTION_PUSH_SIZE)
class OFPActionPushMpls(OFPAction)
##Push MPLS action

@OFPAction.register_action_type(ofproto.OFPAT_POP_VLAN,
                                ofproto.OFP_ACTION_HEADER_SIZE)
class OFPActionPopVlan(OFPAction)
## Pop VLAN action：此操作从数据包中弹出最外层的VLAN标记

@OFPAction.register_action_type(ofproto.OFPAT_POP_MPLS,
                                ofproto.OFP_ACTION_POP_MPLS_SIZE)
class OFPActionPopMpls(OFPAction)
## Pop MPLS action：此操作从数据包中弹出MPLS报头。

@OFPAction.register_action_type(ofproto.OFPAT_SET_FIELD,
                                ofproto.OFP_ACTION_SET_FIELD_SIZE)
class OFPActionSetField(OFPAction)
'''
Set field action: 此操作修改数据包中的报头字段。  可用于此的关键字集合与OFPMatch相同。
'''  #代码实例
set_field = OFPActionSetField(eth_src="00:00:00:00:00:00")

@OFPAction.register_action_type(ofproto.OFPAT_PUSH_PBB,
                                ofproto.OFP_ACTION_PUSH_SIZE)
class OFPActionPushPbb(OFPAction)
## Push PBB action       属性：ethertype   

@OFPAction.register_action_type(ofproto.OFPAT_POP_PBB,
                                ofproto.OFP_ACTION_HEADER_SIZE)
class OFPActionPopPbb(OFPAction)
## Pop PBB action

@OFPAction.register_action_type(
    ofproto.OFPAT_EXPERIMENTER,
    ofproto.OFP_ACTION_EXPERIMENTER_HEADER_SIZE)
class OFPActionExperimenter(OFPAction)
'''
Experimenter action: 此操作是实验者的可扩展操作。  属性：experimenter： Experimenter ID
'''
class OFPActionExperimenterUnknown(OFPActionExperimenter)
```

```python
class OFPBucket(StringifyMixin)

@_set_msg_type(ofproto.OFPT_GROUP_MOD)
class OFPGroupMod(MsgBase)
'''
修改组条目消息: 控制器发送此消息以 修改组表。   属性：
command:  默认OFPGC_ADD （MODIFY/DELETE)
type：  默认OFPGT_ALL  （SELECT/INDIRECT/FF)
group_id ;      buckets: list of 'OFPBucket'
'''     #代码实例：
		def send_group_mod(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            port = 1
            max_len = 2000
            actions = [ofp_parser.OFPActionOutput(port, max_len)]
            weight = 100
            watch_port = 0
            watch_group = 0
            buckets = [ofp_parser.OFPBucket(weight, watch_port, watch_group, actions)]
            group_id = 1
            req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                         ofp.OFPGT_SELECT, group_id, buckets)
            datapath.send_msg(req)
```

#### Meter

```python
@_set_msg_type(ofproto.OFPT_METER_MOD)
class OFPMeterMod(MsgBase)
'''
meter修改信息： 控制器发送此消息以修改仪表。   属性：
command： 默认ADD(ADD/MODIFY/DELETE);   flags(KBPS默认KTPS/BURST/STATS);    meter_id：默认1;
bands: 以下类的实例（OFPMeterBandDrop、OFPMeterBandDscpRemark、 OFPMeterBandExperimenter）
'''    、



@_set_msg_type(ofproto.OFPT_QUEUE_GET_CONFIG_REQUEST)
class OFPQueueGetConfigRequest(MsgBase)
'''
队列配置请求消息: 
'''
		def send_queue_get_config_request(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            req = ofp_parser.OFPQueueGetConfigRequest(datapath, ofp.OFPP_ANY)
            datapath.send_msg(req)
            
class OFPQueuePropHeader(StringifyMixin)
class OFPQueueProp(OFPQueuePropHeader)

@OFPQueueProp.register_property(ofproto.OFPQT_MIN_RATE,
                                ofproto.OFP_QUEUE_PROP_MIN_RATE_SIZE)
class OFPQueuePropMinRate(OFPQueueProp)

@OFPQueueProp.register_property(ofproto.OFPQT_MAX_RATE,
                                ofproto.OFP_QUEUE_PROP_MAX_RATE_SIZE)
class OFPQueuePropMaxRate(OFPQueueProp)

class OFPPacketQueue(StringifyMixin)

@_register_parser
@_set_msg_type(ofproto.OFPT_QUEUE_GET_CONFIG_REPLY)
class OFPQueueGetConfigReply(MsgBase)


```







### ofproto_v1_3

```python
OFP_VERSION = 0x04
MAX_XID = 0xffffffff

OFPT_HELLO

OFPT_ERROR

OFPT_ECHO_REQUEST

OFPT_ECHO_REPLY

OFPT_EXPERIMENTER

OFPT_FEATURES_REQUEST

OFPT_FEATURES_REPLY

OFPT_GET_CONFIG_REQUEST

OFPT_GET_CONFIG_REPLY
'''
OXM_OF_IN_PORT
OXM_OF_METADATA
OXM_OF_METADATA_W
...
'''
OFPT_PACKET_IN
OFPT_FLOW_REMOVED
OFPT_PACKET_OUT
OFPFlowMod   # 重点
OFPT_TABLE_MOD

# By default, choose a priority in the middle.
OFP_DEFAULT_PRIORITY = 0x8000

OFPP_NORMAL     ## OFPP_NORMAL = 0xfffffffa   # Process with normal L2/L3 switching.
OFPIT_APPLY_ACTIONS   # Applies the action(s) immediately
## actions， 端口
OFPP_IN_PORT   #将packet从输入端口发送出去。必须显式使用此虚拟端口，才能从输入端口送出。
OFPP_TABLE  #在流程表中执行操作（注：这只能是 packet-out消息的 目的地端口）
OFPP_FLOOD  # 除 输入端口 和 那些被STP禁用的端口外的所有物理端口。 （重点）
OFPP_ALL    # 除输入端口外的所有物理端口。
OFPP_CONTROLLER   # Send to controller
OFPP_LOCAL   # 本地 openflow 'port'
OFPP_ANY    # 未与物理端口关联
## instruction_type
OFPIT_GOTO_TABLE = 1            # Setup the next table in the lookup pipeline.
OFPIT_WRITE_METADATA = 2        # Setup the metadata field for use later in pipeline.
OFPIT_WRITE_ACTIONS = 3         # Write the action(s) onto the datapath action set
OFPIT_CLEAR_ACTIONS = 5         # Clears all actions from the datapath action set
OFPIT_METER = 6                 # Apply meter (rate limiter)
OFPIT_EXPERIMENTER = 0xFFFF     # Experimenter instruction

OFPT_PORT_STATUS
OFPT_PORT_MOD

OFPT_GROUP_MOD

OFPIT_METER
OFPT_METER_MOD
```

### packet

```python
from ryu.lib.packet import packet

#from ryu.lib.packet import ether_types

## 重要
class Packet(StringifyMixin):
'''
分组解码器/编码器类: 实例用于对 单个数据包 进行解码或编码。
*data* 是描述要解码的原始数据报的字节数组。 解码时，数据包对象是可迭代的。
迭代值是协议(例如 ethernet, ipv4等)头和载荷: 以在线顺序迭代。
协议头： packet_base.PacketBase 子类的协议;  载荷是 bytearray.
'data' 在对数据包进行编码时应省略。
''' 
	def __init__(self, data=None, protocols=None, parse_cls=ethernet.ethernet):
    # 属性有 data, protocols
    	super().__init__()
        self.data = data
        if protocols is None:
            self.protocols = []
        else:
            self.protocols = protocols
        if self.data:
            self._parser(parse_cls)
    def serialize(self)
    # 对数据包进行编码并存储结果字节数组; 只有在对数据包进行编码时，此方法才是合法的。
    def add_protocol(self, proto)
    '''为此数据包注册协议'proto':  只有在对数据包进行编码时，此方法才是合法的。
    	编码数据包时，注册协议(以太网、IPv4...)， 并添加到此数据包的报头。
    	协议头应该在调用self.serialize之前以在线顺序注册。
    '''
    def get_protocols(self, protocol) 
    '''Returns a list of protocols that matches to the specified protocol.'''
    # 返回与指定协议匹配的协议列表
    # protocol参数可选：ethernet, arp, icmp, icmpv6, ipv4, ipv6, lldp, mpls, packet,packet_base, packet_utils
    def get_protocol(self, protocol)
    # 返回与指定协议匹配的第一个找到的协议。
    
```

### ethernet

```python
frome ryu.lib import packet
'''
Ryu数据包库:  常见协议(如TCP/IP)的 解码器/编码器实现 。
'''

from ryu.lib.packet import ethernet

class ethernet(packet_base.PacketBase)
'''
以太网头编码器/解码器类。          具有以下属性：
 ============== ==================== =====================
    Attribute      Description          Example
    ============== ==================== =====================
    dst            destination address  'ff:ff:ff:ff:ff:ff'
    src            source address       '08:60:6e:7f:74:e7'
    ethertype      ether type           0x0800       
    ============== ==================== =====================
    MAC 地址 表示为字符串
'''
```

```python
from ryu.lib.packet import ether_types
from ryu.ofproto import ether

ETH_TYPE_IP = 0x0800      # IPv4
ETH_TYPE_ARP = 0x0806
ETH_TYPE_TEB = 0x6558
ETH_TYPE_8021Q = 0x8100
ETH_TYPE_IPV6 = 0x86dd
ETH_TYPE_SLOW = 0x8809
ETH_TYPE_MPLS = 0x8847
ETH_TYPE_8021AD = 0x88a8
ETH_TYPE_LLDP = 0x88cc     # LLDP
ETH_TYPE_8021AH = 0x88e7
ETH_TYPE_IEEE802_3 = 0x05dc
ETH_TYPE_CFM = 0x8902
ETH_TYPE_NSH = 0x894f  # RFC8300
```



#### msg

```python
from ryu.lib.packet import openflow


class openflow(packet_base.PacketBase)
'''属性：
msg: an instance of OpenFlow message (see :ref:`ofproto_ref`)  或者
     an instance of OFPUnparseableMsg if failed to parse packet as OpenFlow message.
'''

class OFPUnparseableMsg(stringify.StringifyMixin)
''' 无法解析的OpenFlow消息编码器类； 属性：
	datapath       A ryu.ofproto.ofproto_protocol.ProtocolDesc instance
                   for this message or None if OpenFlow protocol version
                   is unsupported version.
    version        OpenFlow protocol version
    msg_type       Type of OpenFlow message
    msg_len        Length of the message
    xid            Transaction id
    body           OpenFlow body data
'''
```



