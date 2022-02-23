# Containernet + Ryu

## Containernet

### 介绍

Containernet 是著名的 Mininet 网络模拟器的分支，允许在模拟网络拓扑中使用 Docker 容器作为主机。这为构建网络/云模拟器和试验台提供了有趣的功能。

 One example:     https://github.com/sonata-nfv/son-emu  NFV multi-PoP infrastructure emulator :

它是由Sonata-NFV项目创建的，现在是OpenSource mano(OSM)项目的一部分.

Sonata-NFV: https://sonata-nfv.eu/

OSM:   https://osm.etsi.org/

此外，Containernet被研究界积极使用，主要集中在云计算、雾计算、网络功能虚拟化(NFV)和多路访问边缘计算(MEC)领域的实验。

### install and setup

使用Ubuntu20（ubuntu16 目前尝试下载失败）

```shell
## 提前安装好docker
curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun
curl -sSL https://get.daocloud.io/docker | sh
## 安装环境
sudo apt-get install ansible git aptitude
## 下载原代码
git clone https://github.com/containernet/containernet.git
## 修改下载脚本
cd /opt/contianernet/util
vim install.sh
KERNEL_LOC=http://www.openflow.org/downloads/mininet   #修改为：
KERNEL_LOC=http://opennetworking.org/mininet/
# 如果 下载时无法连上github 需要修改git clone curl
git clone https://github.com/mininet/openflow  #修改为：
git clone git://github.com/mininet/openflow 
# 如果 containernet 同一根目录下存在 openflow 文件夹，需要删掉

## 修改完后，开始安装下载
cd containernet/ansible
sudo ansible-playbook -i "localhost," -c local install.yml
cd ..
Wait (and have a coffee) ...
```

### 自定义拓扑

```shell
# 官方给了一些例子
cd ~/containernet/examples
# 例如 containernet_example.py
python3 containernet_example.py

# 我写的一些拓扑， 参考mn_topo 文件里
topo.py  # 简单的树状拓扑，可用来测试 ryu控制器的一些应用
dymanic_topo.py # 可实现链路带宽和延迟的动态变化
sat_topo.py  # 4x4 带环形的卫星模拟拓扑
sat_topo1.py 

## 我创建的Hadoop docker 镜像， 使用时可先行拉取下载该镜像
dimage="demenlee/hadoop:v3.2.master"  
## 该镜像已经下载 Hadoop， Hibench, java等实验套件(在/opt目录下)，并且已配置好基本的环境； 和一些常用的网络测试工具iperf


############# 实验实例：
python3 topo.py  # 打开拓扑
ryu-manager /opt/flowmanager/flowmanager.py yourapp.py  # 打开ryu控制器
## 进入docker 容器 配置Hadoop集群
docker exec -it mn.h1 bash
source /etc/profile   # 测试环境：Hadoop；java；ping
vim /etc/hosts  # DNS： ip  host  
service ssh start
配置密钥(重点)
chmod -R 777 /opt/hadoop-3.1.3
cd /opt/hadoop-3.1.3/etc/hadoop
vim workers
检查其他配置: 如 vim yarn-site.xml
hdfs namenode -format
start-all.sh  #启动集群
```

### CLI 平台

`containernet>`

```shell
Documented commands (type help <topic>):
========================================
EOF    gterm  iperfudp  nodes        pingpair      py      switch
dpctl  help   link      noecho       pingpairfull  quit    time  
dump   intfs  links     pingall      ports         sh      x     
exit   iperf  net       pingallfull  px            source  xterm 

You may also send a command to a node using:
  <node> command {args}
For example:
  mininet> h1 ifconfig

The interpreter automatically substitutes IP addresses
for node names when a node is the first arg, so commands
like
  mininet> h2 ping h3
should work.

Some character-oriented interactive commands require
noecho:
  mininet> noecho h2 vi foo.py
However, starting up an xterm/gterm is generally better:
  mininet> xterm h2

EOF #exit
nodes  #list all nodes
py    # py nodes.cmd('')
switch   #up or down a switch
dpctl  #ovs-ofctl command [arg] [arg]
link   # up or down a link
noecho  #Run an interactive command with echoing turned off.
dump   #print nodes info
intfs  # print interfaces
links  # list all links
ports  # list all ports
sh     # 在当前文件夹位置 run an external shell command
x      #Create an X11 tunnel to the given node, optionally starting a client.
iperf/iperfudp
net
px     #Execute a Python statement; e.g. px print node.cmd('')
source  #Read commands from an input file

```

```python
h1 = net.getNodeByName( 'h1' )
s3 = net.getNodeByName( 's3' )
links = h1.connectionsTo(s3)

srcLink = links[0][1]
dstLink = links[0][1]

srcLink.config(**{ 'bw' : 1, 'delay' : '1ms' })
dstLink.config(**{ 'bw' : 1, 'delay' : '1ms' })

topo.setlinkInfo('h1', 's3', { 'bw' : 4, 'delay' : '1ms' })
 

intf = h2.intf()
info( "Setting BW Limit for Interface " + str(intf) + " to " + str(target_bw) + "\n" )
intf.config(bw = target_bw, smooth_change = smooth_change)
```

### 源代码解读

#### mininet.node.Node

```python
from mininet.node import Node
'''
Host, CPULimitedHost, Docker
Switch, UserSwitch, OVSSwitch, OVSBridge(支持STP)， IVSSwitch
Controller, OVSController, NOXController, Ryu, RemoteController
'''
class Node(Object):
    def __init__(self, **params):
        self.name = params.get('name', name)
        # dict.get(key, default=None): 
        # 返回指定键的值，如果键不在字典中返回默认值 None 或者指定的默认值。
        
	def cmd( self, *args, **kwargs ):
        """Send a command, wait for output, and return it.
           cmd: string"""
        verbose = kwargs.get( 'verbose', False )
        log = info if verbose else debug
        log( '*** %s : %s\n' % ( self.name, args ) )
        if self.shell:
            self.shell.poll()
            if self.shell.returncode is not None:
                print("shell died on ", self.name)
                self.shell = None
                self.startShell()
            self.sendCmd( *args, **kwargs )
            return self.waitOutput( verbose )
        else:
            warn( '(%s exited - ignoring cmd%s)\n' % ( self, args ) )
	def cmdPrint( self, *args):
        """Call cmd and printing its output
           cmd: string"""
        return self.cmd( *args, **{ 'verbose': True } )
    
class Host(Node):
    pass #HOST is just a smiple Node
class Docker(Host):
    def __init__(self, name, dimage=None, dcmd=None, build_params={},
                 **kwargs):
    	self.dnameprefix = "mn"
   		# sources limit
        defaults = {}
        defaults.update(kwargs)
        # create new docker container
        self.dc = self.dcli.create_container(
            name="%s.%s" % (self.dnameprefix, name),
            # e.g:  mn.master, mn.slave1 等
            image=self.dimage,
            command=self.dcmd,
            entrypoint=list(),  # overwrite (will be executed manually at the end)
            stdin_open=True,  # keep container open
            tty=True,  # allocate pseudo tty
            environment=self.environment,
            # network_disabled=True, 
            # docker stats breaks if we disable the default network
            host_config=hc,
            ports=defaults['ports'],
            labels=['com.containernet'],
            volumes=[self._get_volume_mount_name(v) for v in self.volumes if self._get_volume_mount_name(v) is not None],
            hostname=name
        )
    def build(self, **kwargs):
    def start(self):
    def cmd(self, *args, **kwargs ):
        """Send a command, wait for output, and return it.
           cmd: string"""
        verbose = kwargs.get( 'verbose', False )
        log = info if verbose else debug
        log( '*** %s : %s\n' % ( self.name, args ) )
        self.sendCmd( *args, **kwargs )
        return self.waitOutput( verbose )
class CPULimitedHost(Host):
class Switch( Node ):   # 继承Node类
    def __init__(self, **params):
        # **params --> params 作为一个字典，拥有字典的方法
    '''
    每个switch具有唯一的dpid，而dpid的默认设定受到switch命名(name)影响，
    switch的name设定不当可能导致dpid重复，从而导致路由受到影响。
    '''
    def defaultDpid( self, dpid=None ):
        "Return correctly formatted dpid from dpid or switch name (s1 -> 1)"
        if dpid:
            # Remove any colons and make sure it's a good hex number
            dpid = dpid.replace( ':', '' )
            assert len( dpid ) <= self.dpidLen and int( dpid, 16 ) >= 0
        else:
            # Use hex of the first number in the switch name
            nums = re.findall( r'\d+', self.name )
            # 使用正则表达式获取name中数字（\d+ 表获取数字一次或多次），然后存到nums列表里
            if nums:
                dpid = hex( int( nums[ 0 ] ) )[ 2: ]   # hex : 0xn (012...)
                # 从列表nums中获取第一个数，转换成16进制形式(0x...)，获取0x后面的数字（去掉Ox）
                # 即 dpid显示的数字是16进制的
            else:
                self.terminate()  # Python 3.6 crash workaround
                raise Exception( 'Unable to derive default datapath ID - '
                                 'please either specify a dpid or use a '
                                 'canonical switch name such as s23.' )
        return '0' * ( self.dpidLen - len( dpid ) ) + dpid

## 全局变量和方法：
DefaultControllers = ( Controller, OVSController )
def findController( controllers=DefaultControllers ):
    "Return first available controller from list, if any"
    for controller in controllers:
        if controller.isAvailable():
            return controller
def DefaultController( name, controllers=DefaultControllers, **kwargs ):
    "Find a controller that is available and instantiate it"
    controller = findController( controllers )
    if not controller:
        raise Exception( 'Could not find a default OpenFlow controller' )
    return controller( name, **kwargs )
def NullController( *_args, **_kwargs ):
    "Nonexistent controller - simply returns None"
    return None
def parse_build_output(output):
        output_str = ""
        for line in output:
            for item in line.values():
                output_str += str(item)
        return output_str
```



## Ryu

### install and setup

```shell
## 方式一： quick start 
python -m pip install ryu

## 方式二： 源代码安装（推荐）
git clone git://github.com/faucetsdn/ryu.git
cd ryu
#安装ryu
pip install .

## 编辑你的ryu应用
vim yourapp.py
#启动ryu
ryu-manager app1.py app2.py # or： ryu run app.py
```

```shell
# optional requirements
pip install -r lxml ncclient paramiko SQLAlchemy
```

#### Flowmanager

介绍： 是Ryu 控制器应用程序； 使用此应用，可以实时观测交换机的流条目等信息。

```shell
## 下载源代码
git clone https://github.com/martimy/flowmanager.git

# 启动方式一：
cd /opt/flowmanager
ryu-manager flowmanager.py ryu.app.simple_switch_13

# 启动方式二：
cd /opt/ryu/ryu/app
ryu-manager /opt/flowmanager/flowmanager.py simple_switch_13.py
ryu-manager /opt/flowmanager/flowmanager.py simple_monitor_13.py
```

使用浏览器访问站点： http://localhost:8080/home/index.html

#### Topology Viewer

```shell
PYTHONPATH=. ./bin/ryu run --observe-links ryu/app/gui_topology/gui_topology.py
# or
cd /opt/ryu/ryu/app/gui_topology
ryu-manager gui_topology.py
```

使用浏览器访问站点： http://localhost:8080

### ryu-manager 命令

```shell
--boserve-links    # get the details of network topology  链路发现， 有时候会使控制器
--ofp-listen-host   # monitor the hosts/clients
--wsapi-host IP / --wsapi-port PORT    #set the IP:PORT for web server

ryu-manager ryu.app.simple_switch_13 ryu.app.ofctl_rest
curl -X GET http://localhost:8080/stats/switches  # get all switches
curl -X GET http://localhost:8080/stats/desc/1
curl -X GET http://localhost:8080/stats/flows/1
```

### ryu app

```shell
#### 官方给了一些例子  
cd ~\ryu\ryu\app    
# 例如 simple_switch_13.py   通过flood自学习下发 二层(mac地址)流条目，实现转发
#                            (13表示openflow1.3协议)
#     simple_switch_stp_13.py  针对环形拓扑的 自学习下发 二层(mac地址)流条目
## 可参考官方所给例子来编写自己的ryu app
ryu-manager simple_switch_13.py

#### 我写的一些例子，参考ryu_app 文件
switch_test.py   # 自定义 路由路径 下发二层流条目（定向路由）
switch_test1.py
simple_switchL3_13.py  # 通过ARP flood自学习下发 三层(ip地址)流条目，实现转发
```

### 源代码解读

参考另一个文件 Ryu source code.md



另外可参考的学习ryu地址： https://github.com/knetsolutions/learn-sdn-with-ryu.git



## Hibanch

### install and setup

- Python 2.x(>=2.6) is required.
- `bc` is required to generate the HiBench report.
- Supported Hadoop version: Apache Hadoop 2.x, CDH5.x, HDP
- Build HiBench according to [build HiBench](https://github.com/Intel-bigdata/HiBench/blob/master/docs/build-hibench.md).
- Start HDFS, Yarn in the cluster.

```shell
# current version:7.1
git clone https://github.com/Intel-bigdata/HiBench.git

# 安装bc(Basic Calculator)
sudo apt install bc

# build HiBench (重要)
# 1 安装mvn,修改配置
cd HiBench
# building all
mvn -Dspark=2.4 -Dscala=2.11 clean package
# 指定Hadoop模块
mvn -Phadoopbench -Dspark=2.4 -Dscala=2.11 clean package
# 指定Hadoop和spark 模块
mvn -Phadoopbench -Psparkbench -Dspark=2.4 -Dscala=2.11 clean package
# 指定Hadoop version
mvn -Phadoopbench -Dhadoop=3.1 -Dhive=0.14 clean package

#getting start: running hadoopBench
# bc is required to generate the HiBench report.
cp conf/hadoop.conf.template conf/hadoop.conf

# run a workload
bin/workloads/micro/wordcount/prepare/prepare.sh
bin/workloads/micro/wordcount/hadoop/run.sh
# view report
<workload>/hadoop/bench.log

#input data size
conf/hibench.conf
vim hibench.scale.profile
```

### 6种类型负载

1 micro 

| 负载                           | 数据生成或测试功能 |
| ------------------------------ | ------------------ |
| sort                           | RandomTextWriter   |
| wordcount                      | Random TextWriter  |
| terasort                       | teragen            |
| Repartition(mirco/repartition) | 测试shuffle性能    |
| sleep                          | 测试框架调度器     |
| enhanced DFSIO(dfsioe)         | 测试HDFS吞吐量     |

 2 机器学习

```
1 Bayesian Classification (Bayes)
2 K-means clustering (Kmeans)
3 Gaussian Mixture Model (GMM)
4 Logistic Regression (LR)
5 Alternating Least Squares (ALS)
6 Gradient Boosted Trees (GBT)
7 XGBoost (XGBoost)
8 Linear Regression (Linear)
9 Latent Dirichlet Allocation (LDA)
...
```

3 SQL

4 Websearch Benchmarks

5 Graph Benchmarks

6 Streaming Benchmarks

### 配置

```shell
cp conf/hadoop.conf.template conf/hadoop.conf
```

| Property                     | Meaning                      |
| ---------------------------- | ---------------------------- |
| hibench.hadoop.home          | /opt/hadoop-3.1.3            |
| hibench.hadoop.executable    | /opt/hadoop-3.1.3/bin/hadoop |
| hibench.hadoop.configure.dir | /opt/hadoop-3.1.3/etc/hadoop |
| hibench.hdfs.master          | hdfs://master:9000           |
| hibench.hadoop.release       | apache                       |

```shell
# 生成数据 randomtextwriter
bin/workloads/micro/wordcount/prepare/prepare.sh
# 执行作业 wordcount
bin/workloads/micro/wordcount/hadoop/run.sh
```

### 报告

汇总工作负载报告，包括工作负载名称、执行持续时间、数据大小、每个群集的吞吐量、每个节点的吞吐量。

```shell
<workload>/hadoop/bench.log   客户端原始数据
<workload>/hadoop/monitor.html    系统利用监控结果
<workload>/hadoop/conf/<workload>.conf  为此工作负载生成了环境变量配置。
```

