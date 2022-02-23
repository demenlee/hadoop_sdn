#!/usr/bin/python
"""
This is a simple tree topo (without loop) to showcase Containernet.
This topo can realize dymanic link.
"""
from mininet.net import Containernet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
import time
setLogLevel('info')

net = Containernet(controller=Controller)   # 默认交换机自身controller， 控制层未分离交换机（传统交换机）
info('*** Adding controller\n')
net.addController('c0')
info('*** Adding docker containers\n')
master = net.addDocker('master', ip='10.0.0.251', ports=['50070', '8088', '9000'] , dimage="demenlee/hadoop:v3.2.master", mac='00:00:00:00:00:21')
slave1 = net.addDocker('slave1', ip='10.0.0.252', dimage="demenlee/hadoop:v3.2", mac='00:00:00:00:00:22')
slave2 = net.addDocker('slave2', ip='10.0.0.253', dimage="demenlee/hadoop:v3.2", mac='00:00:00:00:00:23')
slave3 = net.addDocker('slave3', ip='10.0.0.254', dimage="demenlee/hadoop:v3.2", mac='00:00:00:00:00:24')
slave4 = net.addDocker('slave4', ip='10.0.0.255', dimage="demenlee/hadoop:v3.2", mac='00:00:00:00:00:25')
info('*** Adding switches\n')
s1 = net.addSwitch('s1')
s2 = net.addSwitch('s2')
s3 = net.addSwitch('s3')
info('*** Creating links\n')
#net.addLink(master, s1, params1={"ip": "10.0.0.1/8"})
link1 = net.addLink(s1, s2, cls=TCLink, delay='10ms', bw=100)
link2 = net.addLink(s1, s3, cls=TCLink, delay='10ms', bw=100)
net.addLink(master, s2)
net.addLink(slave1, s2)
net.addLink(slave2, s2)
net.addLink(slave3, s3)
net.addLink(slave4, s3)

info('*** Starting network\n')
net.start()
# info('*** Running CLI\n')
# CLI(net)   # python is interpretive language; this command will stack at 'containernet>'; 
# then 'while(True)' (cannot continue to enter CLI perform), until stop this program.

while(True):   # dymanic link bw and delay
    time.sleep(10)
    link1.intf1.config(bw=10, delay ='100ms')
    link1.intf2.config(bw=10, delay ='100ms')
    link2.intf1.config(bw=10, delay ='100ms')
    link2.intf2.config(bw=10, delay ='100ms')
    time.sleep(10)
    link1.intf1.config(bw=100, delay ='10ms')
    link1.intf2.config(bw=100, delay ='10ms')
    link2.intf1.config(bw=100, delay ='10ms')
    link2.intf2.config(bw=100, delay ='10ms')

'''
info('*** Testing connectivity\n')
net.ping([master, slave1])
net.ping([master, slave2])
info('*** Running CLI\n')
CLI(net)
info('*** Stopping network')
net.stop()
'''