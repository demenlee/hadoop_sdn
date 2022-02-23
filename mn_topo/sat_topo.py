#!/usr/bin/python
"""
This is a simple satellite topology (4x4) to showcase Containernet.
"""
from re import S
from mininet.net import Containernet, Mininet
from mininet.node import Controller, RemoteController, Node
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.util import quietRun
import os
setLogLevel('info')

net = Containernet(controller=Controller)  #传统网络
info('*** Adding controller\n')
net.addController('c0')

info('*** Adding switches\n')      
sat_name = locals()
str_sws = []
for i in range(16):
    str_sws.append('s'+str(i+1))
    sat_name['sat' + str(i)] = net.addSwitch('s'+str(i+1))

info('*** Adding docker containers\n')
'''
master = net.addDocker('master', ip='10.0.0.200', ports=['50070', '8088', '9000'] , 
                       dimage="demenlee/hadoop:v3.2.master", mac='00:00:00:00:00:20')
h1 = net.addDocker('slave1', ip='10.0.0.201', dimage="demenlee/hadoop:v3.2", mac='00:00:00:00:00:21')
'''
str_hosts = []
str_ips = []
last_ip = 200
mac_adrs = []
last_mac = 0
host_name = locals()
for i in range(16):
    str_hosts.append('h' + str(i+1))
    last_ip += 1
    last_str = str(last_ip)
    str_ips.append('10.0.0.' + last_str)
    last_mac += 1
    last_str = str(last_mac)
    mac_adrs.append('00:00:00:00:00:' + last_str)
    host_name['h' + str(i)] = net.addDocker(str_hosts[i], ip=str_ips[i], dimage="demenlee/hadoop:v3.2.master", mac=mac_adrs[i])


    
info('*** Creating links\n')
#net.addLink(master, s1, params1={"ip": "10.0.0.1/8"})
'''
net.addLink(sat1_1, sat1_2, cls=TCLink, delay='20ms', bw=100)
net.addLink(sat1_1, sat2_1, cls=TCLink, delay='5ms', bw=150)
'''
for i in range(0,3):
    net.addLink(sat_name['sat' + str(i)], sat_name['sat' + str(i+1)], cls=TCLink, delay='10ms', bw=100)
for i in range(4,7):
    net.addLink(sat_name['sat' + str(i)], sat_name['sat' + str(i+1)], cls=TCLink, delay='10ms', bw=100)
for i in range(8,11):
    net.addLink(sat_name['sat' + str(i)], sat_name['sat' + str(i+1)], cls=TCLink, delay='10ms', bw=100)
for i in range(12,15):
    net.addLink(sat_name['sat' + str(i)], sat_name['sat' + str(i+1)], cls=TCLink, delay='10ms', bw=100)
for i in range(0,12,4):
    net.addLink(sat_name['sat' + str(i)], sat_name['sat' + str(i+4)], cls=TCLink, delay='10ms', bw=100)
for i in range(1,13,4):
    net.addLink(sat_name['sat' + str(i)], sat_name['sat' + str(i+4)], cls=TCLink, delay='10ms', bw=100)
for i in range(2,14,4):
    net.addLink(sat_name['sat' + str(i)], sat_name['sat' + str(i+4)], cls=TCLink, delay='10ms', bw=100)
for i in range(3,15,4):
    net.addLink(sat_name['sat' + str(i)], sat_name['sat' + str(i+4)], cls=TCLink, delay='10ms', bw=100)
#net.addLink(s12, s13, cls=TCLink, delay='10ms', bw=100)
for i in range(16):
    net.addLink(sat_name['sat' + str(i)], host_name['h' + str(i)])

info('*** Starting network\n')
net.start()

# 网络拓扑存在环路，需要使用STP来避免泛洪； 否则网络无法ping通
for i in range(16):
    os.system('ovs-vsctl set Bridge ' + str_sws[i] + ' stp_enable=true')
    # os.system('ovs-vsctl set Bridge ' + str_sws[i] + ' rstp_enable=true')

info('*** Testing connectivity\n')
net.ping([h1, h2])
net.ping([h2, h3])
info('*** Running CLI\n')
CLI(net)
info('*** Stopping network')
net.stop()