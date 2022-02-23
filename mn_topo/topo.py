#!/usr/bin/python
"""
This is a simple tree topo (without loop) to showcase Containernet.
               s1
              %  %
             s2   s3
            %  %  % %
           h1 h2 h3 h4
"""
from mininet.net import Containernet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
setLogLevel('info')

net = Containernet(controller=RemoteController)
info('*** Adding controller\n')
net.addController('c0')
info('*** Adding docker containers\n')
h1 = net.addDocker('h1', ip='10.0.0.251', dimage="demenlee/hadoop:v3.2.master", mac='00:00:00:00:00:21')
h2 = net.addDocker('h2', ip='10.0.0.252', dimage="demenlee/hadoop:v3.2.master", mac='00:00:00:00:00:22')
h3 = net.addDocker('h3', ip='10.0.0.253', dimage="demenlee/hadoop:v3.2.master", mac='00:00:00:00:00:23')
h4 = net.addDocker('h4', ip='10.0.0.254', dimage="demenlee/hadoop:v3.2.master", mac='00:00:00:00:00:24')
# h5 = net.addDocker('h5', ip='10.0.0.255', dimage="demenlee/hadoop:v3.2.master", mac='00:00:00:00:00:25')
info('*** Adding switches\n')
s1 = net.addSwitch('s1')
s2 = net.addSwitch('s2')
s3 = net.addSwitch('s3')
info('*** Creating links\n')
#net.addLink(master, s1, params1={"ip": "10.0.0.1/8"})
net.addLink(s1, s2, cls=TCLink, delay='10ms', bw=100)
net.addLink(s1, s3, cls=TCLink, delay='10ms', bw=100)
#net.addLink(master, s2, delay='10ms', bw=50)
net.addLink(h1, s2, delay='10ms', bw=50)
net.addLink(h2, s2, delay='10ms', bw=50)
net.addLink(h3, s3, delay='10ms', bw=50)
net.addLink(h4, s3, delay='10ms', bw=50)

info('*** Starting network\n')
net.start()

info('*** Testing connectivity\n')
net.ping([h1, h2])
net.ping([h1, h3])
info('*** Running CLI\n')
CLI(net)
info('*** Stopping network')
net.stop()
