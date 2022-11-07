#!/usr/bin/python3.8
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.node import CPULimitedHost
from mininet.link import TCLink, Link
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import os
import time

IPBASE 	= '132.1.0.0'
PREFIXBASE 	= '/18'
PREFIX1a	= '/24'
PREFIX1b	= '/24'
PREFIX2a	= '/24'
PREFIX2b	= '/24'
PREFIXNET1	= '/30'
PREFIXNET2	= '/30'
PREFIXNET3	= '/30'
PREFIXNET4	= '/30'

IPR1ETH0 	= '132.1.0.2'
IPR1SE2 	= '132.1.4.1'
IPR1SE3 	= '132.1.4.9'

IPR2ETH0 	= '132.1.2.2'
IPR2SE2 	= '132.1.4.2'
IPR2SE3 	= '132.1.4.13'

IPR3ETH1 	= '132.1.1.2'
IPR3SE2 	= '132.1.4.14'
IPR3SE3 	= '132.1.4.5'

IPR4ETH1 	= '132.1.3.2'
IPR4SE2 	= '132.1.4.10'
IPR4SE3 	= '132.1.4.6'

IPAETH0	= '132.1.0.1'
IPAETH1	= '132.1.1.1'

IPBETH0	= '132.1.2.1'
IPBETH1	= '132.1.3.1'

NETID1a 	= '132.1.0.0{}'.format(PREFIX1a)
NETID1b	= '132.1.1.0{}'.format(PREFIX1b)
NETID2a	= '132.1.2.0{}'.format(PREFIX2a)
NETID2b	= '132.1.3.0{}'.format(PREFIX2b)

NETIDNET1 = '132.1.4.0{}'.format(PREFIXNET1)
NETIDNET2 = '132.1.4.4{}'.format(PREFIXNET2)
NETIDNET3 = '132.1.4.8{}'.format(PREFIXNET3)
NETIDNET4 = '132.1.4.12{}'.format(PREFIXNET4)

class LinuxRouter(Node):
	def config(self,**params):
		super(LinuxRouter, self).config(**params)
		self.cmd('sysctl net.ipv4.ip_forward=1')
	def terminate(self):
		self.cmd('sysctl net.ipv4.ip_forward=0')
		super(LinuxRouter,self).terminate()

class NetworkTopo(Topo):
	def build(self,**opts):
		h1 = self.addHost('h1')
		h2 = self.addHost('h2')
	
		r1 = self.addNode('r1', cls=LinuxRouter)
		r2 = self.addNode('r2', cls=LinuxRouter)
		r3 = self.addNode('r3', cls=LinuxRouter)
		r4 = self.addNode('r4', cls=LinuxRouter)
		
		MAX_QUEUE_SIZE = 20
		
		self.addLink(h1,r1, cls=TCLink, max_queue_size=MAX_QUEUE_SIZE, intfName1='h1-eth0', intfName2='r1-eth0', bw=1)
		self.addLink(h1,r3, cls=TCLink, max_queue_size=MAX_QUEUE_SIZE, intfName1='h1-eth1', intfName2='r3-eth1', bw=1)
		self.addLink(h2,r2, cls=TCLink, max_queue_size=MAX_QUEUE_SIZE, intfName1='h2-eth0', intfName2='r2-eth0', bw=1)
		self.addLink(h2,r4, cls=TCLink, max_queue_size=MAX_QUEUE_SIZE, intfName1='h2-eth1', intfName2='r4-eth1', bw=1)

		self.addLink(r1,r2, cls=TCLink, max_queue_size=MAX_QUEUE_SIZE, intfName1='r1-se2', intfName2='r2-se2', bw=0.5)
		self.addLink(r1,r4, cls=TCLink, max_queue_size=MAX_QUEUE_SIZE, intfName1='r1-se3', intfName2='r4-se2', bw=1)
		self.addLink(r2,r3, cls=TCLink, max_queue_size=MAX_QUEUE_SIZE, intfName1='r2-se3', intfName2='r3-se2', bw=1)
		self.addLink(r3,r4, cls=TCLink, max_queue_size=MAX_QUEUE_SIZE, intfName1='r3-se3', intfName2='r4-se3', bw=0.5)
        
def runTopo():
	os.system('mn -c')
	os.system('clear')
	topo = NetworkTopo()
	net = Mininet(topo=topo, link=TCLink)
	
	h1,h2,r1,r2,r3,r4 = net.get('h1','h2','r1','r2','r3','r4')

	r1.setIP('{}{}'.format(IPR1ETH0, PREFIX1a),intf='r1-eth0')
	r1.setIP('{}{}'.format(IPR1SE2, PREFIXNET1),intf='r1-se2')
	r1.setIP('{}{}'.format(IPR1SE3, PREFIXNET3),intf='r1-se3')

	r2.setIP('{}{}'.format(IPR2ETH0, PREFIX2a),intf='r2-eth0')
	r2.setIP('{}{}'.format(IPR2SE2, PREFIXNET1),intf='r2-se2')
	r2.setIP('{}{}'.format(IPR2SE3, PREFIXNET4),intf='r2-se3')

	r3.setIP('{}{}'.format(IPR3ETH1, PREFIX1b),intf='r3-eth1')
	r3.setIP('{}{}'.format(IPR3SE2, PREFIXNET4),intf='r3-se2')
	r3.setIP('{}{}'.format(IPR3SE3, PREFIXNET2),intf='r3-se3')

	r4.setIP('{}{}'.format(IPR4ETH1, PREFIX2b),intf='r4-eth1')
	r4.setIP('{}{}'.format(IPR4SE2, PREFIXNET3),intf='r4-se2')
	r4.setIP('{}{}'.format(IPR4SE3, PREFIXNET2),intf='r4-se3')
	
	# Menambahkan ip ke host
	h1.setIP('{}{}'.format(IPAETH0, PREFIX1a),intf='h1-eth0')
	h1.setIP('{}{}'.format(IPAETH1, PREFIX1b),intf='h1-eth1')
	
	h2.setIP('{}{}'.format(IPBETH0, PREFIX2a),intf='h2-eth0')
	h2.setIP('{}{}'.format(IPBETH1, PREFIX2b),intf='h2-eth1')




	r1.cmd('route add -net {} gw {}'.format(NETID2a, IPR2SE2))
	r1.cmd('route add -net {} gw {}'.format(NETIDNET4, IPR2SE2))
	r1.cmd('route add -net {} gw {}'.format(NETID2b, IPR4SE2))
	r1.cmd('route add -net {} gw {}'.format(NETIDNET2, IPR4SE2))
	r1.cmd('route add -net {} gw {}'.format(NETID1b, IPR4SE2))

	r2.cmd('route add -net {} gw {}'.format(NETID1a, IPR1SE2))
	r2.cmd('route add -net {} gw {}'.format(NETIDNET3, IPR1SE2))
	r2.cmd('route add -net {} gw {}'.format(NETID1b, IPR3SE2))
	r2.cmd('route add -net {} gw {}'.format(NETIDNET2, IPR3SE2))
	r2.cmd('route add -net {} gw {}'.format(NETID2b, IPR3SE2))
	

	r3.cmd('route add -net {} gw {}'.format(NETIDNET1, IPR2SE3))
	r3.cmd('route add -net {} gw {}'.format(NETID2a, IPR2SE3))
	r3.cmd('route add -net {} gw {}'.format(NETIDNET3, IPR4SE3))
	r3.cmd('route add -net {} gw {}'.format(NETID2b, IPR4SE3))
	r3.cmd('route add -net {} gw {}'.format(NETID1a, IPR4SE3))
	
	r4.cmd('route add -net {} gw {}'.format(NETID1a, IPR1SE3))
	r4.cmd('route add -net {} gw {}'.format(NETIDNET1, IPR1SE3))
	r4.cmd('route add -net {} gw {}'.format(NETID1b, IPR3SE3))
	r4.cmd('route add -net {} gw {}'.format(NETIDNET4, IPR3SE3))
	r4.cmd('route add -net {} gw {}'.format(NETID2a, IPR3SE3))

	h1.cmd('ip rule add from {} table 1'.format(IPAETH0))
	h1.cmd('ip rule add from {} table 2'.format(IPAETH1))
	h1.cmd('ip route add {} dev h1-eth0 scope link table 1'.format(NETID1a))
	h1.cmd('ip route add default via {} dev h1-eth0 table 1'.format(IPR1ETH0))
	h1.cmd('ip route add {} dev h1-eth1 scope link table 2'.format(NETID1b))
	h1.cmd('ip route add default via {} dev h1-eth1 table 2'.format(IPR3ETH1))
	h1.cmd('ip route add default scope global nexthop via {} dev h1-eth0'.format(IPR1ETH0))
	h1.cmd('ip route add default scope global nexthop via {} dev h1-eth1'.format(IPR3ETH1))
	
	h2.cmd('ip rule add from {} table 1'.format(IPBETH0))
	h2.cmd('ip rule add from {} table 2'.format(IPBETH1))
	h2.cmd('ip route add {} dev h2-eth0 scope link table 1'.format(NETID2a))
	h2.cmd('ip route add default via {} dev h2-eth0 table 1'.format(IPR2ETH0))
	h2.cmd('ip route add {} dev h2-eth1 scope link table 2'.format(NETID2b))
	h2.cmd('ip route add default via {} dev h2-eth1 table 2'.format(IPR4ETH1))
	h2.cmd('ip route add default scope global nexthop via {} dev h2-eth0'.format(IPR2ETH0))
	h2.cmd('ip route add default scope global nexthop via {} dev h2-eth1'.format(IPR4ETH1))
	
	
	net.start()
	
	#info('\n',net.ping(),'\n')

	# traceroute h1 to h2 
	h1.cmdPrint('traceroute {}'.format(IPBETH0))
	h1.cmdPrint('traceroute {}'.format(IPBETH1))
	h2.cmdPrint('traceroute {}'.format(IPAETH0))
	h2.cmdPrint('traceroute {}'.format(IPAETH1))


	#iperf testing
	h1.cmd("xterm -e 'tcpdump -w tubes_1301204014.pcap -c 200 -i any tcp'&")
	h1.cmdPrint("iperf -s -t 100 -B {}&".format(IPAETH0))
	time.sleep(1)
	h2.cmdPrint("iperf -c {} -i 1".format(IPAETH0))
	#h2 Server, h1 Client
	h2.cmd("xterm -e 'tcpdump -w tubes_1301204014.pcap -c 200 -i any tcp'&")
	h2.cmdPrint("iperf -s -t 100 -B {}&".format(IPBETH0))
	time.sleep(1)
	h1.cmdPrint("iperf -c {} -i 1".format(IPBETH0))

	CLI(net)

	net.stop()
	
	
topos = { 'runTopo': (lambda:runTopo() ) }
