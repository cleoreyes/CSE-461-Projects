# Part 2 of UWCSE's Project 3
#
# based on Lab 4 from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

# Part 2 of UWCSE's Project 3
#
# based on Lab 4 from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
from pox.lib.util import dpidToStr
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.icmp import icmp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp

log = core.getLogger()

class Firewall(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        
        # install and initialize the firewall
        self.install_firewall_rules()
        
    def install_firewall_rules(self):
        # allow ARP traffic flow
        arp_match = of.ofp_match()
        arp_match.dl_type = ethernet.ARP_TYPE
        arp_rule = of.ofp_flow_mod()
        arp_rule.match = arp_match
        arp_rule.priority = 100
        arp_rule.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(arp_rule)
        
        # allow ICMP between h1 and h4 (subnet 10.0.1.0/24)
        h1_h4_icmp = of.ofp_flow_mod()
        h1_h4_icmp.priority = 100
        h1_h4_icmp.match.dl_type = ethernet.IP_TYPE
        h1_h4_icmp.match.nw_proto = ipv4.ICMP_PROTOCOL
        h1_h4_icmp.match.nw_src = IPAddr("10.0.1.2")
        h1_h4_icmp.match.nw_dst = IPAddr("10.0.1.3")
        h1_h4_icmp.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(h1_h4_icmp)
        
        # allow ICMP from h4 to h1
        h4_h1_icmp = of.ofp_flow_mod()
        h4_h1_icmp.priority = 100
        h4_h1_icmp.match.dl_type = ethernet.IP_TYPE
        h4_h1_icmp.match.nw_proto = ipv4.ICMP_PROTOCOL
        h4_h1_icmp.match.nw_src = IPAddr("10.0.1.3")
        h4_h1_icmp.match.nw_dst = IPAddr("10.0.1.2")
        h4_h1_icmp.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(h4_h1_icmp)
        
        # allow ICMP between h2 and h3 (subnet 10.0.0.0/24)
        h2_h3_icmp = of.ofp_flow_mod()
        h2_h3_icmp.priority = 100
        h2_h3_icmp.match.dl_type = ethernet.IP_TYPE
        h2_h3_icmp.match.nw_proto = ipv4.ICMP_PROTOCOL
        h2_h3_icmp.match.nw_src = IPAddr("10.0.0.2")
        h2_h3_icmp.match.nw_dst = IPAddr("10.0.0.3")
        h2_h3_icmp.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(h2_h3_icmp)
        
        # allow ICMP from h3 to h2
        h3_h2_icmp = of.ofp_flow_mod()
        h3_h2_icmp.priority = 100
        h3_h2_icmp.match.dl_type = ethernet.IP_TYPE
        h3_h2_icmp.match.nw_proto = ipv4.ICMP_PROTOCOL
        h3_h2_icmp.match.nw_src = IPAddr("10.0.0.3")
        h3_h2_icmp.match.nw_dst = IPAddr("10.0.0.2")
        h3_h2_icmp.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(h3_h2_icmp)
        
        # drop all other IPv4 traffic
        ipv4_match = of.ofp_match()
        ipv4_match.dl_type = ethernet.IP_TYPE
        ipv4_rule = of.ofp_flow_mod()
        ipv4_rule.match = ipv4_match
        ipv4_rule.priority = 1  # lower priority than specific rules
        # No actions means drop
        self.connection.send(ipv4_rule)
        
    def _handle_PacketIn(self, event):
        # called when a packet is sent to the controller
        # don't need to do anything because all rules have been installed installed
        pass

def launch():
    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Firewall(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)