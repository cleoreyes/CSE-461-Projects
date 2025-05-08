# Part 3 of UWCSE's Mininet-SDN project
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr

log = core.getLogger()

# Convenience mappings of hostnames to ips
IPS = {
    "h10": "10.0.1.10",
    "h20": "10.0.2.20",
    "h30": "10.0.3.30",
    "serv1": "10.0.4.10",
    "hnotrust": "172.16.10.100",
}

# Convenience mappings of hostnames to subnets
SUBNETS = {
    "h10": "10.0.1.0/24",
    "h20": "10.0.2.0/24",
    "h30": "10.0.3.0/24",
    "serv1": "10.0.4.0/24",
    "hnotrust": "172.16.10.0/24",
}


class Part3Controller(object):
    """
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        print(connection.dpid)
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)
        # use the dpid to figure out what switch is being created
        if connection.dpid == 1:
            self.s1_setup()
        elif connection.dpid == 2:
            self.s2_setup()
        elif connection.dpid == 3:
            self.s3_setup()
        elif connection.dpid == 21:
            self.cores21_setup()
        elif connection.dpid == 31:
            self.dcs31_setup()
        else:
            print("UNKNOWN SWITCH")
            exit(1)

    def s1_setup(self):
        """
        Setup rules for switch 1 (connected to h10)
        - Allow all IPv4 and ARP traffic to be flooded
        """
        # Allow all IPv4 traffic (flooding)
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x800  # IPv4
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)
        
        # Allow ARP traffic (necessary for hosts to find each other)
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x806  # ARP
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    def s2_setup(self):
        """
        Setup rules for switch 2 (connected to h20)
        - Allow all IPv4 and ARP traffic to be flooded
        """
        # Allow all IPv4 traffic (flooding)
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x800  # IPv4
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)
        
        # Allow ARP traffic
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x806  # ARP
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    def s3_setup(self):
        """
        Setup rules for switch 3 (connected to h30)
        - Allow all IPv4 and ARP traffic to be flooded
        """
        # Allow all IPv4 traffic (flooding)
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x800  # IPv4
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)
        
        # Allow ARP traffic
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x806  # ARP
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    def cores21_setup(self):
        """
        Setup rules for core switch (central router)
        - Route traffic between different subnets with specific ports
        - Implement firewall policies to protect trusted hosts
        """
        # Create a routing table for the core switch
        # Map each subnet to the appropriate output port
        routing_table = {
            "h10": 1,    # Port 1 leads to switch s1 (h10)
            "h20": 2,    # Port 2 leads to switch s2 (h20)
            "h30": 3,    # Port 3 leads to switch s3 (h30)
            "serv1": 4,  # Port 4 leads to datacenter switch (serv1)
            "hnotrust": 5 # Port 5 leads to untrusted host
        }
        
        # Set up routing rules for each subnet
        for src_host, src_subnet in SUBNETS.items():
            for dst_host, dst_subnet in SUBNETS.items():
                if src_host != dst_host:
                    # 1. Block ICMP traffic from hnotrust to any trusted host
                    if src_host == "hnotrust" and dst_host in ["h10", "h20", "h30", "serv1"]:
                        msg = of.ofp_flow_mod()
                        msg.priority = 100  # Higher priority to override general rules
                        msg.match.dl_type = 0x800  # IPv4
                        msg.match.nw_proto = 1  # ICMP
                        msg.match.nw_src = src_subnet
                        msg.match.nw_dst = dst_subnet
                        # No actions means drop
                        self.connection.send(msg)
                    
                    # 2. Block all IP traffic from hnotrust to serv1
                    if src_host == "hnotrust" and dst_host == "serv1":
                        msg = of.ofp_flow_mod()
                        msg.priority = 99  # Lower than ICMP but higher than general rules
                        msg.match.dl_type = 0x800  # IPv4
                        msg.match.nw_src = src_subnet
                        msg.match.nw_dst = dst_subnet
                        # No actions means drop
                        self.connection.send(msg)
                    
                    # 3. Allow all other IP traffic between any hosts
                    msg = of.ofp_flow_mod()
                    msg.priority = 50  # Lower priority general rule
                    msg.match.dl_type = 0x800  # IPv4
                    msg.match.nw_src = src_subnet
                    msg.match.nw_dst = dst_subnet
                    msg.actions.append(of.ofp_action_output(port=routing_table[dst_host]))
                    self.connection.send(msg)
        
        # Allow all ARP traffic
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x806  # ARP
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    def dcs31_setup(self):
        """
        Setup rules for datacenter switch (connected to serv1)
        - Allow all IPv4 and ARP traffic to be flooded
        """
        # Allow all IPv4 traffic (flooding)
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x800  # IPv4
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)
        
        # Allow ARP traffic
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x806  # ARP
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    # used in part 4 to handle individual ARP packets
    # not needed for part 3 (USE RULES!)
    # causes the switch to output packet_in on out_port
    def resend_packet(self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        self.connection.send(msg)

    def _handle_PacketIn(self, event):
        """
        Packets not handled by the router rules will be
        forwarded to this method to be handled by the controller
        """

        packet = event.parsed  # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # The actual ofp_packet_in message.
        print(
            "Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump()
        )


def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Part3Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)