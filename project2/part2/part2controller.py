# Part 2 of UWCSE's Project 3
#
# based on Lab 4 from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Firewall(object):
    """
    A Firewall object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # add switch rules here
        h1_ip = "10.0.1.2"
        h2_ip = "10.0.0.2"
        h3_ip = "10.0.0.3"
        h4_ip = "10.0.1.3"

        # allow icmp traffic in h1 h4 subnet
        self.add_rule(0x800, 100, 1, h1_ip, h4_ip)
        self.add_rule(0x800, 100, 1, h4_ip, h1_ip)

        # allow icmp traffic in h2 h3 subnet
        self.add_rule(0x800, 100, 1, h2_ip, h3_ip)
        self.add_rule(0x800, 100, 1, h3_ip, h2_ip)

        # allow arp traffic
        self.add_rule(0x806, 100)

        # drop all other ipv4
        self.add_rule(0x800, 0)
        
    def add_rule(self, dl_type, priority, proto=None, src=None, dst=None):
        rule = of.ofp_flow_mod()
        rule.priority = priority
        rule.match.dl_type = dl_type

        if proto is not None:
            rule.match.nw_proto = proto

        if src is not None and dst is not None:
            # icmp
            rule.match.nw_src = src
            rule.match.nw_dst = dst

        if priority > 0:
            rule.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))

        self.connection.send(rule)


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
        print("Unhandled packet :" + str(packet.dump()))

def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Firewall(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
