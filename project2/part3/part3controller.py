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

    
    def add_rule(self, dl_type=None, priority=0, proto=None, src=None, dst=None, port=None):
        rule = of.ofp_flow_mod()
        rule.priority = priority

        if dl_type is not None:
            rule.match.dl_type = dl_type
        if proto is not None:
            rule.match.nw_proto = proto
        if src is not None:
            rule.match.nw_src = src
        if dst is not None:
            rule.match.nw_dst = dst
        
        if port is not None:
            rule.actions.append(of.ofp_action_output(port=port))
        
        self.connection.send(rule)

    def setup(self):
        # allow all traffic
        self.add_rule(priority=1, port=of.OFPP_FLOOD)
    
    def s1_setup(self):
        # put switch 1 rules here
        self.setup()

    def s2_setup(self):
        # put switch 2 rules here
        self.setup()

    def s3_setup(self):
        # put switch 3 rules here
        self.setup()

    def cores21_setup(self):
        ports = {"h10": 1, "h20": 2, "h30": 3, "serv1": 4, "hnotrust": 5}

        # handle ARP
        self.add_rule(dl_type=0x806, priority=200, port=of.OFPP_FLOOD)

        # block hnotrust from sending IP to serv1
        self.add_rule(dl_type=0x800, priority=100, src=IPS["hnotrust"], dst=IPS["serv1"])

        # block hnotrust from sending all ICMP
        self.add_rule(dl_type=0x800, priority=100, proto=1, src=IPS["hnotrust"])

        # let serv1 communicate with hnotrust
        self.add_rule(
            dl_type=0x800,
            priority=100, 
            src=IPS["serv1"], 
            dst=IPS["hnotrust"], 
            port=ports["hnotrust"]
        )

        # otherwise allow all traffic between trusted hosts
        internal_hosts = ["h10", "h20", "h30", "serv1"]
        for src in internal_hosts:
            for dst in internal_hosts:
                if src != dst:
                    self.add_rule(
                        dl_type=0x800,
                        priority=50,
                        src=IPS[src],
                        dst=IPS[dst],
                        port=ports[dst]
                    )

        # allow communication between regular hosts and hnotrust
        for host in internal_hosts[:3]:
            self.add_rule(
                dl_type=0x800,
                priority=50,
                src=IPS["hnotrust"],
                dst=IPS[host],
                port=ports[host]
            )
            self.add_rule(
                dl_type=0x800, priority=50,
                src=IPS[host], dst=IPS["hnotrust"],
                port=ports["hnotrust"]
            )

    def dcs31_setup(self):
        # put datacenter switch rules here
        self.setup()

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
