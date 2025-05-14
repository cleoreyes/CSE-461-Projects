# Part 4 of UWCSE's Mininet-SDN project
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from pox.lib.packet import arp, ethernet

log = core.getLogger()

IPS = {
    "h10": "10.0.1.10",
    "h20": "10.0.2.20",
    "h30": "10.0.3.30",
    "serv1": "10.0.4.10",
    "hnotrust": "172.16.10.100",
}

SUBNETS = {
    "h10": "10.0.1.0/24",
    "h20": "10.0.2.0/24",
    "h30": "10.0.3.0/24",
    "serv1": "10.0.4.0/24",
    "hnotrust": "172.16.10.0/24",
}

class Part4Controller(object):
    """
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        print(connection.dpid)
        self.connection = connection

        # create ARP table to map IPs to MAC addresses and port
        self.arp_table = {}

        connection.addListeners(self)
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
        arp_rule = of.ofp_flow_mod()
        arp_rule.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(arp_rule)

    def s2_setup(self):
        arp_rule = of.ofp_flow_mod()
        arp_rule.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(arp_rule)

    def s3_setup(self):
        arp_rule = of.ofp_flow_mod()
        arp_rule.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(arp_rule)

    def cores21_setup(self):
        hnotrust_drop_rule = of.ofp_flow_mod()
        hnotrust_drop_rule.priority = 30
        hnotrust_drop_rule.match.dl_type = 0x0800
        hnotrust_drop_rule.match.nw_proto = 1
        hnotrust_drop_rule.match.nw_src = IPS["hnotrust"]
        hnotrust_drop_rule.actions = []
        self.connection.send(hnotrust_drop_rule)

        serv1_drop_rule = of.ofp_flow_mod()
        serv1_drop_rule.priority = 20
        serv1_drop_rule.match.dl_type = 0x0800
        serv1_drop_rule.match.nw_src = IPS["hnotrust"]
        serv1_drop_rule.match.nw_dst = IPS["serv1"]
        serv1_drop_rule.actions = []
        self.connection.send(serv1_drop_rule)

    def dcs31_setup(self):
        arp_rule = of.ofp_flow_mod()
        arp_rule.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(arp_rule)

    # used in part 4 to handle individual ARP packets
    # not needed for part 3 (USE RULES!)
    # causes the switch to output packet_in on out_port
    def resend_packet(self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        self.connection.send(msg)

    def handle_arp(self, packet, event):
        arp_packet = packet.payload

        # see if the packet is an ARP request
        if arp_packet.opcode == arp.REQUEST :
            self.learn_packet(packet, event)
            self.send_arp_reply(packet, event)

    def learn_packet(self, packet, event) :
        # takes in ARP packet and maps IP to MAC, Port tuple
        arp_payload = packet.payload
        ip = str(arp_payload.protosrc)
        mac = str(arp_payload.hwsrc)
        port = event.port
        self.arp_table[ip] = (mac, port)
        print(f"Learning address for ip {ip}: mac : {mac} port : {port}")

    def send_arp_reply(self, packet, event) :
        # proxy the ARP replies
        arp_packet = packet.payload
        reply_arp = arp()
        reply_arp.opcode = arp.REPLY
        reply_arp.hwsrc = self.connection.eth_addr
        reply_arp.hwdst = arp_packet.hwsrc
        reply_arp.protosrc = arp_packet.protodst
        reply_arp.protodst = arp_packet.protosrc

        reply_eth = ethernet()
        reply_eth.type = ethernet.ARP_TYPE
        reply_eth.dst = reply_arp.hwdst
        reply_eth.src = reply_arp.hwsrc
        reply_eth.payload = reply_arp

        self.resend_packet(reply_eth.pack(), event.port)

    def forward_ip(self, packet, event) :
        # method to forward IP packets using the ARP table records

        ip_packet = packet.payload

        ip_src = str(ip_packet.srcip)
        ip_dst = str(ip_packet.dstip)

        print(f"Checking if ip_dst {ip_dst} is in arp_table: {self.arp_table}")

        if ip_dst in self.arp_table:
            mac, port = self.arp_table[ip_dst]
            print(f"Record for ip {ip_dst} found. mac {mac} port {port}")
            forward_rule = of.ofp_flow_mod()
            forward_rule.match.dl_type = 0x0800
            forward_rule.match.nw_dst = IPAddr(ip_dst)
            forward_rule.actions.append(of.ofp_action_dl_addr.set_src(self.connection.eth_addr))
            forward_rule.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(mac.encode())))
            forward_rule.actions.append(of.ofp_action_output(port=port))
            forward_rule.priority = 10
            self.connection.send(forward_rule)

            
            ethernet_record = packet.find('ethernet')
            if ethernet_record :
                ethernet_record.src = self.connection.eth_addr

            if mac :
                ethernet_record.dst = forward_rule.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(mac)))
                self.resend_packet(packet, port)
        else:
            print(f"No entry in ARP records for {ip_dst}, flooding ARP request.")

            arp_req = arp()
            arp_req.opcode = arp.REQUEST
            arp_req.hwsrc = self.connection.eth_addr
            arp_req.hwdst = EthAddr("ff:ff:ff:ff:ff:ff")
            arp_req.protosrc = IPAddr(ip_src)
            arp_req.protodst = IPAddr(ip_dst)

            eth = ethernet()
            eth.type = ethernet.ARP_TYPE
            eth.src = self.connection.eth_addr
            eth.dst = arp_req.hwdst
            eth.payload = arp_req

            self.resend_packet(eth.pack(), of.OFPP_FLOOD)


    def _handle_PacketIn(self, event):
        """
        Packets not handled by the router rules will be
        forwarded to this method to be handled by the controller
        """

        packet = event.parsed 
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp

        if packet.type == packet.ARP_TYPE :
            self.handle_arp(packet, event)
        elif packet.type == packet.IP_TYPE :
            self.forward_ip(packet, event)
        else:
            print(
                "Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump()
            )


def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Part4Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
