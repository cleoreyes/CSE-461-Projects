import socket
import struct
# import struct
from packet_struct import Packet
# import time

SERVER_ADDR = 'attu2.cs.washington.edu'
UDP_PORT = 12235
TIMEOUT = 3
RETRANSMIT_INTERVAL = 0.5

def stage_a(sock):
    print("---- Starting Stage A ----")

    payload = b'hello world\0'
    packet = Packet(len(payload), 0, 1, payload)
    processed_packet = packet.wrap_payload()

    print(f"Sending packet: {processed_packet}")

    sock.sendto(processed_packet, (SERVER_ADDR, UDP_PORT))
    print("Sent 'hello world'")

    data, _ = sock.recvfrom(1024)
    if len(data) < 16:
        raise Exception("Stage A response too short")

    payload = Packet.extract_payload(data)
    num, length, udp_port, secretA = struct.unpack('!IIII', payload)
    print(f"Received: num={num}, len={length}, udp_port={udp_port}, secretA={secretA}")

    return num, length, udp_port, secretA

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[*] Sending to {SERVER_ADDR}:{UDP_PORT}")
    sock.settimeout(TIMEOUT)
    num, length, udp_port, secretA = stage_a(sock)

    print("\n[✓] Protocol complete!")

if __name__ == "__main__":
    main()
