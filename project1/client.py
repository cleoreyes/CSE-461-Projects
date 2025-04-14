import socket
import struct
# import struct
from packet_struct import Packet

SERVER_ADDR = 'attu2.cs.washington.edu'
TIMEOUT = 3
RETRANSMIT_INTERVAL = 1
UDP_PORT = 12235

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

def stage_b(sock, num, length, udp_port, secretA):
    print("---- Starting Stage B ----")
    
    payload = b'\x00' * length
    for id in range(num):
        # send num packets with id number of 4 bytes and payload of length length with 0s
        full_payload = struct.pack('!I', id) + payload
        packet = Packet(len(full_payload), secretA, 1, full_payload)
        processed_packet = packet.wrap_payload()
        send_ack(sock, processed_packet, id, udp_port)
    
    data, _ = sock.recvfrom(1024)
    payload = Packet.extract_payload(data)
    tcp_port, secretB = struct.unpack('!II', payload)

    print(f"Received: tcp_port={tcp_port}, secretB={secretB}")
    return tcp_port, secretB

def send_ack(sock, processed_packet, id, udp_port, retries=10):

    print(f"Sending packet with ack: {processed_packet}")

    for i in range(retries):
        sock.sendto(processed_packet, (SERVER_ADDR, udp_port))
        try:
            sock.settimeout(RETRANSMIT_INTERVAL)
            data, _ = sock.recvfrom(1024)
            
            payload = Packet.extract_payload(data)
            # now the id should be the next four bytes:
            ack_id = struct.unpack('!I', payload[:4])[0]

            if ack_id == id:
                print(f"ACK received for id {ack_id}")
                return data
        except socket.timeout:
            print(f"Timeout, retrying ({i + 1})")

def main():
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"Sending to {SERVER_ADDR}:{UDP_PORT}")
    sock.settimeout(TIMEOUT)
    num, length, udp_port, secretA = stage_a(sock)
    
    print("\n stage A complete!")

    tcp_port, secretB = stage_b(sock, num, length, udp_port, secretA)

    print("\n stage B complete!")




if __name__ == "__main__":
    main()
