import socket
import struct
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from packet_struct import Packet

TIMEOUT = 3
RETRANSMIT_INTERVAL = 1

def stage_a(sock, SERVER_ADDR, UDP_PORT):
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

def stage_b(sock, num, length, udp_port, secretA, SERVER_ADDR, UDP_PORT):
    print("---- Starting Stage B ----")
    
    payload = b'\x00' * length
    for id in range(num):
        # send num packets with id number of 4 bytes and payload of length length with 0s
        full_payload = struct.pack('!I', id) + payload
        packet = Packet(len(full_payload), secretA, 1, full_payload)
        processed_packet = packet.wrap_payload()
        send_ack(sock, processed_packet, id, udp_port, SERVER_ADDR, UDP_PORT)
    
    data, _ = sock.recvfrom(1024)
    payload = Packet.extract_payload(data)
    tcp_port, secretB = struct.unpack('!II', payload)

    print(f"Received: tcp_port={tcp_port}, secretB={secretB}")
    return tcp_port, secretB

def stage_c(sock, tcp_port, secretB):
    print("---- Starting Stage C ----")

    # receive packet from server and process
    data = sock.recv(1024)

    if len(data) < 13:
        raise Exception(f"Stage C response too short: got {len(data)} bytes, expected 13")

    payload = Packet.extract_payload(data)
    
    num2, len2, secretC, c = struct.unpack('!IIIc', payload)
    
    print(f"Received: num2={num2}, len2={len2}, secretC={secretC}, c={c.decode()}")
    return num2, len2, secretC, c.decode()

def send_ack(sock, processed_packet, id, udp_port, SERVER_ADDR, UDP_PORT, retries=10):

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

def stage_d(sock, num2, len2, secretC, c):
    print("---- Starting Stage D ----")
    
    payload = c.encode() * len2 # create payload of length len2 with c
    
    # send num2 payloads
    for i in range(num2):
        packet = Packet(len(payload), secretC, 1, payload)
        processed_packet = packet.wrap_payload()
        print(f"Sending packet {i+1}/{num2} with payload length {len(payload)}")
        sock.send(processed_packet)
    
    # receive response from server
    data = sock.recv(1024)
    
    if len(data) < 4:
        raise Exception(f"Stage D response too short: got {len(data)} bytes, expected at least 4")
    
    payload = Packet.extract_payload(data)
    secretD = struct.unpack('!I', payload)[0]
    
    print(f"Received: secretD={secretD}")
    return secretD

def main():

    SERVER_ADDR = str(sys.argv[1])
    UDP_PORT = int(sys.argv[2])
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"Sending to {SERVER_ADDR}:{UDP_PORT}")
    sock.settimeout(TIMEOUT)

    # start stage_a
    num, length, udp_port, secretA = stage_a(sock, SERVER_ADDR, UDP_PORT)
    
    print("\n stage A complete!\n")

    # start stage_b
    tcp_port, secretB = stage_b(sock, num, length, udp_port, secretA, SERVER_ADDR, UDP_PORT)

    print("\n stage B complete!\n")
    sock.close()

    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.connect((SERVER_ADDR, tcp_port))

    # start stage_c
    num2, len2, secretC, c = stage_c(tcp_sock, tcp_port, secretB)

    print("\n stage C complete!\n")

    # start stage_d

    secretD = stage_d(tcp_sock, num2, len2, secretC, c)

    print("\n stage D complete!\n")

    print("\n---- Final Output ----")
    print(f"Secret A: {secretA}")
    print(f"Secret B: {secretB}")
    print(f"Secret C: {secretC}")
    print(f"Secret D: {secretD}")

    tcp_sock.close()

if __name__ == "__main__":
    main()
