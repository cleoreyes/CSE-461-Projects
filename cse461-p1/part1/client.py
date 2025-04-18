import socket
import struct
# import struct
from packet_struct import Packet
import sys

SERVER_ADDR = sys.argv[1]
TIMEOUT = 10
RETRANSMIT_INTERVAL = 1
UDP_PORT = int(sys.argv[2])

def stage_a(sock):
    print("---- Starting Stage A ----")

    payload = b'hello world\0'
    packet = Packet(len(payload), 0, 1, payload)
    processed_packet = packet.wrap_payload()

    print(f"Sending packet: {processed_packet}")

    sock.sendto(processed_packet, (SERVER_ADDR, UDP_PORT))
    print("Sent 'hello world'")

    data, _ = sock.recvfrom(1024)

    payload = Packet.extract_payload(data)

    if len(payload) < 16:
        print("Stage A response too short")
        
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
    
    # Create a longer timeout because gradescopt will take longer
    try:
        sock.settimeout(TIMEOUT)
        data, _ = sock.recvfrom(1024)
    except socket.timeout:
        print("No response received for Stage B")

    payload = Packet.extract_payload(data)

    if len(payload) < 8:
        print(f"Stage B response too short")

    tcp_port, secretB = struct.unpack('!II', payload)

    print(f"Received: tcp_port={tcp_port}, secretB={secretB}")
    return tcp_port, secretB

def stage_c(sock, tcp_port):
    print("---- Starting Stage C ----")

    # receive packet from server and process
    header = recv_data(sock, Packet.HEADER_SIZE)

    if len(header) < Packet.HEADER_SIZE:
        print("Stage C header too short")

    payload_len = struct.unpack(Packet.HEADER_FORMAT, header)[0]

    data = recv_data(sock, max(payload_len, 16))

    payload = Packet.extract_payload(header + data)

    if len(payload) < 13:
        print(f"Stage C response too short")
    
    num2, len2, secretC, c = struct.unpack('!IIIc', payload)
    
    print(f"Received: num2={num2}, len2={len2}, secretC={secretC}, c={c.decode()}")
    return num2, len2, secretC, c

def stage_d(sock, num2, len2, secretC, c):
    print("---- Starting Stage D ----")
    
    payload = c * len2
    print(f"Stage D: Sending {num2} packets of length {len(payload)} filled with char '{c}'")
    
    # send num2 payloads
    for i in range(num2):
        packet = Packet(len(payload), secretC, 1, payload)
        processed_packet = packet.wrap_payload()
        print(f"Sending packet {i+1}/{num2} with payload length {len(payload)}")
        sock.sendall(processed_packet)
    
    header = recv_data(sock, Packet.HEADER_SIZE)
    if len(header) < Packet.HEADER_SIZE:
        print("Stage D header too short")

    payload_len = struct.unpack(Packet.HEADER_FORMAT, header)[0]
    data = recv_data(sock, payload_len)

    payload = Packet.extract_payload(header + data)

    if len(payload) < 4:
        print("Stage D response too short")
    
    secretD = struct.unpack('!I', payload)[0]
    
    print(f"Received: secretD={secretD}")
    return secretD


def send_ack(sock, processed_packet, id, udp_port):

    print(f"Sending packet with ack: {processed_packet}")

    while True:
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
            print(f"Timeout, retrying")

def recv_data(sock, length):
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        data += chunk
    return data


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"Sending to {SERVER_ADDR}:{UDP_PORT}")
    #sock.settimeout(TIMEOUT)

    # start stage_a
    num, length, udp_port, secretA = stage_a(sock)
    
    print("\n stage A complete!\n")

    # start stage_b
    tcp_port, secretB = stage_b(sock, num, length, udp_port, secretA)

    print("\n stage B complete!\n")
    sock.close()

    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            print(f"Connecting to TCP port {tcp_port}...")
            tcp_sock.connect((SERVER_ADDR, tcp_port))
            break  # Connection successful, break out of the loop
        except (ConnectionRefusedError, socket.timeout):
            print(f"Connection to TCP port {tcp_port} refused. Retrying...")
            continue  # Retry until connection is successful

    # start stage_c
    num2, len2, secretC, c = stage_c(tcp_sock, tcp_port)

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
