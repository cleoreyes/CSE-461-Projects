import socket
import threading
from packet_struct import Packet
import random
import struct

HOST = "0.0.0.0"  # Any network interface
PORT = 12235
RECV_SIZE = 1024
TIMEOUT = 3  # seconds
HEADER_SIZE = Packet.HEADER_SIZE
HEADER_FORMAT = Packet.HEADER_FORMAT
STUDENT_ID_LAST3 = 176  # Assuming 176 is the last 3 digits of student ID?

# The server should verify the header of every packet received and close any open sockets to the client and/or fail to respond to the client if:
  # unexpected number of buffers have been received
  # unexpected payload, or length of packet or length of packet payload has been received
  # the server does not receive any packets from the client for 3 seconds
  # the server does not receive the correct secret

def random_int():
    return random.randint(1, 5)
def random_length():
    return random.randint(1, 10)
def random_port():
    return random.randint(1024, 65535)
def random_secret():
    return random.randint(1000, 99999)

def handle_stage_a(data, addr, udp_sock):
    try:
        # Verify the packet length
        if len(data) != HEADER_SIZE + 12:
            print(f"[{addr}] Invalid packet length: {len(data)}")
            return None
        
        # Verify packet header
        payload_len, psecret, step, student_id = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
        if payload_len != 12 or psecret != 0 or step != 1 or student_id != STUDENT_ID_LAST3:
            print(f"[{addr}] Header validation failed:")
            print(f"  len={payload_len}, secret={psecret}, step={step}, id={student_id}")
            return None
        
        # Extract payload
        payload = Packet.extract_payload(data)

        if payload != b'hello world\0':
            print(f"[{addr}] Invalid payload: {payload}")
            return None

        num = random_int()
        length = random_length()
        udp_port = random_port()
        secretA = random_secret()

        response_payload = struct.pack('!IIII', num, length, udp_port, secretA)
        packet = Packet(len(response_payload), 0, 1, response_payload)

        print(f"[{addr}] Sending Stage A response: num={num}, len={length}, udp_port={udp_port}, secretA={secretA}")
    
        udp_sock.sendto(packet.wrap_payload(), addr)
        return num, length, udp_port, secretA
    except Exception as e:
        print(f"[{addr}] Error in Stage A: {e}")
        return None
   
def handle_stage_b(addr, num, length, udp_port, secretA):
    # Create a UDP socket for this stage at port udp_port
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((HOST, udp_port))
    udp_sock.settimeout(TIMEOUT)

    received = 0  # number of packets received
    last_acked = -1  # to track the last acknowledged packet
    print(f"[{addr}] Listening on UDP port {udp_port} for Stage B")
    while received < num:
        try:
            data, client = udp_sock.recvfrom(2048)

            payload = Packet.extract_payload(data)
            if len(payload) != length + 4:
                continue
    
            packet_id = struct.unpack('!I', payload[:4])[0]  # Extract packet ID as int
            content = payload[4:]

            # Verify packet ID and content
            if content != b'\x00' * length or packet_id != received:
                continue

            # Randomly acknoledge packets and the last packet
            if random.random() > 0.4 or received == num - 1:
                ack_payload = struct.pack('!I', packet_id)
                ack_packet = Packet(4, secretA, 2, ack_payload)
                udp_sock.sendto(ack_packet.wrap_payload(), client)
                received += 1
        except socket.timeout:
            break

    tcp_port = random_port()
    secretB = random_secret()
    response_payload = struct.pack('!II', tcp_port, secretB)
    packet = Packet(len(response_payload), secretA, 2, response_payload)

    print(f"[{addr}] Sending Stage B response: tcp_port={tcp_port}, secretB={secretB}")
    udp_sock.sendto(packet.wrap_payload(), addr)
    return tcp_port, secretB

def handle_stage_c(conn, secretB):
    num2 = random_int()
    len2 = random_length()
    secretC = random_secret()
    c = random.choice(b'abcdefghijklmnopqrstuvwxyz')
    c_byte = bytes([c])  # Convert to bytes

    payload = struct.pack('!IIIc', num2, len2, secretC, c_byte)
    packet = Packet(len(payload), secretB, 3, payload)

    print(f"[TCP] Sending Stage C response: num2={num2}, len2={len2}, secretC={secretC}, c={chr(c)}")
    conn.sendall(packet.wrap_payload())
    return num2, len2, secretC, c_byte

# Helper Function: keep receiving until the exact number of bytes is received (for TCP)
def recv_exact(sock, num_bytes):
    buf = b""
    # Keep receiving until we have the exact number of bytes
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed prematurely")
        buf += chunk
    return buf

# Helper Function: calculate the padded length of a payload to be a multiple of 4
def padded_length(n):
    return ((n + 3) // 4) * 4

def handle_stage_d(conn, num2, len2, secretC, c):
    try:
        for i in range(num2):
            # Receive header
            header = recv_exact(conn, HEADER_SIZE)
            payload_len, psecret, step, student_id = struct.unpack(HEADER_FORMAT, header)

            # Verify header fields
            if psecret != secretC or step != 1 or student_id != STUDENT_ID_LAST3:
                print(f"[TCP] Stage D validation failed on header at packet {i}")
                print(f"  Expected secretC: {secretC}, Received: {psecret}")
                print(f"  Expected step: 1, Received: {step}")
                print(f"  Expected student_id: {STUDENT_ID_LAST3}, Received: {student_id}")
                return

            # Calculate the number of bytes to read to get the entire payload and receive it
            pad_len = padded_length(payload_len)
            full_payload = recv_exact(conn, pad_len)

            # Extract only the real payload (the rest is padding)
            payload = full_payload[:payload_len]

            if payload != c * len2:
                print(f"[TCP] Stage D content validation failed at packet {i}")
                print(f"  Expected: {c * len2}, Received: {payload}")
                return

            print(f"[TCP] Stage D packet {i} valid")

        # If all packets were valid, create and send Stage D response
        secretD = random_secret()
        response_payload = struct.pack("!I", secretD)
        response = Packet(len(response_payload), secretC, 4, response_payload).wrap_payload()
        conn.sendall(response)
        print(f"[TCP] Stage D complete. Sent secretD: {secretD}")
    except Exception as e:
        print(f"[TCP] Error in Stage D: {e}")
        conn.close()

def start_tcp_server(tcp_port):
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind((HOST, tcp_port))
    tcp_sock.listen(1)
    tcp_sock.settimeout(TIMEOUT)

    try:
        conn, _ = tcp_sock.accept()
        tcp_sock.close()
        return conn
    except socket.timeout:
        tcp_sock.close()
        return None

def client_thread(data, addr, udp_sock):
    stage_a = handle_stage_a(data, addr, udp_sock)
    if not stage_a:
        return
    num, length, udp_port, secretA = stage_a

    stage_b = handle_stage_b(addr, num, length, udp_port, secretA)
    if not stage_b:
        return
    tcp_port, secretB = stage_b

    conn = start_tcp_server(tcp_port)
    if not conn:
        return

    num2, len2, secretC, c = handle_stage_c(conn, secretB)
    handle_stage_d(conn, num2, len2, secretC, c)
    conn.close()

def start_udp_server():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((HOST, PORT))
    print(f"[SERVER] Listening on UDP port {PORT}")
    udp_sock.settimeout(TIMEOUT)

    while True:
        try:
            data, addr = udp_sock.recvfrom(RECV_SIZE)  # Corrected to use recvfrom
            print(f"[SERVER] Received data from {addr} ({len(data)} bytes)")
            if data:
                thread = threading.Thread(target=client_thread, args=(data, addr, udp_sock))
                thread.start()
        except socket.timeout:
            print("[SERVER] UDP socket timed out")

if __name__ == "__main__":
    start_udp_server()
