import socket
import threading

HOST = "0.0.0.0"  # Any network interface
PORT = 12235
RECV_SIZE = 1024
TIMEOUT = 3  # seconds

# --- Stage handlers ---
client_states = {}  # maps client_addr -> stage info
client_states_lock = threading.Lock()  # lock for thread-safe access

# TODO: methods that handle different stages
# The server should verify the header of every packet received and close any open sockets to the client and/or fail to respond to the client if:
  # unexpected number of buffers have been received
  # unexpected payload, or length of packet or length of packet payload has been received
  # the server does not receive any packets from the client for 3 seconds
  # the server does not receive the correct secret

def handle_stage_a(data, addr, udp_sock):
    print(f"[{addr}] Handling Stage A")

    # 
    response = b"Stage A complete"
    udp_sock.sendto(response, addr)
    with client_states_lock:
        client_states[addr] = 'B'

def handle_stage_b(data, addr, udp_sock):
    print(f"[{addr}] Handling Stage B")
    response = b"Stage B complete"
    udp_sock.sendto(response, addr)
    with client_states_lock:
        client_states[addr] = 'C'

def handle_stage_c(data, addr, conn):
    print(f"[{addr}] Handling Stage C")
    response = b"Stage C complete"
    conn.sendall(response)
    with client_states_lock:
        client_states[addr] = 'D'

def handle_stage_d(data, addr, conn):
    print(f"[{addr}] Handling Stage D")
    response = b"Stage D complete"
    conn.sendall(response)
    with client_states_lock:
        client_states[addr] = 'done'

stage_handlers = {
    'A': handle_stage_a,
    'B': handle_stage_b,
    'C': handle_stage_c,
    'D': handle_stage_d
}

# --- TCP handling ---
def handle_tcp_client(conn, addr):
    with conn:
        print(f"[TCP] Connected by {addr}")
        conn.settimeout(TIMEOUT)
        while True:
            try:
                data = conn.recv(RECV_SIZE)
                if not data:
                    break

                # Handle the request based on current stage
                with client_states_lock:
                    current_stage = client_states.get(addr, 'A')
                handler = stage_handlers.get(current_stage)
                if not handler:
                    print(f"[{addr}] Unknown stage: {current_stage}")
                    continue
                handler(data, addr, conn)
            except socket.timeout:
                print(f"[{addr}] Connection timed out")
                break

def tcp_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print("[TCP] Server listening on port 12235...")

        while True:
            conn, cli_addr = s.accept()
            # Create multiple threads for more clients
            thread = threading.Thread(target=handle_tcp_client, args=(conn, cli_addr), daemon=True)
            thread.start()

# --- UDP handling ---
def udp_server():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((HOST, PORT))
        print("[UDP] Server listening on port 12235...")
        s.settimeout(TIMEOUT)

        while True:
            try:
                data, addr = s.recvfrom(RECV_SIZE)
                with client_states_lock:
                    current_stage = client_states.get(addr, 'A')
                handler = stage_handlers.get(current_stage)
                if not handler:
                    print(f"[{addr}] Unknown stage: {current_stage}")
                    continue
                # Create multiple threads for more clients
                thread = threading.Thread(target=handler, args=(data, addr, s), daemon=True)
                thread.start()
            except socket.timeout:
                print(f"[{addr}] Connection timed out")
                break

# --- Start both servers to handle both UDP and TCP ---
threading.Thread(target=tcp_server, daemon=True).start()
udp_server()  # run UDP in main thread
