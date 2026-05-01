import socket
import threading
import time
from pydivert.ebpf import EBPFDivert

PORT = 12345
PAYLOAD = b"MILESTONE1_PAYLOAD"

def receive_udp():
    """Tries to receive the packet on the destination port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", PORT))
    sock.settimeout(2.0)
    try:
        data, addr = sock.recvfrom(1024)
        if PAYLOAD in data:
            print("FAILURE: Packet reached destination socket! It was not stolen.")
            return False
    except socket.timeout:
        print("SUCCESS: Packet did not reach destination socket (it was stolen).")
        return True
    finally:
        sock.close()
    return False

def send_udp():
    """Sends the UDP packet to the destination port."""
    time.sleep(1) # wait for capture to start
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(PAYLOAD, ("127.0.0.1", PORT))
    sock.close()

def main():
    print("--- Starting Milestone 1 Integration Test ---")
    
    recv_thread = threading.Thread(target=receive_udp)
    recv_thread.start()

    print("Starting eBPF packet capture on 'lo' interface...")
    captured = False
    
    try:
        # For now, it ignores the filter and captures everything
        with EBPFDivert() as w:
            threading.Thread(target=send_udp).start()
            
            print("Waiting for packet in pydivert...")
            start_time = time.time()
            
            while time.time() - start_time < 3.0:
                try:
                    packet = w.recv(timeout=0.5)
                    # Check if our payload is in the packet's raw bytes
                    if packet.payload and PAYLOAD in packet.payload:
                        print("SUCCESS: Packet physical interception confirmed by Divert!")
                        captured = True
                        break
                except TimeoutError:
                    continue
    except Exception as e:
        print(f"ERROR starting EBPFDivert: {e}")
        
    recv_thread.join()
    
    if captured:
        print("--- Milestone 1 Test: PASSED ---")
    else:
        print("--- Milestone 1 Test: FAILED ---")

if __name__ == "__main__":
    main()
