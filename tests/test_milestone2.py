import socket
import threading
import time
import subprocess
from pydivert.ebpf import EBPFDivert

def test_milestone2():
    print("--- Starting Milestone 2 Integration Test ---")
    
    # Send a quick UDP packet to make sure UDP is NOT blocked.
    # We will use socket to send a UDP packet and receive it.
    udp_port = 12346
    
    def receive_udp():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", udp_port))
        sock.settimeout(2.0)
        try:
            data, _ = sock.recvfrom(1024)
            if b"TEST_UDP" in data:
                print("SUCCESS: UDP packet passed through unharmed (as expected)!")
                return True
        except socket.timeout:
            print("FAILURE: UDP packet was dropped! Milestone 2 should only drop ICMP.")
            return False
        finally:
            sock.close()
        return False
        
    def send_udp():
        time.sleep(1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"TEST_UDP", ("127.0.0.1", udp_port))
        sock.close()

    udp_thread = threading.Thread(target=receive_udp)
    udp_thread.start()
    
    # We will use the system's 'ping' command to send ICMP packets
    try:
        with EBPFDivert(filter="icmp") as w:
            threading.Thread(target=send_udp).start()
            
            # Start ping to 127.0.0.1 (count 1, timeout 1s)
            print("Pinging 127.0.0.1 (expecting 100% packet loss because ICMP should be dropped)...")
            ping_process = subprocess.run(["ping", "-c", "1", "-W", "1", "127.0.0.1"], capture_output=True, text=True)
            
            if "100% packet loss" in ping_process.stdout or ping_process.returncode != 0:
                print("SUCCESS: Ping failed (ICMP packet dropped successfully)!")
                ping_dropped = True
            else:
                print("FAILURE: Ping succeeded! The packet was not dropped by eBPF.")
                ping_dropped = False
                
            # Verify pydivert caught the ICMP packet
            start_time = time.time()
            captured_icmp = False
            while time.time() - start_time < 2.0:
                try:
                    packet = w.recv(timeout=0.5)
                    if packet.ipv4 and packet.icmpv4:
                        print("SUCCESS: Divert successfully captured the stolen ICMP packet!")
                        captured_icmp = True
                        break
                except TimeoutError:
                    continue
                    
    except Exception as e:
        print(f"ERROR starting EBPFDivert: {e}")
        ping_dropped = False
        captured_icmp = False
        
    udp_thread.join()
    
    if ping_dropped and captured_icmp:
        print("--- Milestone 2 Test: PASSED ---")
    else:
        print("--- Milestone 2 Test: FAILED ---")

if __name__ == "__main__":
    test_milestone2()
