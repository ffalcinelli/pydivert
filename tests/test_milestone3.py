import socket
import threading
import time
import subprocess
from pydivert.ebpf import EBPFDivert

def test_milestone3():
    print("--- Starting Milestone 3 Integration Test ---")
    
    # We will test two ports. Port 12345 is blocked, port 12346 is allowed.
    blocked_port = 12345
    allowed_port = 12346
    
    def receive_udp(port, name):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", port))
        sock.settimeout(2.0)
        try:
            data, _ = sock.recvfrom(1024)
            if b"TEST" in data:
                return True
        except socket.timeout:
            return False
        finally:
            sock.close()
        return False
        
    def send_udp(port):
        time.sleep(1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"TEST_UDP", ("127.0.0.1", port))
        sock.close()

    # Start receivers
    allowed_thread = threading.Thread(target=lambda: result.update({"allowed": receive_udp(allowed_port, "allowed")}))
    blocked_thread = threading.Thread(target=lambda: result.update({"blocked": receive_udp(blocked_port, "blocked")}))
    
    result = {}
    allowed_thread.start()
    blocked_thread.start()
    
    try:
        # Transpiler rule: steal UDP destination port 12345
        with EBPFDivert(filter="udp.DstPort == 12345") as w:
            # Send to both ports
            threading.Thread(target=send_udp, args=(allowed_port,)).start()
            threading.Thread(target=send_udp, args=(blocked_port,)).start()
            
            # Start ping to 127.0.0.1 (count 1, timeout 1s). It should pass because filter is ONLY udp.DstPort == 12345
            ping_process = subprocess.run(["ping", "-c", "1", "-W", "1", "127.0.0.1"], capture_output=True, text=True)
            if ping_process.returncode == 0:
                print("SUCCESS: Ping succeeded! Unrelated ICMP packet was correctly NOT dropped.")
                ping_passed = True
            else:
                print("FAILURE: Ping failed! ICMP packet was unexpectedly dropped.")
                ping_passed = False

            # Verify pydivert caught the blocked UDP packet
            start_time = time.time()
            captured_blocked = False
            while time.time() - start_time < 3.0:
                try:
                    packet = w.recv(timeout=0.5)
                    if packet.udp and packet.dst_port == blocked_port:
                        print("SUCCESS: Divert correctly captured the blocked UDP packet.")
                        captured_blocked = True
                        break
                except TimeoutError:
                    continue
                    
    except Exception as e:
        print(f"ERROR starting EBPFDivert: {e}")
        ping_passed = False
        captured_blocked = False
        
    allowed_thread.join()
    blocked_thread.join()
    
    if result.get("allowed", False):
        print("SUCCESS: Allowed UDP packet correctly reached destination.")
    else:
        print("FAILURE: Allowed UDP packet was dropped!")
        
    if not result.get("blocked", True):
        print("SUCCESS: Blocked UDP packet correctly NOT reached destination.")
    else:
        print("FAILURE: Blocked UDP packet reached destination!")
    
    if ping_passed and captured_blocked and result.get("allowed", False) and not result.get("blocked", True):
        print("--- Milestone 3 Test: PASSED ---")
    else:
        print("--- Milestone 3 Test: FAILED ---")

if __name__ == "__main__":
    test_milestone3()
