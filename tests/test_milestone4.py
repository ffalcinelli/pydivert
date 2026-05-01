import socket
import threading
import time
from pydivert.ebpf import EBPFDivert

def test_milestone4():
    print("--- Starting Milestone 4 Integration Test ---")
    
    port = 12347
    
    def receive_udp():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", port))
        sock.settimeout(5.0)
        try:
            data, _ = sock.recvfrom(1024)
            if b"TEST_MODIFIED" in data:
                print("SUCCESS: Modified payload was successfully received by the destination!")
                return True
            else:
                print(f"FAILURE: Received incorrect payload: {data}")
                return False
        except socket.timeout:
            print("FAILURE: Packet was dropped or not reinjected properly!")
            return False
        finally:
            sock.close()
        return False
        
    def send_udp():
        time.sleep(1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"TEST_ORIGINAL", ("127.0.0.1", port))
        sock.close()

    result = {}
    recv_thread = threading.Thread(target=lambda: result.update({"success": receive_udp()}))
    recv_thread.start()
    
    try:
        with EBPFDivert(filter=f"udp.DstPort == {port}") as w:
            threading.Thread(target=send_udp).start()
            
            start_time = time.time()
            captured_and_sent = False
            while time.time() - start_time < 3.0:
                try:
                    packet = w.recv(timeout=0.5)
                    if packet.udp and packet.dst_port == port:
                        print(f"Divert intercepted a packet! Payload: {packet.payload}")
                        if packet.payload == b"TEST_ORIGINAL":
                            # Modify the payload
                            packet.payload = b"TEST_MODIFIED"
                            # Reinject the packet (checksums will be recalculated)
                            w.send(packet)
                            print("Modified packet successfully reinjected!")
                            captured_and_sent = True
                        elif packet.payload == b"TEST_MODIFIED":
                            print("Oh no! The reinjected packet was intercepted AGAIN!")
                except TimeoutError:
                    continue
                    
    except Exception as e:
        print(f"ERROR starting EBPFDivert: {e}")
        captured_and_sent = False
        
    recv_thread.join()
    
    if result.get("success", False) and captured_and_sent:
        print("--- Milestone 4 Test: PASSED ---")
    else:
        print("--- Milestone 4 Test: FAILED ---")

if __name__ == "__main__":
    test_milestone4()
