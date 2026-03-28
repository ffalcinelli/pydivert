import time
from multiprocessing import Process

import pydivert


def inbound_func():
    print("Starting inbound process...")
    # The WinDivert handle MUST be opened, preferably using a context manager.
    with pydivert.WinDivert("inbound") as w:
        print("Inbound WinDivert handle opened.")
        for packet in w:
            # do something with the packet
            print(f"Inbound packet received: {packet}")
            w.send(packet)

def outbound_func():
    print("Starting outbound process...")
    # Alternatively, you can call .open() and .close() explicitly.
    w = pydivert.WinDivert("outbound")
    w.open()
    try:
        print("Outbound WinDivert handle opened.")
        while True:
            packet = w.recv()
            # do something with the packet
            print(f"Outbound packet received: {packet}")
            w.send(packet)
    finally:
        w.close()

if __name__ == '__main__':
    # Note: Running this example requires Administrator privileges and WinDivert driver installed.
    # It will also capture all inbound/outbound traffic, which might be disruptive.

    p1 = Process(name='inboundProcess', target=inbound_func)
    p2 = Process(name='outboundProcess', target=outbound_func)

    p1.start()
    p2.start()

    time.sleep(5) # Run for 5 seconds

    print("Terminating processes...")
    p1.terminate()
    p2.terminate()
    p1.join()
    p2.join()
    print("Done.")
