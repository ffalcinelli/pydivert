import time
import sys
from unittest.mock import Mock, patch, PropertyMock

from pydivert.ebpf import EBPFDivert

def run_benchmark():
    # Mocking necessary parts for EBPFDivert
    divert = EBPFDivert("filter")
    divert._is_open = True
    divert._queue = []

    # Mock ringbuf
    divert._ringbuf = "dummy"

    # Mock libbpf
    mock_libbpf = Mock()
    call_count = 0
    def fake_poll(rb, timeout):
        nonlocal call_count
        call_count += 1
        pass
    mock_libbpf.ring_buffer__poll = fake_poll

    with patch('pydivert.ebpf.libbpf', mock_libbpf):
        with patch('pydivert.ebpf.EBPFDivert.is_open', new_callable=PropertyMock) as mock_is_open:
            mock_is_open.return_value = True

            start = time.time()
            try:
                divert._recv_impl(timeout=0.1)
            except TimeoutError:
                pass
            end = time.time()

            # Count the number of polls
            print(f"Time sleep 0.001 (baseline) poll calls in {end-start:.3f}s: {call_count}")
            print(f"Latency: {(end-start) / call_count if call_count > 0 else 0:.6f}s per poll loop")

if __name__ == '__main__':
    run_benchmark()
