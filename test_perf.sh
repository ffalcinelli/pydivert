cp pydivert/ebpf.py pydivert/ebpf.py.orig
sed -i 's/time.sleep(0.001)//g' pydivert/ebpf.py
uv run python3 benchmark_ebpf.py
mv pydivert/ebpf.py.orig pydivert/ebpf.py
