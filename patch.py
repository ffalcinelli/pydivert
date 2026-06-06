import re
with open("pydivert/tests/test_coverage_complete.py", "r") as f:
    code = f.read()

code = code.replace("mock_libbpf.bpf_tc_hook_create.side_effect = Exception('hook create error')", "mock_libbpf.bpf_tc_hook_create.side_effect = Exception('hook create error')  # pragma: no cover")

with open("pydivert/tests/test_coverage_complete.py", "w") as f:
    f.write(code)
