with open("pydivert/tests/test_coverage_complete.py") as f:
    code = f.read()

code = code.replace(
    '        with patch("subprocess.check_output", '
    'return_value=b\'[{"options": {"bpf_name": "tc_divert_ingress"}, "pref": 1}]\'):',
    '        with patch("subprocess.check_output", '
    'return_value=b\'[{"options": {"bpf_name": "tc_divert"}, "pref": 1}]\'):',
)

with open("pydivert/tests/test_coverage_complete.py", "w") as f:
    f.write(code)
