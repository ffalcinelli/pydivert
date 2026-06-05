import os
import sys

# Add pydivert to sys.path
sys.path.insert(0, os.getcwd())

try:
    import pydivert

    print(f"pydivert version: {pydivert.__version__}")
    print(f"Platform: {sys.platform}")

    with pydivert.Divert("false") as w:
        print("Successfully opened WinDivert handle!")
except Exception as e:
    print(f"Failed to open WinDivert handle: {e}")
    import traceback

    traceback.print_exc()
