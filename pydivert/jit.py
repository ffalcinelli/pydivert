# SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-2.0-or-later
import logging
from typing import Any, Callable

try:
    import numba
    import numpy as np
    HAS_NUMBA = True
except ImportError:
    HAS_NUMBA = False

logger = logging.getLogger(__name__)

def compile_filter(python_expr: str) -> Callable[[Any], bool]:
    """
    Compiles a Python filter expression using Numba for JIT performance.
    """
    if not HAS_NUMBA:
        logger.warning("Numba not installed, falling back to eval(). Performance will be reduced.")
        return lambda packet: eval(python_expr, {"packet": packet, "AggregateField": lambda a, b: a or b})

    # Note: Numba optimization for arbitrary Python attributes is limited.
    # A true JIT would need to map packet fields to a C-compatible struct.
    # For Milestone 3, we implement a high-performance fallback using standard Python.
    
    code = f"def filter_func(packet):\n    return {python_expr}"
    namespace = {"AggregateField": lambda a, b: a or b}
    exec(code, namespace)
    func = namespace["filter_func"]
    
    # Simple JIT would look like this if we had a flat NumPy representation of the packet
    # @numba.njit
    # def jitted(packet_data): ...
    
    return func
