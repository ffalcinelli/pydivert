from __future__ import annotations

import ctypes
import logging
from ctypes import byref
from ctypes.wintypes import DWORD

logger = logging.getLogger(__name__)

# Service Access Rights
SC_MANAGER_ALL_ACCESS = 0xF003F
SERVICE_ALL_ACCESS = 0xF01FF
SERVICE_STOP = 0x0020
SERVICE_QUERY_STATUS = 0x0004

# Service Control Codes
SERVICE_CONTROL_STOP = 0x00000001

# Service State
SERVICE_STOPPED = 0x00000001
SERVICE_START_PENDING = 0x00000002
SERVICE_STOP_PENDING = 0x00000003
SERVICE_RUNNING = 0x00000004

class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", DWORD),
        ("dwCurrentState", DWORD),
        ("dwControlsAccepted", DWORD),
        ("dwWin32ExitCode", DWORD),
        ("dwServiceSpecificExitCode", DWORD),
        ("dwCheckPoint", DWORD),
        ("dwWaitHint", DWORD),
    ]

def _get_advapi32():
    try:
        return ctypes.windll.advapi32
    except (AttributeError, OSError):
        return None

def is_registered(service_name: str = "WinDivert") -> bool:
    """
    Check if the service is currently installed on the system using Win32 API.
    """
    advapi32 = _get_advapi32()
    if not advapi32:
        return False

    scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
    if not scm:
        return False

    try:
        service = advapi32.OpenServiceW(scm, service_name, SERVICE_QUERY_STATUS)
        if service:
            advapi32.CloseServiceHandle(service)
            return True
        return False
    finally:
        advapi32.CloseServiceHandle(scm)

def stop_service(service_name: str = "WinDivert") -> bool:
    """
    Stop the service using Win32 API.
    """
    advapi32 = _get_advapi32()
    if not advapi32:
        return False

    scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
    if not scm:
        return False

    try:
        service = advapi32.OpenServiceW(scm, service_name, SERVICE_STOP | SERVICE_QUERY_STATUS)
        if not service:
            return False

        try:
            status = SERVICE_STATUS()
            if not advapi32.ControlService(service, SERVICE_CONTROL_STOP, byref(status)):
                return False
            return True
        finally:
            advapi32.CloseServiceHandle(service)
    finally:
        advapi32.CloseServiceHandle(scm)
