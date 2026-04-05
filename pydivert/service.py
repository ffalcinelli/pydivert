from __future__ import annotations

import ctypes
import logging
from ctypes import byref
from ctypes.wintypes import DWORD, LPCWSTR, HANDLE, BOOL

logger = logging.getLogger(__name__)

# Service Access Rights
SC_MANAGER_CONNECT = 0x0001
SERVICE_QUERY_STATUS = 0x0004
SERVICE_STOP = 0x0020

# Service Control Codes
SERVICE_CONTROL_STOP = 0x00000001

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
        advapi32 = ctypes.windll.advapi32
        
        advapi32.OpenSCManagerW.argtypes = [LPCWSTR, LPCWSTR, DWORD]
        advapi32.OpenSCManagerW.restype = HANDLE
        
        advapi32.OpenServiceW.argtypes = [HANDLE, LPCWSTR, DWORD]
        advapi32.OpenServiceW.restype = HANDLE
        
        advapi32.CloseServiceHandle.argtypes = [HANDLE]
        advapi32.CloseServiceHandle.restype = BOOL
        
        advapi32.ControlService.argtypes = [HANDLE, DWORD, ctypes.POINTER(SERVICE_STATUS)]
        advapi32.ControlService.restype = BOOL
        
        return advapi32
    except (AttributeError, OSError):
        return None

def is_registered(service_name: str = "WinDivert") -> bool:
    """
    Check if the service is currently installed on the system using Win32 API.
    """
    advapi32 = _get_advapi32()
    if not advapi32:
        return False

    scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
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

    scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
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
