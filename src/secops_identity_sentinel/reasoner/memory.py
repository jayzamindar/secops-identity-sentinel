"""
RAM Protection Safeguards & Memory Watchdog.

Monitors resident set size (RSS) against the 2048MB container ceiling (1750MB watermark)
and proactively drops active reasoning rounds upon hazard detection adhering to
GEMINI.md Sections 2 and 3.5.
"""

from __future__ import annotations

import logging
import os
import platform
from typing import Any

logger = logging.getLogger(__name__)


class RAMWatchdogBreachError(RuntimeError):
    """
    Raised when active process memory breaches the safety watermark (1750MB).
    """


def get_process_memory_mb() -> float:
    """
    Retrieve current process Resident Set Size (RSS) in megabytes.

    Cross-platform implementation utilizing native standard libraries:
    - Windows: ctypes K32GetProcessMemoryInfo on 64-bit kernel32
    - Linux / Docker: /proc/self/status VmRSS
    - macOS / BSD: resource.getrusage
    """
    system = platform.system().lower()

    # 1. Try psutil if available
    try:
        import importlib

        psutil = importlib.import_module("psutil")
        return float(psutil.Process().memory_info().rss / (1024.0 * 1024.0))
    except (ImportError, Exception):
        pass

    # 2. Windows implementation via ctypes kernel32
    if system == "windows":
        try:
            import ctypes
            import ctypes.wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.wintypes.DWORD),
                    ("PageFaultCount", ctypes.wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            windll = getattr(ctypes, "windll", None)
            if windll is not None:
                k32 = windll.kernel32
                k32.K32GetProcessMemoryInfo.argtypes = [
                    ctypes.wintypes.HANDLE,
                    ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
                    ctypes.wintypes.DWORD,
                ]
                k32.K32GetProcessMemoryInfo.restype = ctypes.wintypes.BOOL

                pmc = PROCESS_MEMORY_COUNTERS()
                pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
                handle = k32.GetCurrentProcess()
                if k32.K32GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb):
                    return float(pmc.WorkingSetSize / (1024.0 * 1024.0))
        except Exception as exc:
            logger.debug("Windows memory check failed: %s", exc)

    # 3. Linux / Docker container implementation via /proc/self/status
    if system == "linux" or os.path.exists("/proc/self/status"):
        try:
            with open("/proc/self/status", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        parts = line.split()
                        # VmRSS is reported in kB
                        return float(parts[1]) / 1024.0
        except Exception as exc:
            logger.debug("Linux /proc memory check failed: %s", exc)

    # 4. macOS / Unix implementation via resource module
    if system != "windows":
        try:
            import importlib

            res_mod: Any = importlib.import_module("resource")
            rusage_self = res_mod.RUSAGE_SELF
            usage = res_mod.getrusage(rusage_self).ru_maxrss
            # On macOS ru_maxrss is in bytes; on Linux it is in kilobytes
            if system == "darwin":
                return float(usage / (1024.0 * 1024.0))
            return float(usage / 1024.0)
        except Exception as exc:
            logger.debug("Resource memory check failed: %s", exc)

    # Fallback default baseline
    return 64.0


class RAMWatchdog:
    """
    Watches memory usage against the 2048MB container ceiling and 1750MB safety watermark.
    """

    def __init__(
        self,
        ram_ceiling_mb: float = 2048.0,
        watermark_mb: float = 1750.0,
        memory_provider: Any = None,
    ) -> None:
        self.ram_ceiling_mb: float = ram_ceiling_mb
        self.watermark_mb: float = watermark_mb
        self._memory_provider = memory_provider or get_process_memory_mb

    def get_current_mb(self) -> float:
        """Return current process memory in megabytes."""
        try:
            return float(self._memory_provider())
        except Exception:
            return 64.0

    def check_memory(self, prospective_buffer_mb: float = 0.0) -> float:
        """
        Check whether current memory + prospective buffer breaches safety watermark.

        Raises:
            RAMWatchdogBreachError: If memory watermark (1750MB) is breached.
        """
        current_mb = self.get_current_mb()
        projected_mb = current_mb + prospective_buffer_mb

        if projected_mb >= self.watermark_mb:
            msg = (
                f"RAM watchdog breach hazard: projected memory {projected_mb:.1f}MB "
                f"(current: {current_mb:.1f}MB + buffer: {prospective_buffer_mb:.1f}MB) "
                f"exceeds watermark {self.watermark_mb:.1f}MB of "
                f"{self.ram_ceiling_mb:.1f}MB ceiling."
            )
            logger.error(msg)
            raise RAMWatchdogBreachError(msg)

        return current_mb


__all__: list[str] = [
    "RAMWatchdogBreachError",
    "get_process_memory_mb",
    "RAMWatchdog",
]
