"""
PureUninstaller
===============

A review-first Windows 11 desktop utility that launches an application's
official uninstaller, audits common per-user/per-machine data locations for
leftovers, and only then asks the user to choose exactly what may be removed.

Design principles
-----------------
* Nothing is deleted automatically. The vendor uninstaller is an explicit
  opt-in step, and every candidate path is shown before cleanup.
* Scanning and cleanup never follow symlinks/junctions found below a trusted
  cleanup root. A configured known-folder root may itself be redirected by
  Windows; the guard permits that only at the trusted root boundary.
* Cleanup is restricted to user-data roots, with a second, independent safety
  guard immediately before every delete operation.
* All registry and filesystem work runs on daemon worker threads. Tkinter is
  touched only from the Tk main thread through a queue.

Runtime
-------
Python 3.11+ (developed against Python 3.12), customtkinter 5.2.2,
Windows 10/11. No third-party packages other than customtkinter.

Build (PyInstaller, single-file, no console)
--------------------------------------------
    py -3.12 -m pip install customtkinter==5.2.2 pyinstaller
    py -3.12 -m PyInstaller --noconfirm --clean --onefile --windowed ^
        --name PureUninstaller --collect-all customtkinter pure_uninstaller.py

GitHub Actions can run the exact same command on windows-latest and upload
``dist/PureUninstaller.exe`` as an artifact. No icon or external data files are
needed, so the result is a self-contained, zero-asset executable.

Safety note
-----------
The app intentionally does not delete anything under Windows, Program Files,
System32, drive roots, or the Windows-known user folders. Per-user AppData,
ProgramData, user dot-folders, and explicitly matched HKCU\\Software keys are
the only cleanup domains.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
import queue
import re
import shutil
import stat
import string
import subprocess
import sys
import threading
import time
import unicodedata
import winreg
from collections import deque
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from difflib import SequenceMatcher
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence

import tkinter as tk
from tkinter import messagebox as tk_messagebox

try:
    import customtkinter as ctk
except ImportError as exc:  # pragma: no cover - dependency guard for source users
    raise SystemExit(
        "PureUninstaller requires customtkinter 5.2.2. "
        "Install it with: py -m pip install customtkinter==5.2.2"
    ) from exc


APP_NAME = "PureUninstaller"
APP_VERSION = "1.0.0"
APP_TAGLINE = "Review-first Windows cleanup"

# ---------------------------------------------------------------------------
# Palette and visual constants
# ---------------------------------------------------------------------------

BG = "#080D13"
SIDEBAR = "#0B121A"
PANEL = "#101923"
CARD = "#121D28"
CARD_HOVER = "#172432"
BORDER = "#1D2C3B"
BORDER_SOFT = "#16232F"
INPUT = "#091117"
TEXT = "#EAF2FA"
MUTED = "#8FA4B9"
FAINT = "#60768C"
ACCENT = "#22D3EE"
ACCENT_HOVER = "#06B6D4"
ACCENT_DARK = "#072A33"
BLUE = "#3B82F6"
ON_ACCENT = "#031318"
SUCCESS = "#34D399"
WARNING = "#FBBF24"
DANGER = "#F87171"
DANGER_HOVER = "#DC2626"
CHIP = "#172534"
CHIP_REG = "#1C2838"

FONT_DISPLAY = "Segoe UI Variable Display"
FONT_TEXT = "Segoe UI Variable Text"
FONT_MONO = "Cascadia Mono"

PAGE_SIZE = 40
MAX_LOG_LINES = 1500
EVENT_POLL_MS = 90

# ---------------------------------------------------------------------------
# Windows registry constants and lookup tables
# ---------------------------------------------------------------------------

UNINSTALL_ROOT = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
REG_VIEWS: tuple[tuple[int, str], ...] = (
    (winreg.KEY_WOW64_64KEY, "64-bit"),
    (winreg.KEY_WOW64_32KEY, "32-bit"),
)
REG_HIVES: tuple[tuple[int, str], ...] = (
    (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
    (winreg.HKEY_CURRENT_USER, "HKCU"),
)

UPDATE_RELEASE_TYPES = {
    "update",
    "hotfix",
    "security update",
    "servicepack",
    "service pack",
    "feature update",
}

UPDATE_NAME_RE = re.compile(
    r"^(?:(?:security\s+)?update\s+for|"
    r"(?:cumulative|feature|security|definition)\s+update\s+(?:for|to)|"
    r"hotfix\s+for|servicing\s+stack(?:\s+update)?)\b",
    re.IGNORECASE,
)
KB_NAME_RE = re.compile(r"^KB\d{6,}\b", re.IGNORECASE)
PRODUCT_CODE_RE = re.compile(
    r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}"
)

# Entries below these folders are OS-managed or security-sensitive. The
# scanner skips them, and SafetyGuard independently rejects them.
PROTECTED_COMPONENT_NAMES = {
    "microsoft",
    "windows",
    "windowsapps",
    "system32",
    "syswow64",
    "winsxs",
    "packages",
    "package cache",
    "programs",
    "temp",
    "connecteddevicesplatform",
    "comms",
    "d3dscache",
    "crashdumps",
    "usoprivate",
    "usoshared",
    "windows defender",
    "windows nt",
    "windows.old",
    "recovery",
    "system volume information",
    "installer",
    "packagestaging",
    "appreadiness",
    "microsoft office",
    "microsoft update",
}

SENSITIVE_USER_CONTAINERS = {
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
}

PROTECTED_USER_CONTAINERS = SENSITIVE_USER_CONTAINERS | {
    ".config",
    ".cache",
    ".local",
}

USER_KNOWN_FOLDER_NAMES = {
    "desktop",
    "documents",
    "downloads",
    "music",
    "pictures",
    "videos",
    "onedrive",
    "favorites",
    "links",
    "contacts",
    "searches",
    "saved games",
    "3d objects",
    "appdata",
    "ntuser.dat",
}

PROTECTED_REGISTRY_TOP_LEVEL = {
    "microsoft",
    "classes",
    "policies",
    "registeredapplications",
    "clients",
    "wow6432node",
    "windows",
    "setup",
    "microsoft\\windows",
}

FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
WAIT_FAILED = 0xFFFFFFFF
STILL_ACTIVE = 259

CREATE_NO_WINDOW = 0x08000000
SEE_MASK_NOCLOSEPROCESS = 0x00000040
SEE_MASK_NOASYNC = 0x00000100
SW_HIDE = 0
SW_SHOWNORMAL = 1

GENERIC_MATCH_WORDS = {
    "app",
    "apps",
    "application",
    "applications",
    "beta",
    "client",
    "codec",
    "component",
    "desktop",
    "driver",
    "edition",
    "enterprise",
    "free",
    "helper",
    "install",
    "installer",
    "launcher",
    "library",
    "manager",
    "only",
    "player",
    "premium",
    "professional",
    "program",
    "remove",
    "runtime",
    "service",
    "setup",
    "software",
    "standard",
    "studio",
    "suite",
    "system",
    "tool",
    "tools",
    "trial",
    "uninstall",
    "uninstaller",
    "update",
    "updater",
    "utility",
    "version",
    "windows",
    "x64",
    "x86",
    "64bit",
    "32bit",
    "64x",
    "32x",
}

VENDOR_NOISE_WORDS = {
    "the",
    "inc",
    "llc",
    "ltd",
    "gmbh",
    "corp",
    "corporation",
    "co",
    "company",
    "limited",
    "technologies",
    "technology",
    "systems",
    "software",
    "solutions",
    "group",
    "project",
    "team",
    "foundation",
    "labs",
    "studio",
}

# ---------------------------------------------------------------------------
# Environment paths
# ---------------------------------------------------------------------------


def _env_path(variable: str, fallback: str) -> Path:
    """Return an environment path without requiring it to already exist."""
    raw = os.environ.get(variable, "").strip()
    return Path(raw or fallback)


USERPROFILE_DIR = _env_path("USERPROFILE", str(Path.home()))
APPDATA_DIR = _env_path("APPDATA", str(USERPROFILE_DIR / "AppData" / "Roaming"))
LOCALAPPDATA_DIR = _env_path(
    "LOCALAPPDATA", str(USERPROFILE_DIR / "AppData" / "Local")
)
PROGRAMDATA_DIR = _env_path("PROGRAMDATA", r"C:\ProgramData")
# The task intentionally audits the standard LocalAppData Temp tree rather
# than an arbitrary redirected %TEMP% directory on another volume.
TEMP_DIR = LOCALAPPDATA_DIR / "Temp"
WINDOWS_DIR = _env_path("SystemRoot", r"C:\Windows")
PROGRAM_FILES_DIR = _env_path("ProgramFiles", r"C:\Program Files")
PROGRAM_FILES_X86_DIR = _env_path("ProgramFiles(x86)", r"C:\Program Files (x86)")
SYSTEM_DRIVE = os.environ.get("SystemDrive", "C:")


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def extended_path(value: os.PathLike[str] | str) -> str:
    """Prefix long paths for Win32 APIs without affecting display paths."""
    raw = os.path.abspath(os.fspath(value))
    if raw.startswith("\\\\?\\"):
        return raw
    if len(raw) < 248:
        return raw
    if raw.startswith("\\\\"):
        return "\\\\?\\UNC\\" + raw[2:]
    return "\\\\?\\" + raw


def stat_is_reparse(st: os.stat_result) -> bool:
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT) or stat.S_ISLNK(st.st_mode)


def is_reparse_point(value: os.PathLike[str] | str) -> bool:
    """Return True for links, junctions, or unreadable path attributes.

    A missing path is not a reparse point. Other inspection failures fail
    closed so the scanner never treats an unreadable directory as normal.
    """
    try:
        st = os.lstat(extended_path(value))
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return stat_is_reparse(st)


def canonical_path(value: os.PathLike[str] | str) -> str:
    """Return a normalized, link-resolved absolute path for guard checks."""
    raw = os.path.abspath(os.fspath(value))
    try:
        resolved = os.path.realpath(raw)
    except OSError:
        resolved = raw
    return os.path.normpath(resolved)


def path_equal(left: os.PathLike[str] | str, right: os.PathLike[str] | str) -> bool:
    return os.path.normcase(os.path.normpath(os.fspath(left))) == os.path.normcase(
        os.path.normpath(os.fspath(right))
    )


def path_is_within(
    child: os.PathLike[str] | str, parent: os.PathLike[str] | str
) -> bool:
    """Case-insensitive, boundary-safe Windows containment test."""
    child_n = os.path.normcase(os.path.normpath(os.fspath(child)))
    parent_n = os.path.normcase(os.path.normpath(os.fspath(parent)))
    if child_n == parent_n:
        return True
    try:
        return os.path.commonpath((child_n, parent_n)) == parent_n
    except (ValueError, OSError):
        return False


def human_size(size_bytes: int, unknown: str = "Unknown") -> str:
    if size_bytes is None or size_bytes < 0:
        return unknown
    if size_bytes == 0:
        return "0 B"
    units = ("B", "KB", "MB", "GB", "TB")
    value = float(size_bytes)
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}" if value < 100 else f"{value:.0f} {unit}"
        value /= 1024.0
    return f"{value:.1f} TB"


def pretty_date(iso_date: str) -> str:
    if not iso_date:
        return "Unknown"
    try:
        parsed = date.fromisoformat(iso_date)
        return parsed.strftime("%d %b %Y")
    except ValueError:
        return iso_date


def normalize_words(value: str) -> str:
    """Lowercase, strip diacritics, and collapse punctuation to spaces."""
    if not value:
        return ""
    text = unicodedata.normalize("NFKD", str(value)).casefold()
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = re.sub(r"[\W_]+", " ", text, flags=re.UNICODE)
    return re.sub(r"\s+", " ", text).strip()


def compact_key(value: str) -> str:
    """Compact normalized key used for conservative filename matching."""
    return re.sub(r"[\W_]+", "", normalize_words(value), flags=re.UNICODE)


def truncate_middle(value: str, limit: int = 96) -> str:
    if len(value) <= limit:
        return value
    left = (limit - 1) // 2
    right = limit - left - 1
    return f"{value[:left]}…{value[-right:]}"


def command_preview(argv: Sequence[str]) -> str:
    try:
        return subprocess.list2cmdline(list(argv))
    except (TypeError, ValueError):
        return " ".join(argv)


def safe_thread_name(prefix: str) -> str:
    return f"{prefix}-{int(time.time() * 1000) % 100000}"


def window_scale(window: tk.Misc) -> float:
    """Return customtkinter's DPI scale for a window, with a safe fallback."""
    try:
        value = float(ctk.ScalingTracker.get_window_scaling(window))
        if value > 0:
            return value
    except Exception:
        pass
    try:
        value = float(window._get_window_scaling())  # type: ignore[attr-defined]
        if value > 0:
            return value
    except Exception:
        pass
    return 1.0


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class InstalledApp:
    """A single, de-duplicated Windows uninstall registry record."""

    display_name: str
    publisher: str = ""
    version: str = ""
    install_date: str = ""
    date_source: str = "install"
    estimated_size_kb: int = 0
    uninstall_string: str = ""
    quiet_uninstall_string: str = ""
    install_location: str = ""
    display_icon: str = ""
    architecture: str = ""
    hive_name: str = ""
    registry_hive: int = field(default=0, repr=False)
    registry_path: str = ""
    registry_view: int = 0
    registry_view_name: str = ""
    product_code: str = ""

    @property
    def identity(self) -> str:
        return "|".join(
            (
                normalize_words(self.display_name),
                normalize_words(self.version),
                normalize_words(self.publisher),
                normalize_words(self.install_location),
            )
        )

    @property
    def reported_size_bytes(self) -> int:
        try:
            return max(0, int(self.estimated_size_kb)) * 1024
        except (TypeError, ValueError):
            return 0

    @property
    def has_uninstaller(self) -> bool:
        return bool(self.uninstall_string.strip() or self.quiet_uninstall_string.strip())

    @property
    def is_msi(self) -> bool:
        text = f"{self.uninstall_string} {self.quiet_uninstall_string}".casefold()
        return "msiexec" in text or bool(self.product_code)

    @property
    def size_text(self) -> str:
        if self.estimated_size_kb <= 0:
            return "Size not reported"
        return human_size(self.reported_size_bytes)


@dataclass
class LeftoverItem:
    """One audited leftover and the metadata needed to explain/delete it."""

    kind: str  # folder | file | registry
    path: str
    size_bytes: int
    category: str
    reason: str
    filesystem_path: Optional[Path] = None
    registry_path: str = ""
    registry_view: int = 0
    registry_view_name: str = ""

    @property
    def is_registry(self) -> bool:
        return self.kind == "registry"

    @property
    def size_text(self) -> str:
        if self.is_registry:
            return "Registry key"
        if self.size_bytes <= 0:
            return "0 B"
        return human_size(self.size_bytes)

    @property
    def kind_label(self) -> str:
        if self.is_registry:
            return "REGISTRY"
        return "FOLDER" if self.kind == "folder" else "FILE"

    @property
    def category_label(self) -> str:
        if self.is_registry and self.registry_view_name:
            return f"{self.category} · {self.registry_view_name}"
        return self.category


@dataclass
class ScanReport:
    app: InstalledApp
    items: list[LeftoverItem]
    warnings: list[str]
    elapsed_seconds: float
    still_registered: bool = False

    @property
    def total_bytes(self) -> int:
        return sum(item.size_bytes for item in self.items if not item.is_registry)


@dataclass
class CleanupFailure:
    path: str
    reason: str


@dataclass
class CleanupReport:
    deleted: list[LeftoverItem]
    failed: list[CleanupFailure]
    skipped: list[str]
    freed_bytes: int
    elapsed_seconds: float
    cancelled: bool = False


@dataclass
class UninstallReport:
    exit_code: Optional[int]
    error: str
    cancelled: bool
    elevated: bool
    registration_state: str  # removed | present | unknown
    elapsed_seconds: float
    command: str


# ---------------------------------------------------------------------------
# Safety guard
# ---------------------------------------------------------------------------


class SafetyGuard:
    """
    Independent, final-line-of-defense validation for every cleanup target.

    The scanner uses the same guard, but cleanup validates again immediately
    before deleting. A path must be strictly below one of the approved roots.
    Equality with any root, Windows directories, Program Files, drive roots, or
    known user folders is always rejected. Reparse points below a trusted root
    are rejected; the trusted root itself may be a redirected known folder.
    """

    def __init__(
        self,
        appdata: Optional[Path] = None,
        localappdata: Optional[Path] = None,
        programdata: Optional[Path] = None,
        userprofile: Optional[Path] = None,
        windows_dir: Optional[Path] = None,
        program_files: Optional[Path] = None,
        program_files_x86: Optional[Path] = None,
    ) -> None:
        self.appdata = Path(appdata or APPDATA_DIR)
        self.localappdata = Path(localappdata or LOCALAPPDATA_DIR)
        self.programdata = Path(programdata or PROGRAMDATA_DIR)
        self.userprofile = Path(userprofile or USERPROFILE_DIR)
        self.windows_dir = Path(windows_dir or WINDOWS_DIR)
        self.program_files = Path(program_files or PROGRAM_FILES_DIR)
        self.program_files_x86 = Path(program_files_x86 or PROGRAM_FILES_X86_DIR)
        self.temp = self.localappdata / "Temp"

        self.allowed_roots = (
            self.appdata,
            self.localappdata,
            self.programdata,
        )
        self._allowed_canonical = tuple(
            canonical_path(p) for p in self.allowed_roots
        )
        self.userprofile_canonical = canonical_path(self.userprofile)

        self.critical_paths = {
            canonical_path(self.windows_dir),
            canonical_path(self.windows_dir / "System32"),
            canonical_path(self.windows_dir / "SysWOW64"),
            canonical_path(self.program_files),
            canonical_path(self.program_files_x86),
            canonical_path(self.appdata),
            canonical_path(self.localappdata),
            canonical_path(self.localappdata / "Temp"),
            canonical_path(self.programdata),
            self.userprofile_canonical,
            canonical_path(self.userprofile / "Desktop"),
            canonical_path(self.userprofile / "Documents"),
            canonical_path(self.userprofile / "Downloads"),
            canonical_path(self.userprofile / "AppData"),
            canonical_path(self.userprofile / "OneDrive"),
            "C:\\",
            "C:\\Users",
        }
        for letter in string.ascii_uppercase:
            self.critical_paths.add(f"{letter}:\\")

        self.system_deny_subtrees = tuple(
            canonical_path(path)
            for path in (
                self.windows_dir,
                self.windows_dir / "System32",
                self.windows_dir / "SysWOW64",
                self.program_files,
                self.program_files_x86,
            )
        )

    # -- path validation ---------------------------------------------------

    def _under_allowed_root(self, canonical: str) -> Optional[Path]:
        for root, root_canonical in zip(self.allowed_roots, self._allowed_canonical):
            if path_is_within(canonical, root_canonical):
                return root
        return None

    @staticmethod
    def _strict_reparse_point(path: os.PathLike[str] | str) -> bool:
        """Fail closed if the attributes of an existing path cannot be read."""
        try:
            st = os.lstat(extended_path(path))
        except FileNotFoundError:
            return False
        except OSError:
            return True
        return stat_is_reparse(st)

    def _reparse_boundary(self, absolute: str) -> Optional[str]:
        """Choose the most specific trusted root for ancestor-link checks."""
        candidates = [os.path.abspath(os.fspath(root)) for root in self.allowed_roots]
        candidates.append(os.path.abspath(os.fspath(self.userprofile)))
        matching = [path for path in candidates if path_is_within(absolute, path)]
        if not matching:
            return None
        return max(matching, key=len)

    @classmethod
    def _has_reparse_ancestor(
        cls, path: str, boundary: Optional[str] = None
    ) -> bool:
        """Check parents below a trusted boundary (the boundary may be moved)."""
        try:
            current = os.path.abspath(path)
            boundary_abs = os.path.abspath(boundary) if boundary else None
            while True:
                parent = os.path.dirname(current)
                if path_equal(parent, current):
                    break
                if boundary_abs is not None and path_equal(parent, boundary_abs):
                    break
                if cls._strict_reparse_point(parent):
                    return True
                current = parent
        except (OSError, ValueError):
            return True
        return False

    def validate_path(
        self, value: os.PathLike[str] | str
    ) -> tuple[bool, str]:
        raw = os.fspath(value)
        if not raw or "\x00" in raw:
            return False, "Empty or invalid path."
        if self._strict_reparse_point(raw):
            return False, "Reparse points (symlinks/junctions) are never deleted."
        absolute = os.path.abspath(raw)
        if absolute.endswith(" ") or absolute.endswith("."):
            return False, "Paths ending in a space or dot are not allowed."
        if self._has_reparse_ancestor(
            absolute, self._reparse_boundary(absolute)
        ):
            return False, "A parent folder is a reparse point."
        canonical = canonical_path(absolute)

        # These subtrees are never cleanup domains, even if an environment
        # variable or a caller supplies a misleading root.
        for denied in self.system_deny_subtrees:
            if path_is_within(canonical, denied):
                return False, "Path is inside Windows or Program Files."

        # Absolute critical-path blocklist, checked before root containment.
        for critical in self.critical_paths:
            if path_equal(canonical, critical):
                return False, "This is a protected Windows/system location."
            if path_is_within(critical, canonical) and not path_is_within(
                canonical, critical
            ):
                return False, "This path contains a protected Windows location."

        root = self._under_allowed_root(canonical)
        if root is None:
            if path_is_within(canonical, self.userprofile_canonical):
                return self._validate_user_profile_path(canonical)
            return False, "Path is outside the approved user-data cleanup roots."
        if path_equal(canonical, canonical_path(root)):
            return False, "The root of an approved data folder cannot be deleted."

        rel = os.path.relpath(canonical, canonical_path(root))
        parts = [part for part in rel.split(os.sep) if part and part != "."]
        if not parts:
            return False, "The root of an approved data folder cannot be deleted."

        first = parts[0].casefold()
        is_local_temp = (
            first == "temp"
            and path_equal(canonical_path(root), canonical_path(self.localappdata))
        )
        if first in PROTECTED_COMPONENT_NAMES and not is_local_temp:
            return False, f"“{parts[0]}” is a protected system component."
        sensitive_names = {name.casefold() for name in SENSITIVE_USER_CONTAINERS}
        if any(part.casefold() in sensitive_names for part in parts):
            return False, "This is a sensitive credential/configuration folder."

        # ProgramData and AppData have extra folder-specific safeguards.
        if path_equal(canonical_path(root), canonical_path(self.programdata)):
            if first in {
                "microsoft",
                "packages",
                "package cache",
                "windows",
                "windows defender",
                "windows nt",
                "usoprivate",
                "usoshared",
                "recovery",
                "system volume information",
                "packagestaging",
                "appreadiness",
            }:
                return False, "This ProgramData component belongs to Windows."
        if path_equal(canonical_path(root), canonical_path(self.localappdata)):
            if first in {
                "microsoft",
                "packages",
                "programs",
                "connecteddevicesplatform",
                "comms",
                "d3dscache",
                "crashdumps",
                "packagestaging",
            }:
                return False, "This LocalAppData component belongs to Windows."
            if first == "temp":
                if len(parts) < 2:
                    return False, "The entire Temp directory cannot be deleted."
                if parts[1].casefold() in {
                    "microsoft",
                    "windows",
                    "packages",
                    "windowsapps",
                    "system32",
                    "syswow64",
                }:
                    return False, "This Temp component is protected."
        if path_equal(canonical_path(root), canonical_path(self.appdata)):
            if first in {"microsoft", "packages", "temp"}:
                return False, "This Roaming AppData component is protected."

        return True, ""

    def _validate_user_profile_path(self, canonical: str) -> tuple[bool, str]:
        if path_equal(canonical, self.userprofile_canonical):
            return False, "The user profile root cannot be deleted."
        rel = os.path.relpath(canonical, self.userprofile_canonical)
        parts = [part for part in rel.split(os.sep) if part and part != "."]
        if not parts:
            return False, "The user profile root cannot be deleted."
        first = parts[0]
        if not first.startswith("."):
            return False, "Only dot-folders/files at the profile root are eligible."
        if first.casefold() in USER_KNOWN_FOLDER_NAMES:
            return False, "This is a known user folder and is protected."
        sensitive_names = {name.casefold() for name in SENSITIVE_USER_CONTAINERS}
        if any(part.casefold() in sensitive_names for part in parts):
            return False, "This path is inside a sensitive user security store."
        if path_equal(canonical, canonical_path(self.userprofile / first)):
            if first.casefold() in {name.casefold() for name in PROTECTED_USER_CONTAINERS}:
                return False, "This dot-folder is a shared configuration container."
        return True, ""

    def validate_registry_key(self, key_path: str) -> tuple[bool, str]:
        if not key_path or "\x00" in key_path:
            return False, "Empty registry path."
        parts = [part for part in key_path.split("\\") if part]
        if len(parts) < 2:
            return False, "Broad registry roots cannot be deleted."
        if parts[0].casefold() != "software":
            return False, "Only HKCU\\Software application keys are eligible."
        if any(part.strip() in {".", ".."} for part in parts):
            return False, "Invalid registry path."
        for part in parts:
            if part.casefold() in PROTECTED_REGISTRY_TOP_LEVEL:
                return False, "This is a protected Windows registry component."
        return True, ""

    def validate_item(self, item: LeftoverItem) -> tuple[bool, str]:
        if item.is_registry:
            return self.validate_registry_key(item.registry_path)
        candidate = item.filesystem_path or Path(item.path)
        return self.validate_path(candidate)

    def describe_roots(self) -> str:
        return " · ".join(str(root) for root in self.allowed_roots)


# ---------------------------------------------------------------------------
# Matching profile
# ---------------------------------------------------------------------------


class MatchingProfile:
    """
    Conservative name-matching profile.

    Publisher names are used only to *descend into* a vendor container; an
    entire publisher directory is never selected merely because its publisher
    matches. Actual artifacts must match the product name or a derived
    executable/install-folder alias.
    """

    def __init__(self, app: InstalledApp) -> None:
        self.app = app
        self.display_name = app.display_name
        self.primary_terms: set[str] = set()
        self.token_terms: set[str] = set()
        self.vendor_terms: set[str] = set()
        self._build_terms()

    @staticmethod
    def _clean_product_name(name: str) -> str:
        text = str(name or "")
        text = re.sub(r"\((?:remove only|64-bit|32-bit|x64|x86)\)\s*$", "", text, flags=re.I)
        text = re.sub(
            r"\s+(?:version\s+)?v?\d+(?:[.\-_]\d+)*(?:\+[\w.\-]+)?\s*$",
            "",
            text,
            flags=re.I,
        )
        text = re.sub(r"[®™©]", " ", text)
        return re.sub(r"\s+", " ", text).strip()

    @staticmethod
    def _clean_publisher(publisher: str) -> str:
        text = re.sub(r"[®™©]", " ", str(publisher or ""))
        words = normalize_words(text).split()
        words = [word for word in words if word not in VENDOR_NOISE_WORDS]
        return " ".join(words)

    def _add_primary(self, value: str) -> None:
        term = compact_key(value)
        if len(term) >= 3 and term not in GENERIC_MATCH_WORDS:
            self.primary_terms.add(term)

    def _add_token(self, value: str) -> None:
        term = compact_key(value)
        if (
            len(term) >= 4
            and term not in GENERIC_MATCH_WORDS
            and term not in self.primary_terms
        ):
            self.token_terms.add(term)

    def _build_terms(self) -> None:
        cleaned_name = self._clean_product_name(self.display_name)
        publisher_clean = self._clean_publisher(self.app.publisher)

        self._add_primary(cleaned_name)
        self._add_primary(self.display_name)

        publisher_words = set(publisher_clean.split())
        name_without_publisher = " ".join(
            word
            for word in normalize_words(cleaned_name).split()
            if word not in publisher_words
        )
        if name_without_publisher:
            self._add_primary(name_without_publisher)
            for word in name_without_publisher.split():
                self._add_token(word)

        if self.app.install_location:
            self._add_primary(Path(self.app.install_location).name)

        exe_stem = self._executable_stem()
        if exe_stem:
            self._add_primary(exe_stem)
            self._add_token(exe_stem)

        key_tail = self.app.registry_path.rsplit("\\", 1)[-1]
        if key_tail and not PRODUCT_CODE_RE.fullmatch(key_tail):
            key_tail = re.sub(r"(?:_is1|-is1)$", "", key_tail, flags=re.I)
            self._add_primary(key_tail)

        if publisher_clean:
            vendor = compact_key(publisher_clean)
            if len(vendor) >= 3:
                self.vendor_terms.add(vendor)
            for word in publisher_clean.split():
                token = compact_key(word)
                if len(token) >= 3 and token not in GENERIC_MATCH_WORDS:
                    self.vendor_terms.add(token)

        # Publishing-house folder names are traversal hints, never cleanup
        # targets. Do not let an install-folder basename such as
        # "Epic Games" cause the entire publisher container to be selected.
        full_app_key = compact_key(cleaned_name)
        self.primary_terms = {
            term
            for term in self.primary_terms
            if term == full_app_key or term not in self.vendor_terms
        }
        self.token_terms = {
            term
            for term in self.token_terms
            if term == full_app_key or term not in self.vendor_terms
        }

    def _executable_stem(self) -> str:
        candidates: list[str] = []
        if self.app.display_icon:
            icon = self.app.display_icon.strip().strip('"')
            icon = icon.split(",", 1)[0].strip().strip('"')
            candidates.append(icon)
        if self.app.uninstall_string:
            try:
                parsed = split_windows_command_line(self.app.uninstall_string)
            except ValueError:
                parsed = []
            if parsed:
                candidates.append(parsed[0])
        for candidate in candidates:
            name = Path(os.path.expandvars(candidate)).name
            stem = compact_key(Path(name).stem)
            if (
                stem
                and len(stem) >= 3
                and stem not in GENERIC_MATCH_WORDS
                and not stem.startswith("unins")
                and stem not in {"msiexec", "rundll32", "regsvr32"}
            ):
                return stem
        return ""

    def matches_vendor(self, name: str) -> bool:
        candidate = compact_key(name)
        if len(candidate) < 3:
            return False
        if normalize_words(name).casefold() in PROTECTED_COMPONENT_NAMES:
            return False
        for vendor in self.vendor_terms:
            if candidate == vendor or candidate.startswith(vendor):
                return True
        return False

    def match_artifact(self, name: str, is_file: bool = False) -> Optional[str]:
        lookup_name = Path(name).stem if is_file else name
        candidate = compact_key(lookup_name)
        if len(candidate) < 3:
            return None

        for term in self.primary_terms:
            if candidate == term:
                return "Matched product name"
            if len(term) >= 5 and (candidate.startswith(term) or candidate.endswith(term)):
                return "Matched product name"
            if len(term) >= 5 and term in candidate:
                return "Contains product name"
            if (
                len(candidate) >= 5
                and term.startswith(candidate)
                and len(candidate) / max(1, len(term)) >= 0.6
            ):
                return "Matched shortened product name"

        for term in self.token_terms:
            if candidate == term:
                return "Matched name alias"
            if len(term) >= 5 and (candidate.startswith(term) or term in candidate):
                return "Matched name alias"

        # Dot-files such as .gitconfig are often named "<alias><suffix>".
        if is_file and name.startswith("."):
            for term in self.primary_terms | self.token_terms:
                if len(term) >= 3 and candidate.startswith(term):
                    return "Matched dot-file alias"
        return None

    def match_exact(self, name: str) -> Optional[str]:
        """Exact compact-name match, used for broad registry top-level keys."""
        candidate = re.sub(
            r"(?:_is1|-is1)$", "", compact_key(name), flags=re.IGNORECASE
        )
        if len(candidate) < 3:
            return None
        if candidate in self.primary_terms:
            return "Matched product name exactly"
        if candidate in self.token_terms:
            return "Matched name alias exactly"
        return None


# ---------------------------------------------------------------------------
# Registry discovery
# ---------------------------------------------------------------------------


def _registry_string(key: int, name: str, default: str = "") -> str:
    try:
        value, value_type = winreg.QueryValueEx(key, name)
    except OSError:
        return default
    if value_type in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
        return str(value).strip()
    if value_type in (winreg.REG_DWORD, winreg.REG_QWORD):
        return str(int(value))
    return str(value).strip() if value is not None else default


def _registry_int(key: int, name: str, default: int = 0) -> int:
    try:
        value, _ = winreg.QueryValueEx(key, name)
        return int(value)
    except (OSError, TypeError, ValueError):
        return default


def _registry_last_write_iso(key: int) -> str:
    try:
        last_write = winreg.QueryInfoKey(key)[2]
        if not last_write:
            return ""
        stamp = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
            microseconds=last_write // 10
        )
        return stamp.astimezone().date().isoformat()
    except (OSError, OverflowError, ValueError):
        return ""


def _normalize_install_date(raw: str, fallback: str) -> tuple[str, str]:
    raw = (raw or "").strip()
    if re.fullmatch(r"\d{8}", raw):
        try:
            return datetime.strptime(raw, "%Y%m%d").date().isoformat(), "install"
        except ValueError:
            pass
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        return raw, "install"
    return (fallback, "modified") if fallback else ("", "install")


def _extract_product_code(record: InstalledApp, key_name: str) -> str:
    if PRODUCT_CODE_RE.fullmatch(key_name or ""):
        return key_name.upper()
    match = PRODUCT_CODE_RE.search(record.uninstall_string or "")
    if match:
        return match.group(0).upper()
    match = PRODUCT_CODE_RE.search(record.quiet_uninstall_string or "")
    return match.group(0).upper() if match else ""


def _has_uninstaller_strings(uninstall: str, quiet: str) -> bool:
    return bool(uninstall.strip() or quiet.strip())


def _is_system_or_update(
    display_name: str,
    system_component: int,
    no_remove: int,
    parent_key: str,
    release_type: str,
    uninstall: str,
    quiet: str,
) -> bool:
    if system_component:
        return True
    if no_remove:
        return True
    if parent_key:
        return True
    if release_type.strip().casefold() in UPDATE_RELEASE_TYPES:
        return True
    if UPDATE_NAME_RE.match(display_name) or KB_NAME_RE.match(display_name):
        return True
    if not _has_uninstaller_strings(uninstall, quiet):
        return True
    return False


def _merge_app(existing: InstalledApp, incoming: InstalledApp) -> InstalledApp:
    """Fill gaps in a duplicate record without changing its source identity."""
    for attr in (
        "publisher",
        "version",
        "install_date",
        "uninstall_string",
        "quiet_uninstall_string",
        "install_location",
        "display_icon",
        "architecture",
        "product_code",
    ):
        if not getattr(existing, attr) and getattr(incoming, attr):
            setattr(existing, attr, getattr(incoming, attr))
    if existing.estimated_size_kb <= 0 and incoming.estimated_size_kb > 0:
        existing.estimated_size_kb = incoming.estimated_size_kb
    if incoming.install_date and incoming.date_source == "install":
        if not existing.install_date or existing.date_source != "install":
            existing.install_date = incoming.install_date
            existing.date_source = "install"
    return existing


def enumerate_installed_apps(
    cancel_event: Optional[threading.Event] = None,
    status_callback: Optional[Callable[[str], None]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
) -> list[InstalledApp]:
    """Read all user-uninstallable programs from the three registry scopes."""
    records: dict[str, InstalledApp] = {}
    status = status_callback or (lambda _message: None)
    log = log_callback or (lambda _message: None)

    for hive, hive_name in REG_HIVES:
        for view_flag, view_name in REG_VIEWS:
            if cancel_event is not None and cancel_event.is_set():
                return sorted(records.values(), key=lambda item: item.display_name.casefold())
            access = winreg.KEY_READ | view_flag
            try:
                root = winreg.OpenKey(hive, UNINSTALL_ROOT, 0, access)
            except OSError as exc:
                log(f"{hive_name} {view_name} uninstall root unavailable: {exc}")
                continue

            try:
                subkey_count = winreg.QueryInfoKey(root)[0]
                status(
                    f"Reading {hive_name} {view_name} registry ({subkey_count} records)…"
                )
                for index in range(subkey_count):
                    if cancel_event is not None and cancel_event.is_set():
                        break
                    try:
                        key_name = winreg.EnumKey(root, index)
                    except OSError:
                        continue
                    try:
                        subkey = winreg.OpenKey(root, key_name, 0, access)
                    except OSError:
                        continue

                    with subkey:
                        display_name = _registry_string(subkey, "DisplayName")
                        if not display_name:
                            continue
                        system_component = _registry_int(subkey, "SystemComponent")
                        no_remove = _registry_int(subkey, "NoRemove")
                        parent_key = _registry_string(subkey, "ParentKeyName")
                        release_type = _registry_string(subkey, "ReleaseType")
                        uninstall = _registry_string(subkey, "UninstallString")
                        quiet = _registry_string(subkey, "QuietUninstallString")
                        if _is_system_or_update(
                            display_name,
                            system_component,
                            no_remove,
                            parent_key,
                            release_type,
                            uninstall,
                            quiet,
                        ):
                            continue

                        key_tail = key_name
                        fallback_date = _registry_last_write_iso(subkey)
                        install_date, date_source = _normalize_install_date(
                            _registry_string(subkey, "InstallDate"), fallback_date
                        )
                        install_location = _registry_string(subkey, "InstallLocation")
                        program_files_x86 = str(PROGRAM_FILES_X86_DIR).casefold()
                        architecture = view_name
                        if install_location:
                            if program_files_x86 in install_location.casefold():
                                architecture = "32-bit"
                            elif "program files" in install_location.casefold():
                                architecture = "64-bit"

                        record = InstalledApp(
                            display_name=display_name,
                            publisher=_registry_string(subkey, "Publisher"),
                            version=_registry_string(subkey, "DisplayVersion"),
                            install_date=install_date,
                            date_source=date_source,
                            estimated_size_kb=_registry_int(subkey, "EstimatedSize"),
                            uninstall_string=uninstall,
                            quiet_uninstall_string=quiet,
                            install_location=install_location,
                            display_icon=_registry_string(subkey, "DisplayIcon"),
                            architecture=architecture,
                            hive_name=hive_name,
                            registry_hive=hive,
                            registry_path=f"{UNINSTALL_ROOT}\\{key_name}",
                            registry_view=view_flag,
                            registry_view_name=view_name,
                        )
                        record.product_code = _extract_product_code(record, key_tail)
                        identity = record.identity
                        if identity in records:
                            records[identity] = _merge_app(records[identity], record)
                        else:
                            records[identity] = record
            finally:
                try:
                    winreg.CloseKey(root)
                except OSError:
                    pass

    status("Sorting discovered applications…")
    result = sorted(records.values(), key=lambda item: item.display_name.casefold())
    log(f"Registry discovery complete: {len(result)} user-uninstallable programs.")
    return result


def registry_entry_exists(app: InstalledApp) -> Optional[bool]:
    """Return True/False, or None when the key cannot be inspected."""
    try:
        key = winreg.OpenKey(
            app.registry_hive,
            app.registry_path,
            0,
            winreg.KEY_READ | app.registry_view,
        )
    except FileNotFoundError:
        return False
    except OSError:
        return None
    else:
        try:
            winreg.CloseKey(key)
        except OSError:
            pass
        return True


def wait_for_registration_removal(
    app: InstalledApp,
    grace_seconds: float = 3.0,
    status_callback: Optional[Callable[[str], None]] = None,
) -> str:
    """Poll briefly for the uninstall key; returns removed/present/unknown."""
    status = status_callback or (lambda _message: None)
    deadline = time.monotonic() + max(0.0, grace_seconds)
    state: Optional[bool] = registry_entry_exists(app)
    if state is False:
        return "removed"
    if state is None:
        return "unknown"
    if grace_seconds > 0:
        status("Uninstaller exited; waiting for the registry entry to disappear…")
    while time.monotonic() < deadline:
        time.sleep(0.35)
        state = registry_entry_exists(app)
        if state is False:
            return "removed"
        if state is None:
            return "unknown"
    return "present"


# ---------------------------------------------------------------------------
# Command-line parsing and uninstaller execution
# ---------------------------------------------------------------------------


def split_windows_command_line(command: str) -> list[str]:
    """Parse a Windows command line using the shell's own parser."""
    text = str(command or "").strip()
    if not text:
        return []
    try:
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        shell32.CommandLineToArgvW.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_int),
        ]
        shell32.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
        argc = ctypes.c_int(0)
        argv = shell32.CommandLineToArgvW(text, ctypes.byref(argc))
        if not argv:
            raise ValueError("Windows could not parse the command line.")
        try:
            result = [argv[i] for i in range(argc.value)]
        finally:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.LocalFree.restype = ctypes.c_void_p
            kernel32.LocalFree(argv)
        if result:
            return result
    except (OSError, ValueError):
        pass

    # Very defensive fallback. This is only reached if CommandLineToArgvW
    # fails on a malformed registry string.
    tokens = re.findall(r'"([^"]*)"|(\S+)', text)
    return [first or second for first, second in tokens if (first or second)]


def _expand_argv(argv: Sequence[str]) -> list[str]:
    return [os.path.expandvars(str(part)) for part in argv]


def _resolve_executable(executable: str) -> Optional[str]:
    if not executable:
        return None
    expanded = os.path.expandvars(executable)
    if os.path.isabs(expanded):
        return expanded if os.path.isfile(expanded) else None
    if "\\" in expanded or "/" in expanded:
        candidate = os.path.abspath(expanded)
        return candidate if os.path.isfile(candidate) else None
    found = shutil.which(expanded)
    if found:
        return found
    if expanded.casefold() in {"msiexec", "msiexec.exe"}:
        candidate = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "msiexec.exe")
        return candidate if os.path.isfile(candidate) else None
    return None


def _repair_unquoted_executable(argv: list[str], original: str) -> list[str]:
    """Recover common uninstall strings that forget to quote a spaced path."""
    if not argv or original.lstrip().startswith('"'):
        return argv
    first = os.path.expandvars(argv[0])
    if os.path.isfile(first):
        return argv
    stripped = original.lstrip()
    if not (re.match(r"^[A-Za-z]:\\", stripped) or stripped.startswith("\\\\")):
        return argv
    for end in range(len(argv), 0, -1):
        candidate = " ".join(argv[:end])
        if candidate.casefold().endswith(".exe") and os.path.isfile(os.path.expandvars(candidate)):
            return [os.path.expandvars(candidate), *argv[end:]]
    return argv


def build_uninstall_argv(app: InstalledApp, mode: str) -> tuple[list[str], str]:
    """
    Build the exact argv for interactive or quiet removal.

    Returns (argv, source_label). Raises ValueError with a user-facing reason.
    """
    if mode not in {"interactive", "quiet"}:
        raise ValueError("Unknown uninstall mode.")

    command = app.uninstall_string if mode == "interactive" else app.quiet_uninstall_string
    source = "Official UninstallString" if mode == "interactive" else "Vendor QuietUninstallString"
    if not command and mode == "quiet" and app.product_code:
        command = f'msiexec.exe /x {app.product_code} /qn /norestart'
        source = "Windows Installer quiet removal"

    if not command.strip():
        raise ValueError("The application did not publish a usable uninstall command.")

    argv = _expand_argv(split_windows_command_line(command))
    argv = _repair_unquoted_executable(argv, command)
    if not argv:
        raise ValueError("The uninstall command could not be parsed.")

    resolved = _resolve_executable(argv[0])
    if resolved:
        argv[0] = resolved
    elif os.path.isabs(argv[0]):
        raise ValueError(f"The uninstaller executable no longer exists: {argv[0]}")
    return argv, source


def quiet_uninstall_available(app: InstalledApp) -> bool:
    return bool(app.quiet_uninstall_string.strip() or app.product_code)


def _process_working_directory(app: InstalledApp, executable: str) -> Optional[str]:
    candidates = [app.install_location]
    if os.path.dirname(executable):
        candidates.append(os.path.dirname(executable))
    for candidate in candidates:
        if not candidate:
            continue
        try:
            expanded = os.path.expandvars(candidate)
            if os.path.isdir(expanded):
                return expanded
        except OSError:
            continue
    return None


class _SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIcon", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


def _run_elevated_and_wait(
    argv: Sequence[str],
    cwd: Optional[str],
    quiet: bool,
    status_callback: Optional[Callable[[str], None]] = None,
) -> tuple[Optional[int], str, bool]:
    """Launch via ShellExecuteExW(runas), preserving exit-code monitoring."""
    status = status_callback or (lambda _message: None)
    if not argv:
        return None, "No command to launch.", False
    executable = _resolve_executable(argv[0]) or argv[0]
    executable = os.path.abspath(executable) if os.path.dirname(executable) else executable
    parameters = subprocess.list2cmdline(list(argv[1:])) if len(argv) > 1 else None

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(_SHELLEXECUTEINFOW)]
    shell32.ShellExecuteExW.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    info = _SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(_SHELLEXECUTEINFOW)
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
    info.lpVerb = "runas"
    info.lpFile = executable
    info.lpParameters = parameters
    info.lpDirectory = cwd
    info.nShow = SW_HIDE if quiet else SW_SHOWNORMAL

    status("Waiting for Windows elevation (UAC)…")
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        error_code = ctypes.get_last_error()
        if error_code == 1223:
            return None, "Elevation was cancelled by the user.", True
        return None, f"Windows could not start the elevated uninstaller (error {error_code}).", False

    handle = info.hProcess
    if not handle:
        return None, "Windows did not return a process handle.", False

    status("Elevated uninstaller is running…")
    start = time.monotonic()
    last_update = start
    try:
        while True:
            result = kernel32.WaitForSingleObject(handle, 250)
            if result == WAIT_OBJECT_0:
                break
            if result == WAIT_FAILED:
                return None, "Waiting for the uninstaller failed.", False
            now = time.monotonic()
            if now - last_update >= 8.0:
                elapsed = int(now - start)
                status(f"Waiting for the elevated uninstaller… {elapsed}s")
                last_update = now
        exit_code = wintypes.DWORD(STILL_ACTIVE)
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return None, "The uninstaller exited but its exit code could not be read.", False
        return int(exit_code.value), "", False
    finally:
        try:
            kernel32.CloseHandle(handle)
        except OSError:
            pass


def run_uninstaller(
    app: InstalledApp,
    mode: str,
    elevated: bool,
    status_callback: Optional[Callable[[str], None]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
) -> UninstallReport:
    """Run the official uninstaller and wait for its exit code."""
    status = status_callback or (lambda _message: None)
    log = log_callback or (lambda _message: None)
    started = time.monotonic()

    try:
        argv, source = build_uninstall_argv(app, mode)
    except ValueError as exc:
        return UninstallReport(
            None, str(exc), False, elevated, "unknown", 0.0, ""
        )

    preview = command_preview(argv)
    log(f"{source}: {preview}")
    cwd = _process_working_directory(app, argv[0])

    if elevated:
        status("Requesting administrator privileges (UAC)…")
        code, error, cancelled = _run_elevated_and_wait(argv, cwd, mode == "quiet", status)
        elapsed = time.monotonic() - started
        if error:
            return UninstallReport(
                code, error, cancelled, True, "unknown", elapsed, preview
            )
        state = wait_for_registration_removal(app, 3.0, status)
        return UninstallReport(int(code or 0), "", False, True, state, elapsed, preview)

    status("Launching the vendor uninstaller…")
    creation_flags = CREATE_NO_WINDOW if mode == "quiet" else 0
    try:
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            shell=False,
            close_fds=True,
            creationflags=creation_flags,
            env=os.environ.copy(),
        )
    except OSError as exc:
        winerror = getattr(exc, "winerror", None)
        if winerror == 740:
            log("Windows requires elevation; retrying through the UAC broker.")
            code, error, cancelled = _run_elevated_and_wait(
                argv, cwd, mode == "quiet", status
            )
            elapsed = time.monotonic() - started
            if error:
                return UninstallReport(
                    code, error, cancelled, True, "unknown", elapsed, preview
                )
            state = wait_for_registration_removal(app, 3.0, status)
            return UninstallReport(
                int(code or 0), "", False, True, state, elapsed, preview
            )
        elapsed = time.monotonic() - started
        message = f"Could not launch the uninstaller: {exc}"
        if winerror:
            message += f" (Windows error {winerror})"
        return UninstallReport(None, message, False, False, "unknown", elapsed, preview)

    log(f"Uninstaller process started (PID {proc.pid}). Waiting for exit code…")
    start = time.monotonic()
    last_update = start
    while True:
        return_code = proc.poll()
        if return_code is not None:
            break
        now = time.monotonic()
        if now - last_update >= 8.0:
            elapsed_int = int(now - start)
            status(f"Uninstaller is running… {elapsed_int}s elapsed")
            last_update = now
        time.sleep(0.25)

    log(f"Uninstaller process exited with code {return_code}.")
    state = wait_for_registration_removal(app, 3.0, status)
    return UninstallReport(
        int(return_code),
        "",
        False,
        False,
        state,
        time.monotonic() - started,
        preview,
    )


# ---------------------------------------------------------------------------
# Leftover scanner
# ---------------------------------------------------------------------------


def _safe_scandir(path: Path) -> list[os.DirEntry[str]]:
    try:
        with os.scandir(extended_path(path)) as iterator:
            return list(iterator)
    except OSError:
        return []


def _entry_is_directory(entry: os.DirEntry[str]) -> bool:
    try:
        if entry.is_symlink() or is_reparse_point(entry.path):
            return False
        return entry.is_dir(follow_symlinks=False)
    except OSError:
        return False


def measure_path(
    path: Path,
    cancel_event: Optional[threading.Event] = None,
    limit_entries: int = 0,
) -> int:
    """Compute logical bytes without following links; best-effort on errors."""
    if cancel_event is not None and cancel_event.is_set():
        return 0
    try:
        st = os.lstat(extended_path(path))
    except OSError:
        return 0
    if stat_is_reparse(st):
        return 0
    if not stat.S_ISDIR(st.st_mode):
        return max(0, int(st.st_size))

    total = 0
    visited = 0
    for entry in _safe_scandir(path):
        if cancel_event is not None and cancel_event.is_set():
            break
        if entry.is_symlink() or is_reparse_point(entry.path):
            continue
        try:
            if entry.is_dir(follow_symlinks=False):
                total += measure_path(Path(entry.path), cancel_event)
            else:
                total += max(0, int(entry.stat(follow_symlinks=False).st_size))
        except OSError:
            continue
        visited += 1
        if limit_entries and visited >= limit_entries:
            break
    return total


class LeftoverScanner:
    """Finds only conservative, name-correlated artifacts under safe roots."""

    def __init__(
        self,
        app: InstalledApp,
        guard: SafetyGuard,
        cancel_event: Optional[threading.Event] = None,
        status_callback: Optional[Callable[[str], None]] = None,
        log_callback: Optional[Callable[[str], None]] = None,
        still_registered: bool = False,
    ) -> None:
        self.app = app
        self.guard = guard
        self.cancel_event = cancel_event or threading.Event()
        self.status = status_callback or (lambda _message: None)
        self.log = log_callback or (lambda _message: None)
        self.still_registered = still_registered
        self.profile = MatchingProfile(app)
        self.items: list[LeftoverItem] = []
        self.warnings: list[str] = []
        self._seen_paths: set[str] = set()
        self._seen_registry: set[tuple[str, int]] = set()

    # -- public entry point ------------------------------------------------

    def scan(self) -> ScanReport:
        started = time.monotonic()
        self.log(
            f"Starting leftover audit for “{self.app.display_name}” "
            f"(publisher: {self.app.publisher or 'unknown'})."
        )
        targets = [
            (APPDATA_DIR, "Roaming AppData", 2, True, True),
            (LOCALAPPDATA_DIR, "Local AppData", 2, True, True),
            (TEMP_DIR, "Local Temp", 1, False, False),
            (PROGRAMDATA_DIR, "ProgramData", 2, True, True),
        ]
        for root, category, max_depth, allow_vendor, trusted_root in targets:
            if self.cancel_event.is_set():
                break
            self.status(f"Auditing {category}…")
            try:
                self._scan_container(
                    root,
                    category,
                    max_depth,
                    allow_vendor,
                    trusted_root=trusted_root,
                )
                self.log(f"{category}: {len(self.items)} total candidate(s) so far.")
            except Exception as exc:  # defensive: one root must not kill the audit
                message = f"{category} could not be fully scanned: {exc}"
                self.warnings.append(message)
                self.log(message)

        if not self.cancel_event.is_set():
            self.status("Auditing the user profile…")
            try:
                self._scan_user_profile()
                self.log("User profile dot-folders: audit complete.")
            except Exception as exc:
                message = f"User profile could not be fully scanned: {exc}"
                self.warnings.append(message)
                self.log(message)

        if not self.cancel_event.is_set():
            self.status("Auditing HKCU\\Software…")
            try:
                self._scan_registry()
                self.log("HKCU\\Software: audit complete.")
            except Exception as exc:
                message = f"HKCU\\Software could not be fully scanned: {exc}"
                self.warnings.append(message)
                self.log(message)

        self._deduplicate_items()
        category_order = {
            "Roaming AppData": 0,
            "Local AppData": 1,
            "Local Temp": 2,
            "ProgramData": 3,
            "User profile": 4,
            "User registry": 5,
        }
        self.items.sort(
            key=lambda item: (
                category_order.get(item.category, 99),
                item.path.casefold(),
            )
        )
        total = sum(item.size_bytes for item in self.items if not item.is_registry)
        self.status(
            f"Audit complete: {len(self.items)} candidate(s), {human_size(total)}."
        )
        self.log(
            f"Audit finished in {time.monotonic() - started:.1f}s: "
            f"{len(self.items)} candidate(s), {human_size(total)}."
        )
        return ScanReport(
            app=self.app,
            items=self.items,
            warnings=self.warnings,
            elapsed_seconds=time.monotonic() - started,
            still_registered=self.still_registered,
        )

    # -- shared helpers ----------------------------------------------------

    def _cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def _add_path(
        self,
        path: Path,
        category: str,
        reason: str,
        kind: Optional[str] = None,
    ) -> None:
        if self._cancelled():
            return
        try:
            absolute = Path(os.path.abspath(os.fspath(path)))
        except (OSError, ValueError):
            return
        key = os.path.normcase(str(absolute))
        if key in self._seen_paths:
            return
        if is_reparse_point(absolute):
            return
        allowed, why = self.guard.validate_path(absolute)
        if not allowed:
            self.log(f"Safety guard skipped {absolute}: {why}")
            return
        try:
            is_dir = absolute.is_dir() and not is_reparse_point(absolute)
        except OSError:
            is_dir = False
        actual_kind = kind or ("folder" if is_dir else "file")
        if actual_kind == "folder" and not is_dir:
            return
        if actual_kind == "file" and is_dir:
            return
        self.status(f"Measuring {truncate_middle(str(absolute), 72)}…")
        size = measure_path(absolute, self.cancel_event) if is_dir else _file_size(absolute)
        self._seen_paths.add(key)
        self.items.append(
            LeftoverItem(
                kind=actual_kind,
                path=str(absolute),
                size_bytes=size,
                category=category,
                reason=reason,
                filesystem_path=absolute,
            )
        )
        self.log(f"Found {actual_kind}: {absolute} ({human_size(size)})")

    def _add_registry(
        self, key_path: str, category: str, reason: str, view_flag: int, view_name: str
    ) -> None:
        if self._cancelled():
            return
        identity = (key_path.casefold(), int(view_flag))
        if identity in self._seen_registry:
            return
        allowed, why = self.guard.validate_registry_key(key_path)
        if not allowed:
            self.log(f"Safety guard skipped HKCU\\{key_path}: {why}")
            return
        self._seen_registry.add(identity)
        subkey_note = ""
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                key_path,
                0,
                winreg.KEY_READ | view_flag,
            ) as key:
                subkey_count = winreg.QueryInfoKey(key)[0]
            if subkey_count:
                subkey_note = f" · {subkey_count} subkey(s) included"
        except OSError:
            pass
        self.items.append(
            LeftoverItem(
                kind="registry",
                path=f"HKCU\\{key_path}",
                size_bytes=0,
                category=category,
                reason=f"{reason}{subkey_note}",
                registry_path=key_path,
                registry_view=view_flag,
                registry_view_name=view_name,
            )
        )
        self.log(f"Found registry key: HKCU\\{key_path} ({view_name} view)")

    def _scan_container(
        self,
        root: Path,
        category: str,
        max_depth: int,
        allow_vendor: bool,
        trusted_root: bool = False,
    ) -> None:
        if not root.exists() or self._cancelled():
            return
        if not trusted_root and is_reparse_point(root):
            warning = f"{category} root is a reparse point; it was skipped."
            self.warnings.append(warning)
            self.log(warning)
            return
        for entry in _safe_scandir(root):
            if self._cancelled():
                return
            try:
                name = entry.name
            except OSError:
                continue
            lowered = name.casefold()
            if lowered in PROTECTED_COMPONENT_NAMES:
                continue
            sensitive_names = {value.casefold() for value in SENSITIVE_USER_CONTAINERS}
            if lowered in sensitive_names:
                continue
            if lowered in USER_KNOWN_FOLDER_NAMES:
                continue
            try:
                if entry.is_symlink() or is_reparse_point(entry.path):
                    continue
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue

            if not is_dir:
                reason = self.profile.match_artifact(name, is_file=True)
                if reason:
                    self._add_path(Path(entry.path), category, reason, "file")
                continue

            reason = self.profile.match_artifact(name, is_file=False)
            if reason:
                self._add_path(Path(entry.path), category, reason, "folder")
                continue

            if (
                allow_vendor
                and max_depth >= 2
                and self.profile.matches_vendor(name)
                and not _is_protected_component_name(name)
            ):
                self._scan_vendor_child(Path(entry.path), category)

    def _scan_vendor_child(self, vendor_path: Path, category: str) -> None:
        if self._cancelled():
            return
        for entry in _safe_scandir(vendor_path):
            if self._cancelled():
                return
            lowered = entry.name.casefold()
            if lowered in PROTECTED_COMPONENT_NAMES:
                continue
            if lowered in {value.casefold() for value in SENSITIVE_USER_CONTAINERS}:
                continue
            try:
                if entry.is_symlink() or is_reparse_point(entry.path):
                    continue
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if is_dir:
                reason = self.profile.match_artifact(entry.name, is_file=False)
                if reason:
                    self._add_path(
                        Path(entry.path),
                        category,
                        f"{reason} inside publisher folder",
                        "folder",
                    )
            else:
                reason = self.profile.match_artifact(entry.name, is_file=True)
                if reason:
                    self._add_path(
                        Path(entry.path),
                        category,
                        f"{reason} inside publisher folder",
                        "file",
                    )

    def _scan_user_profile(self) -> None:
        root = self.guard.userprofile
        if not root.exists() or self._cancelled():
            return
        for entry in _safe_scandir(root):
            if self._cancelled():
                return
            name = entry.name
            if not name.startswith("."):
                continue
            try:
                if entry.is_symlink() or is_reparse_point(entry.path):
                    continue
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue
            lowered = name.casefold()
            if lowered in {value.casefold() for value in PROTECTED_USER_CONTAINERS}:
                # .config/.cache/.local are containers, not artifacts; the
                # sensitive ones are never descended into.
                if lowered in {".config", ".cache", ".local"} and is_dir:
                    self._scan_dot_container(Path(entry.path))
                continue

            reason = self.profile.match_artifact(name, is_file=not is_dir)
            if reason:
                self._add_path(
                    Path(entry.path),
                    "User profile",
                    reason,
                    "folder" if is_dir else "file",
                )
            elif is_dir and self.profile.matches_vendor(name):
                self._scan_vendor_child(Path(entry.path), "User profile")

    def _scan_dot_container(self, container: Path) -> None:
        # Never select the generic .config/.cache/.local root itself. Only
        # its app-correlated children are eligible.
        if self._cancelled() or is_reparse_point(container):
            return
        for entry in _safe_scandir(container):
            if self._cancelled():
                return
            if entry.name.casefold() in PROTECTED_COMPONENT_NAMES:
                continue
            if entry.name.casefold() in {
                value.casefold() for value in SENSITIVE_USER_CONTAINERS
            }:
                continue
            try:
                if entry.is_symlink() or is_reparse_point(entry.path):
                    continue
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue
            reason = self.profile.match_artifact(entry.name, is_file=not is_dir)
            if reason:
                self._add_path(
                    Path(entry.path),
                    "User profile",
                    f"{reason} in {container.name}",
                    "folder" if is_dir else "file",
                )
            elif is_dir and self.profile.matches_vendor(entry.name):
                self._scan_vendor_child(Path(entry.path), "User profile")

    def _scan_registry(self) -> None:
        # HKCU\Software is not WOW64-redirected like HKLM\Software. Scan it
        # once, in the native 64-bit view, to avoid duplicate consent rows and
        # a pointless second delete in the other view.
        for view_flag, view_name in ((winreg.KEY_WOW64_64KEY, "64-bit"),):
            if self._cancelled():
                return
            access = winreg.KEY_READ | view_flag
            try:
                software = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software", 0, access)
            except OSError as exc:
                self.warnings.append(
                    f"HKCU\\Software ({view_name} view) unavailable: {exc}"
                )
                continue
            try:
                count = winreg.QueryInfoKey(software)[0]
                for index in range(count):
                    if self._cancelled():
                        return
                    try:
                        top_name = winreg.EnumKey(software, index)
                    except OSError:
                        continue
                    if top_name.casefold() in PROTECTED_REGISTRY_TOP_LEVEL:
                        continue
                    full_path = f"Software\\{top_name}"
                    # A top-level key can contain an entire publisher's
                    # subtree. Require an exact compact-name match; looser
                    # matches are only used to descend into a vendor folder.
                    reason = self.profile.match_exact(top_name)
                    if reason:
                        self._add_registry(
                            full_path,
                            "User registry",
                            reason,
                            view_flag,
                            view_name,
                        )
                        continue
                    if not self.profile.matches_vendor(top_name):
                        continue
                    # Publisher container: only select matching children.
                    try:
                        vendor_key = winreg.OpenKey(
                            winreg.HKEY_CURRENT_USER, full_path, 0, access
                        )
                    except OSError:
                        continue
                    try:
                        child_count = winreg.QueryInfoKey(vendor_key)[0]
                        for child_index in range(child_count):
                            if self._cancelled():
                                return
                            try:
                                child_name = winreg.EnumKey(vendor_key, child_index)
                            except OSError:
                                continue
                            child_path = f"{full_path}\\{child_name}"
                            child_reason = self.profile.match_exact(child_name)
                            if child_reason:
                                self._add_registry(
                                    child_path,
                                    "User registry",
                                    f"{child_reason} inside publisher key",
                                    view_flag,
                                    view_name,
                                )
                    finally:
                        try:
                            winreg.CloseKey(vendor_key)
                        except OSError:
                            pass
            finally:
                try:
                    winreg.CloseKey(software)
                except OSError:
                    pass

    def _deduplicate_items(self) -> None:
        """Remove nested duplicate candidates, keeping the shallowest path."""
        filesystem: list[LeftoverItem] = []
        registry: list[LeftoverItem] = []
        for item in self.items:
            if item.is_registry:
                registry.append(item)
            else:
                filesystem.append(item)

        # Findings are generated so that a matching parent stops recursion,
        # but this provides a second, explicit guarantee.
        filesystem.sort(key=lambda item: len(Path(item.path).parts))
        kept: list[LeftoverItem] = []
        for item in filesystem:
            nested = False
            for parent in kept:
                if parent.kind == "folder" and path_is_within(item.path, parent.path):
                    nested = True
                    break
            if not nested:
                kept.append(item)

        registry.sort(key=lambda item: item.registry_path.count("\\"))
        kept_registry: list[LeftoverItem] = []
        for item in registry:
            nested = False
            for parent in kept_registry:
                # The same key can legitimately exist in both 64-bit and
                # 32-bit HKCU views; never collapse those two findings.
                if parent.registry_view != item.registry_view:
                    continue
                if path_is_within(
                    item.registry_path.casefold(), parent.registry_path.casefold()
                ):
                    nested = True
                    break
            if not nested:
                kept_registry.append(item)

        self.items = kept + kept_registry


def _file_size(path: Path) -> int:
    try:
        st = os.lstat(extended_path(path))
        return max(0, int(st.st_size))
    except OSError:
        return 0


def _is_protected_component_name(name: str) -> bool:
    return name.casefold() in PROTECTED_COMPONENT_NAMES


def scan_leftovers(
    app: InstalledApp,
    guard: SafetyGuard,
    cancel_event: Optional[threading.Event] = None,
    status_callback: Optional[Callable[[str], None]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
    still_registered: bool = False,
) -> ScanReport:
    return LeftoverScanner(
        app,
        guard,
        cancel_event=cancel_event,
        status_callback=status_callback,
        log_callback=log_callback,
        still_registered=still_registered,
    ).scan()


# ---------------------------------------------------------------------------
# Deletion engine
# ---------------------------------------------------------------------------


def _unlink_with_retry(raw: str) -> None:
    try:
        os.unlink(raw)
    except PermissionError:
        os.chmod(raw, stat.S_IWRITE)
        os.unlink(raw)


def _rmdir_with_retry(raw: str) -> None:
    try:
        os.rmdir(raw)
    except PermissionError:
        os.chmod(raw, stat.S_IWRITE)
        os.rmdir(raw)


def _remove_path_safely(path: Path) -> None:
    """Delete a tree without ever traversing a reparse point.

    Child failures do not stop sibling cleanup. If anything remains, the
    aggregate failure is raised so the caller can report a partial cleanup.
    """
    raw = extended_path(path)
    st = os.lstat(raw)
    if stat_is_reparse(st):
        # Remove the link/junction itself; never its target.
        if stat.S_ISDIR(st.st_mode) and not os.path.islink(raw):
            _rmdir_with_retry(raw)
        else:
            _unlink_with_retry(raw)
        return

    if stat.S_ISDIR(st.st_mode):
        errors: list[str] = []
        for entry in _safe_scandir(path):
            try:
                _remove_path_safely(Path(entry.path))
            except OSError as exc:
                errors.append(f"{entry.name}: {exc}")
        try:
            _rmdir_with_retry(raw)
        except OSError as exc:
            if errors:
                detail = "; ".join(errors[:4])
                if len(errors) > 4:
                    detail += f"; {len(errors) - 4} more item(s)"
                raise OSError(
                    f"Partially deleted; remaining child errors: {detail}"
                ) from exc
            raise
        return

    _unlink_with_retry(raw)


def _delete_registry_tree(hive: int, key_path: str, view_flag: int) -> bool:
    """Recursively delete an HKCU key in a specific registry view."""
    parts = [part for part in key_path.split("\\") if part]
    if len(parts) < 2 or parts[0].casefold() != "software":
        raise ValueError("Refusing to delete a broad registry root.")

    parent_path = "\\".join(parts[:-1])
    key_name = parts[-1]
    access = winreg.KEY_READ | winreg.KEY_WRITE | view_flag

    try:
        key = winreg.OpenKey(hive, key_path, 0, access)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise OSError(f"Could not open the registry key for deletion: {exc}") from exc

    try:
        child_count = winreg.QueryInfoKey(key)[0]
        children = []
        for index in range(child_count):
            try:
                children.append(winreg.EnumKey(key, index))
            except OSError:
                continue
    finally:
        try:
            winreg.CloseKey(key)
        except OSError:
            pass

    for child in children:
        _delete_registry_tree(hive, f"{key_path}\\{child}", view_flag)

    try:
        parent = winreg.OpenKey(hive, parent_path, 0, access)
    except OSError as exc:
        raise OSError(f"Could not open the registry parent for deletion: {exc}") from exc
    try:
        winreg.DeleteKey(parent, key_name)
    finally:
        try:
            winreg.CloseKey(parent)
        except OSError:
            pass
    return True


def cleanup_leftovers(
    items: Sequence[LeftoverItem],
    guard: SafetyGuard,
    cancel_event: Optional[threading.Event] = None,
    status_callback: Optional[Callable[[str], None]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> CleanupReport:
    """Delete exactly the reviewed items, revalidating each one first."""
    started = time.monotonic()
    status = status_callback or (lambda _message: None)
    log = log_callback or (lambda _message: None)
    progress = progress_callback or (lambda _done, _total: None)
    deleted: list[LeftoverItem] = []
    failed: list[CleanupFailure] = []
    skipped: list[str] = []
    freed = 0
    total = len(items)
    cancelled = False

    for index, item in enumerate(items, start=1):
        if cancel_event is not None and cancel_event.is_set():
            cancelled = True
            break
        progress(index - 1, total)
        status(f"Removing {index} of {total}: {truncate_middle(item.path, 78)}")
        allowed, reason = guard.validate_item(item)
        if not allowed:
            failed.append(CleanupFailure(item.path, f"Safety guard blocked it: {reason}"))
            log(f"BLOCKED: {item.path} — {reason}")
            progress(index, total)
            continue

        path: Optional[Path] = None
        before_size = 0
        try:
            if item.is_registry:
                removed = _delete_registry_tree(
                    winreg.HKEY_CURRENT_USER, item.registry_path, item.registry_view
                )
                if not removed:
                    skipped.append(item.path)
                    log(f"Already gone: {item.path}")
                else:
                    deleted.append(item)
                    log(f"Deleted registry key: {item.path} ({item.registry_view_name} view)")
            else:
                path = item.filesystem_path or Path(item.path)
                if not os.path.lexists(extended_path(path)):
                    skipped.append(item.path)
                    log(f"Already gone: {item.path}")
                    progress(index, total)
                    continue
                before_size = (
                    measure_path(path, cancel_event)
                    if path.is_dir() and not is_reparse_point(path)
                    else _file_size(path)
                )
                if cancel_event is not None and cancel_event.is_set():
                    cancelled = True
                    break
                _remove_path_safely(path)
                if os.path.lexists(extended_path(path)):
                    raise OSError("The path still exists after deletion.")
                deleted.append(item)
                freed += max(0, before_size)
                log(f"Deleted: {item.path} ({human_size(before_size)})")
        except (OSError, ValueError) as exc:
            reason_text = str(exc)
            partial_note = ""
            if path is not None and before_size > 0:
                remaining = (
                    measure_path(path) if os.path.lexists(extended_path(path)) else 0
                )
                partial_freed = max(0, before_size - remaining)
                if partial_freed > 0:
                    freed += partial_freed
                    partial_note = f" Partial data removed: {human_size(partial_freed)}."
            failed.append(CleanupFailure(item.path, f"{reason_text}{partial_note}"))
            log(f"FAILED: {item.path} — {reason_text}{partial_note}")
        except Exception as exc:  # noqa: BLE001 - report unexpected filesystem errors
            failed.append(CleanupFailure(item.path, f"Unexpected error: {exc}"))
            log(f"FAILED: {item.path} — unexpected error: {exc}")
        progress(index, total)

    progress(total if not cancelled else 0, total)
    elapsed = time.monotonic() - started
    log(
        f"Cleanup finished: {len(deleted)} removed, {len(failed)} failed, "
        f"{len(skipped)} already gone, {human_size(freed)} freed."
    )
    return CleanupReport(
        deleted=deleted,
        failed=failed,
        skipped=skipped,
        freed_bytes=freed,
        elapsed_seconds=elapsed,
        cancelled=cancelled,
    )


# ---------------------------------------------------------------------------
# Tkinter dialogs
# ---------------------------------------------------------------------------


def _darken_window(window: tk.Misc) -> None:
    """Apply Windows 11 dark caption and rounded frames, best effort."""
    try:
        window.update_idletasks()
        hwnd = int(window.winfo_id())
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)
        user32.GetParent.argtypes = [wintypes.HWND]
        user32.GetParent.restype = wintypes.HWND
        dwmapi.DwmSetWindowAttribute.argtypes = [
            wintypes.HWND,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        dwmapi.DwmSetWindowAttribute.restype = ctypes.c_long
        parent = user32.GetParent(hwnd)
        handles = [hwnd]
        if parent:
            handles.insert(0, parent)
        for handle in handles:
            try:
                dark = ctypes.c_int(1)
                dwmapi.DwmSetWindowAttribute(
                    wintypes.HWND(handle),
                    20,
                    ctypes.cast(ctypes.pointer(dark), ctypes.c_void_p),
                    ctypes.sizeof(dark),
                )
            except Exception:
                pass
            try:
                corner = ctypes.c_int(2)
                dwmapi.DwmSetWindowAttribute(
                    wintypes.HWND(handle),
                    33,
                    ctypes.cast(ctypes.pointer(corner), ctypes.c_void_p),
                    ctypes.sizeof(corner),
                )
            except Exception:
                pass
    except Exception:
        pass


class ModalDialog(ctk.CTkToplevel):
    """Shared modal shell with reliable centering and grab handling."""

    def __init__(
        self,
        parent: tk.Misc,
        title: str,
        width: int,
        height: int,
        resizable: bool = False,
    ) -> None:
        super().__init__(parent)
        self.withdraw()
        self.title(title)
        self.configure(fg_color=BG)
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        # Geometry values passed to customtkinter are logical units; Tk's
        # screen dimensions and window offsets are physical pixels.
        self._ui_scale = window_scale(self)
        logical_screen_w = max(1, int(screen_w / self._ui_scale))
        logical_screen_h = max(1, int(screen_h / self._ui_scale))
        self._dialog_width = max(420, min(width, logical_screen_w - 50))
        self._dialog_height = max(240, min(height, logical_screen_h - 50))
        self.geometry(f"{self._dialog_width}x{self._dialog_height}")
        self.minsize(
            min(420, max(320, logical_screen_w - 50)),
            min(240, max(200, logical_screen_h - 50)),
        )
        self.resizable(resizable, resizable)
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", self._request_close)
        self._parent = parent
        self._is_finished = False
        self.after(25, self._present)

    def _present(self) -> None:
        try:
            if not self.winfo_exists():
                return
        except tk.TclError:
            return
        try:
            self.update_idletasks()
            scale = window_scale(self)
            physical_w = max(1, int(round(self._dialog_width * scale)))
            physical_h = max(1, int(round(self._dialog_height * scale)))
            screen_w = self.winfo_screenwidth()
            screen_h = self.winfo_screenheight()
            parent = self._parent
            if parent.winfo_exists():
                px = parent.winfo_rootx()
                py = parent.winfo_rooty()
                pw = parent.winfo_width()
                ph = parent.winfo_height()
                x = px + (pw - physical_w) // 2
                y = py + (ph - physical_h) // 2
            else:
                x = (screen_w - physical_w) // 2
                y = (screen_h - physical_h) // 2
            x = max(20, min(x, screen_w - physical_w - 20))
            y = max(20, min(y, screen_h - physical_h - 40))
            self.geometry(f"{self._dialog_width}x{self._dialog_height}+{x}+{y}")
            self.deiconify()
            self.lift()
            self.grab_set()
            self.focus_force()
            _darken_window(self)
        except tk.TclError:
            pass

    def _request_close(self) -> None:
        self.finish(None)

    def finish(self, result: object) -> None:
        if self._is_finished:
            return
        self._is_finished = True
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()
        self._after_finish(result)

    def _after_finish(self, result: object) -> None:
        """Subclasses override to receive the dialog result."""


class MessageDialog(ModalDialog):
    """Modern replacement for a native message box."""

    def __init__(
        self,
        parent: tk.Misc,
        title: str,
        heading: str,
        message: str,
        tone: str = "info",
        details: str = "",
        on_close: Optional[Callable[[], None]] = None,
        button_text: str = "Close",
    ) -> None:
        self._on_close = on_close
        height = 390 if details else 300
        super().__init__(parent, title, 590, height, resizable=bool(details))
        self._build(heading, message, tone, details, button_text)

    def _build(
        self,
        heading: str,
        message: str,
        tone: str,
        details: str,
        button_text: str,
    ) -> None:
        accent = {
            "info": ACCENT,
            "success": SUCCESS,
            "warning": WARNING,
            "error": DANGER,
        }.get(tone, ACCENT)
        glyph = {
            "info": "i",
            "success": "✓",
            "warning": "!",
            "error": "×",
        }.get(tone, "i")
        card = ctk.CTkFrame(
            self,
            fg_color=CARD,
            corner_radius=18,
            border_width=1,
            border_color=BORDER,
        )
        card.pack(fill="both", expand=True, padx=22, pady=22)
        card.grid_columnconfigure(1, weight=1)
        card.grid_rowconfigure(1, weight=1)

        badge = ctk.CTkFrame(card, width=48, height=48, corner_radius=24, fg_color=accent)
        badge.grid(row=0, column=0, padx=(22, 14), pady=(24, 4), sticky="n")
        badge.grid_propagate(False)
        ctk.CTkLabel(
            badge,
            text=glyph,
            font=ctk.CTkFont(FONT_DISPLAY, 23, "bold"),
            text_color=ON_ACCENT,
        ).place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(
            card,
            text=heading,
            font=ctk.CTkFont(FONT_DISPLAY, 21, "bold"),
            text_color=TEXT,
            anchor="w",
            justify="left",
            wraplength=450,
        ).grid(row=0, column=1, sticky="ew", padx=(0, 22), pady=(27, 4))

        ctk.CTkLabel(
            card,
            text=message,
            font=ctk.CTkFont(FONT_TEXT, 13),
            text_color=MUTED,
            anchor="nw",
            justify="left",
            wraplength=480,
        ).grid(row=1, column=1, sticky="new", padx=(0, 22), pady=(0, 8))

        if details:
            box = ctk.CTkTextbox(
                card,
                height=112,
                fg_color=INPUT,
                border_width=1,
                border_color=BORDER,
                corner_radius=10,
                font=ctk.CTkFont(FONT_MONO, 11),
                text_color=MUTED,
            )
            box.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=22, pady=(0, 8))
            box.insert("1.0", details)
            box.configure(state="disabled")
            card.grid_rowconfigure(2, weight=1)

        actions = ctk.CTkFrame(card, fg_color="transparent")
        actions.grid(row=3, column=0, columnspan=2, sticky="e", padx=22, pady=(8, 22))
        ctk.CTkButton(
            actions,
            text=button_text,
            width=124,
            height=38,
            corner_radius=10,
            fg_color=accent,
            hover_color=ACCENT_HOVER,
            text_color=ON_ACCENT,
            font=ctk.CTkFont(FONT_TEXT, 12, "bold"),
            command=lambda: self.finish(True),
        ).pack(side="right")
        self.bind("<Escape>", lambda _event: self.finish(True))

    def _after_finish(self, result: object) -> None:
        if self._on_close:
            try:
                self._on_close()
            except Exception:
                pass


class DecisionDialog(ModalDialog):
    """Asynchronous two-choice dialog used for the still-registered prompt."""

    def __init__(
        self,
        parent: tk.Misc,
        title: str,
        heading: str,
        message: str,
        primary_text: str,
        secondary_text: str,
        primary_tone: str = "accent",
        on_result: Optional[Callable[[bool], None]] = None,
    ) -> None:
        self._on_result = on_result
        super().__init__(parent, title, 610, 330)
        self._build(heading, message, primary_text, secondary_text, primary_tone)

    def _build(
        self,
        heading: str,
        message: str,
        primary_text: str,
        secondary_text: str,
        primary_tone: str,
    ) -> None:
        card = ctk.CTkFrame(
            self,
            fg_color=CARD,
            corner_radius=18,
            border_width=1,
            border_color=BORDER,
        )
        card.pack(fill="both", expand=True, padx=22, pady=22)
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            card,
            text=heading,
            font=ctk.CTkFont(FONT_DISPLAY, 21, "bold"),
            text_color=TEXT,
            anchor="w",
            justify="left",
            wraplength=540,
        ).grid(row=0, column=0, sticky="ew", padx=24, pady=(25, 10))
        ctk.CTkLabel(
            card,
            text=message,
            font=ctk.CTkFont(FONT_TEXT, 13),
            text_color=MUTED,
            anchor="nw",
            justify="left",
            wraplength=535,
        ).grid(row=1, column=0, sticky="new", padx=24, pady=(0, 12))
        card.grid_rowconfigure(1, weight=1)
        actions = ctk.CTkFrame(card, fg_color="transparent")
        actions.grid(row=2, column=0, sticky="e", padx=22, pady=(8, 22))
        ctk.CTkButton(
            actions,
            text=secondary_text,
            width=118,
            height=38,
            corner_radius=10,
            fg_color="transparent",
            border_width=1,
            border_color=BORDER,
            hover_color=CARD_HOVER,
            text_color=MUTED,
            font=ctk.CTkFont(FONT_TEXT, 12, "bold"),
            command=lambda: self.finish(False),
        ).pack(side="left", padx=(0, 8))
        primary_color = ACCENT if primary_tone == "accent" else WARNING
        ctk.CTkButton(
            actions,
            text=primary_text,
            width=156,
            height=38,
            corner_radius=10,
            fg_color=primary_color,
            hover_color=ACCENT_HOVER if primary_tone == "accent" else "#D97706",
            text_color=ON_ACCENT,
            font=ctk.CTkFont(FONT_TEXT, 12, "bold"),
            command=lambda: self.finish(True),
        ).pack(side="left")
        self.bind("<Escape>", lambda _event: self.finish(False))

    def _after_finish(self, result: object) -> None:
        if self._on_result:
            try:
                self._on_result(bool(result))
            except Exception:
                pass


class ConfirmDialog(ModalDialog):
    """Final permanent-delete confirmation."""

    def __init__(
        self,
        parent: tk.Misc,
        count: int,
        size_bytes: int,
        on_result: Callable[[bool], None],
    ) -> None:
        self._on_result = on_result
        super().__init__(parent, "Confirm permanent deletion", 560, 340)
        self._build(count, size_bytes)

    def _build(self, count: int, size_bytes: int) -> None:
        card = ctk.CTkFrame(
            self,
            fg_color=CARD,
            corner_radius=18,
            border_width=1,
            border_color=BORDER,
        )
        card.pack(fill="both", expand=True, padx=22, pady=22)
        ctk.CTkLabel(
            card,
            text="Permanently delete selected leftovers?",
            font=ctk.CTkFont(FONT_DISPLAY, 21, "bold"),
            text_color=TEXT,
            anchor="w",
            justify="left",
            wraplength=480,
        ).pack(anchor="w", padx=24, pady=(25, 12))
        ctk.CTkLabel(
            card,
            text=(
                f"{count} item(s) will be removed, including approximately "
                f"{human_size(size_bytes)} of files.\n\n"
                "This action cannot be undone. Deletion does not use the Recycle Bin."
            ),
            font=ctk.CTkFont(FONT_TEXT, 13),
            text_color=MUTED,
            justify="left",
            anchor="w",
            wraplength=475,
        ).pack(anchor="w", padx=24, pady=(0, 16))
        actions = ctk.CTkFrame(card, fg_color="transparent")
        actions.pack(side="bottom", fill="x", padx=22, pady=(0, 22))
        ctk.CTkButton(
            actions,
            text="Cancel",
            width=112,
            height=38,
            corner_radius=10,
            fg_color="transparent",
            border_width=1,
            border_color=BORDER,
            hover_color=CARD_HOVER,
            text_color=MUTED,
            font=ctk.CTkFont(FONT_TEXT, 12, "bold"),
            command=lambda: self.finish(False),
        ).pack(side="right", padx=(8, 0))
        ctk.CTkButton(
            actions,
            text="Delete permanently",
            width=166,
            height=38,
            corner_radius=10,
            fg_color=DANGER,
            hover_color=DANGER_HOVER,
            text_color=ON_ACCENT,
            font=ctk.CTkFont(FONT_TEXT, 12, "bold"),
            command=lambda: self.finish(True),
        ).pack(side="right")
        self.bind("<Escape>", lambda _event: self.finish(False))

    def _after_finish(self, result: object) -> None:
        try:
            self._on_result(bool(result))
        except Exception:
            pass


class UninstallOptionsDialog(ModalDialog):
    """Preflight consent for the vendor uninstaller."""

    def __init__(
        self,
        parent: tk.Misc,
        app: InstalledApp,
        on_result: Optional[Callable[[Optional[dict[str, object]]], None]] = None,
    ) -> None:
        self.app = app
        self._on_result = on_result
        self._interactive_available = bool(app.uninstall_string.strip())
        self._quiet_available = quiet_uninstall_available(app)
        self.mode_var = tk.StringVar(
            value="interactive" if self._interactive_available else "quiet"
        )
        self.elevated_var = tk.BooleanVar(value=False)
        self._previews: dict[str, str] = {}
        super().__init__(parent, "Uninstall options", 700, 590, resizable=False)
        self._build()

    def _command_for(self, mode: str) -> str:
        try:
            argv, _source = build_uninstall_argv(self.app, mode)
            return command_preview(argv)
        except ValueError as exc:
            return f"Not available: {exc}"

    def _build(self) -> None:
        shell = ctk.CTkFrame(self, fg_color=BG)
        shell.pack(fill="both", expand=True, padx=24, pady=20)
        ctk.CTkLabel(
            shell,
            text="Uninstall with the vendor tool",
            font=ctk.CTkFont(FONT_DISPLAY, 23, "bold"),
            text_color=TEXT,
            anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            shell,
            text=(
                "PureUninstaller will run the official uninstaller below. After it "
                "finishes, you will review every possible leftover before anything "
                "is removed."
            ),
            font=ctk.CTkFont(FONT_TEXT, 12),
            text_color=MUTED,
            justify="left",
            anchor="w",
            wraplength=630,
        ).pack(anchor="w", pady=(5, 14))

        app_card = ctk.CTkFrame(
            shell,
            fg_color=CARD,
            corner_radius=14,
            border_width=1,
            border_color=BORDER,
        )
        app_card.pack(fill="x", pady=(0, 14))
        ctk.CTkLabel(
            app_card,
            text=truncate_middle(self.app.display_name, 82),
            font=ctk.CTkFont(FONT_TEXT, 15, "bold"),
            text_color=TEXT,
            anchor="w",
            justify="left",
        ).pack(anchor="w", padx=16, pady=(13, 2))
        details = " • ".join(
            part
            for part in (
                self.app.publisher or "Unknown publisher",
                f"v{self.app.version}" if self.app.version else "",
                self.app.size_text,
            )
            if part
        )
        ctk.CTkLabel(
            app_card,
            text=details,
            font=ctk.CTkFont(FONT_TEXT, 11),
            text_color=FAINT,
            anchor="w",
        ).pack(anchor="w", padx=16, pady=(0, 13))

        ctk.CTkLabel(
            shell,
            text="UNINSTALL METHOD",
            font=ctk.CTkFont(FONT_TEXT, 10, "bold"),
            text_color=FAINT,
            anchor="w",
        ).pack(anchor="w", pady=(0, 6))

        interactive = ctk.CTkRadioButton(
            shell,
            text="Interactive — show the vendor uninstaller UI (recommended)",
            variable=self.mode_var,
            value="interactive",
            command=self._refresh_preview,
            font=ctk.CTkFont(FONT_TEXT, 12),
            text_color=TEXT,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            border_color=BORDER,
            radiobutton_width=18,
            radiobutton_height=18,
        )
        interactive.pack(anchor="w", pady=3)
        if not self._interactive_available:
            interactive.configure(state="disabled", text_color=FAINT)

        quiet = ctk.CTkRadioButton(
            shell,
            text="Quiet — use a published or Windows Installer silent command",
            variable=self.mode_var,
            value="quiet",
            command=self._refresh_preview,
            font=ctk.CTkFont(FONT_TEXT, 12),
            text_color=TEXT,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            border_color=BORDER,
            radiobutton_width=18,
            radiobutton_height=18,
        )
        quiet.pack(anchor="w", pady=3)
        if not self._quiet_available:
            quiet.configure(state="disabled", text_color=FAINT)

        ctk.CTkLabel(
            shell,
            text="COMMAND PREVIEW",
            font=ctk.CTkFont(FONT_TEXT, 10, "bold"),
            text_color=FAINT,
            anchor="w",
        ).pack(anchor="w", pady=(14, 5))
        self.command_box = ctk.CTkTextbox(
            shell,
            height=72,
            fg_color=INPUT,
            border_width=1,
            border_color=BORDER,
            corner_radius=10,
            font=ctk.CTkFont(FONT_MONO, 10),
            text_color=MUTED,
            wrap="word",
        )
        self.command_box.pack(fill="x")
        self.command_box.configure(state="disabled")

        self.elevated_check = ctk.CTkCheckBox(
            shell,
            text="Request administrator privileges (UAC prompt)",
            variable=self.elevated_var,
            font=ctk.CTkFont(FONT_TEXT, 11),
            text_color=MUTED,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            border_color=BORDER,
            checkmark_color=ON_ACCENT,
            checkbox_width=18,
            checkbox_height=18,
        )
        self.elevated_check.pack(anchor="w", pady=(13, 0))
        ctk.CTkLabel(
            shell,
            text=(
                "If Windows reports that the uninstaller requires elevation, "
                "PureUninstaller will request it automatically."
            ),
            font=ctk.CTkFont(FONT_TEXT, 10),
            text_color=FAINT,
            anchor="w",
            justify="left",
            wraplength=620,
        ).pack(anchor="w", pady=(3, 0))

        note = ctk.CTkLabel(
            shell,
            text=(
                "The vendor uninstaller is not controlled by PureUninstaller. "
                "It may show its own dialogs or request a reboot."
            ),
            font=ctk.CTkFont(FONT_TEXT, 10),
            text_color=WARNING,
            anchor="w",
            justify="left",
            wraplength=630,
        )
        note.pack(anchor="w", pady=(12, 0))

        actions = ctk.CTkFrame(shell, fg_color="transparent")
        actions.pack(side="bottom", fill="x", pady=(16, 0))
        ctk.CTkButton(
            actions,
            text="Cancel",
            width=112,
            height=40,
            corner_radius=10,
            fg_color="transparent",
            border_width=1,
            border_color=BORDER,
            hover_color=CARD_HOVER,
            text_color=MUTED,
            font=ctk.CTkFont(FONT_TEXT, 12, "bold"),
            command=lambda: self.finish(None),
        ).pack(side="right", padx=(8, 0))
        ctk.CTkButton(
            actions,
            text="Start uninstallation",
            width=186,
            height=40,
            corner_radius=10,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            text_color=ON_ACCENT,
            font=ctk.CTkFont(FONT_TEXT, 12, "bold"),
            command=self._confirm,
        ).pack(side="right")

        self._previews["interactive"] = self._command_for("interactive")
        self._previews["quiet"] = self._command_for("quiet")
        self._refresh_preview()
        self.bind("<Escape>", lambda _event: self.finish(None))

    def _refresh_preview(self) -> None:
        mode = self.mode_var.get()
        text = self._previews.get(mode, "Not available.")
        self.command_box.configure(state="normal")
        self.command_box.delete("1.0", "end")
        self.command_box.insert("1.0", text)
        self.command_box.configure(state="disabled")

    def _confirm(self) -> None:
        mode = self.mode_var.get()
        if mode == "interactive" and not self._interactive_available:
            return
        if mode == "quiet" and not self._quiet_available:
            return
        self.finish({"mode": mode, "elevated": bool(self.elevated_var.get())})

    def _after_finish(self, result: object) -> None:
        if self._on_result:
            self._on_result(result if isinstance(result, dict) else None)


class LeftoverReviewDialog(ModalDialog):
    """Detailed, checkbox-per-item consent gate for leftover cleanup."""

    def __init__(
        self,
        parent: tk.Misc,
        report: ScanReport,
        on_result: Optional[Callable[[Optional[list[LeftoverItem]]], None]] = None,
    ) -> None:
        self.report = report
        self._on_result = on_result
        self._selected: set[int] = set(range(len(report.items)))
        self._check_vars: dict[int, tk.BooleanVar] = {}
        self._rendered = 0
        self._render_chunk = 25
        self._wipe_button: Optional[ctk.CTkButton] = None
        self._selection_label: Optional[ctk.CTkLabel] = None
        self._complete = False
        self._confirm_open = False
        super().__init__(parent, "Leftover audit", 1020, 760, resizable=True)
        self._build()

    def _build(self) -> None:
        shell = ctk.CTkFrame(self, fg_color=BG)
        shell.pack(fill="both", expand=True, padx=22, pady=18)
        shell.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(shell, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew")
        top.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            top,
            text="Review every leftover",
            font=ctk.CTkFont(FONT_DISPLAY, 25, "bold"),
            text_color=TEXT,
            anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            top,
            text=(
                f"{len(self.report.items)} candidate(s) · "
                f"{human_size(self.report.total_bytes)} potential"
            ),
            font=ctk.CTkFont(FONT_TEXT, 13, "bold"),
            text_color=ACCENT,
            anchor="e",
        ).grid(row=0, column=1, sticky="e")
        ctk.CTkLabel(
            top,
            text=(
                "Everything is selected by default. Uncheck anything you want to keep. "
                "No item is deleted until you confirm the final warning."
            ),
            font=ctk.CTkFont(FONT_TEXT, 11),
            text_color=MUTED,
            anchor="w",
            justify="left",
            wraplength=820,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(5, 0))

        if self.report.warnings or self.report.still_registered:
            banner = ctk.CTkFrame(
                shell,
                fg_color="#2A2413",
                corner_radius=10,
                border_width=1,
                border_color="#574414",
            )
            banner.grid(row=1, column=0, sticky="ew", pady=(12, 0))
            warning_text = []
            if self.report.still_registered:
                warning_text.append(
                    "The app is still registered with Windows. Removing its data may "
                    "break an installation that was not actually removed."
                )
            warning_text.extend(self.report.warnings[:2])
            ctk.CTkLabel(
                banner,
                text="  •  ".join(warning_text),
                font=ctk.CTkFont(FONT_TEXT, 10),
                text_color=WARNING,
                anchor="w",
                justify="left",
                wraplength=810,
            ).pack(anchor="w", padx=12, pady=8)
            top_pad = 10
        else:
            top_pad = 12

        toolbar = ctk.CTkFrame(
            shell,
            fg_color=CARD,
            corner_radius=10,
            border_width=1,
            border_color=BORDER_SOFT,
        )
        toolbar.grid(row=2, column=0, sticky="ew", pady=(top_pad, 10))
        self._build_toolbar(toolbar)
        shell.grid_rowconfigure(3, weight=1)

        self.scroll = ctk.CTkScrollableFrame(
            shell,
            fg_color="transparent",
            corner_radius=0,
            scrollbar_button_color=BORDER,
            scrollbar_button_hover_color=FAINT,
        )
        self.scroll.grid(row=3, column=0, sticky="nsew")
        self.scroll.grid_columnconfigure(0, weight=1)

        footer = ctk.CTkFrame(shell, fg_color="transparent")
        footer.grid(row=4, column=0, sticky="ew", pady=(12, 0))
        footer.grid_columnconfigure(0, weight=1)
        self._selection_label = ctk.CTkLabel(
            footer,
            text=f"All {len(self.report.items)} item(s) selected",
            font=ctk.CTkFont(FONT_TEXT, 11),
            text_color=MUTED,
            anchor="w",
        )
        self._selection_label.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            footer,
            text="Permanent deletion · no Recycle Bin",
            font=ctk.CTkFont(FONT_TEXT, 10),
            text_color=FAINT,
            anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        actions = ctk.CTkFrame(footer, fg_color="transparent")
        actions.grid(row=0, column=1, rowspan=2, sticky="e")
        ctk.CTkButton(
            actions,
            text="Skip / Keep",
            width=126,
            height=40,
            corner_radius=10,
            fg_color="transparent",
            border_width=1,
            border_color=BORDER,
            hover_color=CARD_HOVER,
            text_color=MUTED,
            font=ctk.CTkFont(FONT_TEXT, 12, "bold"),
            command=lambda: self.finish(None),
        ).pack(side="left", padx=(0, 8))
        self._wipe_button = ctk.CTkButton(
            actions,
            text="Wipe Selected Leftovers",
            width=208,
            height=40,
            corner_radius=10,
            fg_color=DANGER,
            hover_color=DANGER_HOVER,
            text_color=ON_ACCENT,
            font=ctk.CTkFont(FONT_TEXT, 12, "bold"),
            command=self._wipe,
            state="disabled",
        )
        self._wipe_button.pack(side="left")

        if self.report.items:
            self.after(10, lambda: self._render_next_chunk())
        else:
            self._complete = True
            if self._wipe_button:
                self._wipe_button.configure(state="disabled")
        self.bind("<Escape>", lambda _event: self.finish(None))

    def _build_toolbar(self, toolbar: ctk.CTkFrame) -> None:
        toolbar.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            toolbar,
            text="CANDIDATES",
            font=ctk.CTkFont(FONT_TEXT, 10, "bold"),
            text_color=FAINT,
            anchor="w",
        ).grid(row=0, column=0, padx=(14, 12), pady=10)
        self.scan_summary = ctk.CTkLabel(
            toolbar,
            text=(
                f"{self.report.app.display_name} · "
                f"{self.report.elapsed_seconds:.1f}s audit"
            ),
            font=ctk.CTkFont(FONT_TEXT, 11),
            text_color=MUTED,
            anchor="w",
        )
        self.scan_summary.grid(row=0, column=1, sticky="w", pady=10)
        ctk.CTkButton(
            toolbar,
            text="Select all",
            width=86,
            height=30,
            corner_radius=8,
            fg_color=CHIP,
            hover_color=CARD_HOVER,
            text_color=TEXT,
            font=ctk.CTkFont(FONT_TEXT, 10, "bold"),
            command=lambda: self._select_all(True),
        ).grid(row=0, column=2, padx=(8, 4), pady=7)
        ctk.CTkButton(
            toolbar,
            text="Select none",
            width=92,
            height=30,
            corner_radius=8,
            fg_color="transparent",
            border_width=1,
            border_color=BORDER,
            hover_color=CARD_HOVER,
            text_color=MUTED,
            font=ctk.CTkFont(FONT_TEXT, 10, "bold"),
            command=lambda: self._select_all(False),
        ).grid(row=0, column=3, padx=(4, 12), pady=7)

    def _render_next_chunk(self) -> None:
        try:
            if not self.winfo_exists() or self._complete:
                return
        except tk.TclError:
            return
        end = min(self._rendered + self._render_chunk, len(self.report.items))
        for index in range(self._rendered, end):
            self._render_row(index, self.report.items[index])
        self._rendered = end
        if self._rendered < len(self.report.items):
            self.after(8, self._render_next_chunk)
        else:
            self._complete = True
            if self._wipe_button:
                self._wipe_button.configure(state="normal")
            self._update_selection_label()

    def _render_row(self, index: int, item: LeftoverItem) -> None:
        row = ctk.CTkFrame(
            self.scroll,
            fg_color=CARD,
            corner_radius=12,
            border_width=1,
            border_color=BORDER_SOFT,
        )
        row.grid(row=index, column=0, sticky="ew", pady=(0, 7))
        row.grid_columnconfigure(1, weight=1)

        var = tk.BooleanVar(value=index in self._selected)
        self._check_vars[index] = var
        checkbox = ctk.CTkCheckBox(
            row,
            text="",
            width=24,
            height=24,
            variable=var,
            command=lambda idx=index, value=var: self._toggle(idx, value),
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            border_color=BORDER,
            checkmark_color=ON_ACCENT,
            checkbox_width=19,
            checkbox_height=19,
        )
        checkbox.grid(row=0, column=0, rowspan=2, padx=(14, 4), pady=14, sticky="n")

        header = ctk.CTkFrame(row, fg_color="transparent")
        header.grid(row=0, column=1, sticky="ew", padx=(2, 12), pady=(11, 0))
        ctk.CTkLabel(
            header,
            text=item.kind_label,
            width=62,
            height=19,
            corner_radius=5,
            fg_color=CHIP_REG if item.is_registry else CHIP,
            text_color=ACCENT,
            font=ctk.CTkFont(FONT_TEXT, 8, "bold"),
        ).pack(side="left")
        ctk.CTkLabel(
            header,
            text=item.category_label,
            font=ctk.CTkFont(FONT_TEXT, 9, "bold"),
            text_color=FAINT,
        ).pack(side="left", padx=(8, 0))
        ctk.CTkLabel(
            header,
            text=truncate_middle(item.reason, 72),
            font=ctk.CTkFont(FONT_TEXT, 9),
            text_color=MUTED,
        ).pack(side="left", padx=(8, 0))

        ctk.CTkLabel(
            row,
            text=item.path,
            font=ctk.CTkFont(FONT_MONO, 10),
            text_color=TEXT,
            anchor="w",
            justify="left",
            wraplength=630,
        ).grid(row=1, column=1, sticky="ew", padx=(2, 12), pady=(2, 11))

        ctk.CTkLabel(
            row,
            text=item.size_text,
            font=ctk.CTkFont(FONT_TEXT, 10, "bold" if not item.is_registry else "normal"),
            text_color=ACCENT if not item.is_registry else FAINT,
            width=92,
            anchor="e",
        ).grid(row=0, column=2, rowspan=2, padx=(0, 14), sticky="e")

    def _toggle(self, index: int, variable: tk.BooleanVar) -> None:
        if variable.get():
            self._selected.add(index)
        else:
            self._selected.discard(index)
        self._update_selection_label()

    def _select_all(self, selected: bool) -> None:
        if selected:
            self._selected = set(range(len(self.report.items)))
        else:
            self._selected.clear()
        for index, variable in self._check_vars.items():
            try:
                variable.set(selected)
            except tk.TclError:
                pass
        self._update_selection_label()

    def _update_selection_label(self) -> None:
        if not self._selection_label:
            return
        count = len(self._selected)
        selected_bytes = sum(
            self.report.items[index].size_bytes for index in self._selected
        )
        if count == 0:
            text = "No items selected — choose at least one to wipe"
        elif count == len(self.report.items):
            text = f"All {count} item(s) selected · {human_size(selected_bytes)}"
        else:
            text = f"{count} of {len(self.report.items)} selected · {human_size(selected_bytes)}"
        self._selection_label.configure(text=text)
        if self._wipe_button and self._complete:
            self._wipe_button.configure(state="normal" if count else "disabled")

    def _wipe(self) -> None:
        if not self._complete or self._confirm_open:
            return
        selected = [
            self.report.items[index] for index in sorted(self._selected)
        ]
        if not selected:
            return
        size_bytes = sum(item.size_bytes for item in selected)
        self._confirm_open = True
        ConfirmDialog(
            self,
            len(selected),
            size_bytes,
            on_result=lambda confirmed: self._after_confirm(confirmed, selected),
        )

    def _after_confirm(
        self, confirmed: bool, selected: list[LeftoverItem]
    ) -> None:
        self._confirm_open = False
        if not self.winfo_exists():
            return
        if confirmed:
            self.finish(selected)
            return
        try:
            self.grab_set()
            self.lift()
            self.focus_force()
        except tk.TclError:
            pass

    def finish(self, result: object) -> None:
        super().finish(result)

    def _after_finish(self, result: object) -> None:
        if self._on_result:
            selected = result if isinstance(result, list) else None
            self._on_result(selected)


class LogDialog(ModalDialog):
    """Read-only audit log with copy support."""

    def __init__(self, parent: tk.Misc, lines: Sequence[str]) -> None:
        super().__init__(parent, "Operation log", 780, 560, resizable=True)
        shell = ctk.CTkFrame(self, fg_color=BG)
        shell.pack(fill="both", expand=True, padx=22, pady=18)
        header = ctk.CTkFrame(shell, fg_color="transparent")
        header.pack(fill="x")
        ctk.CTkLabel(
            header,
            text="Operation log",
            font=ctk.CTkFont(FONT_DISPLAY, 23, "bold"),
            text_color=TEXT,
        ).pack(side="left")
        ctk.CTkButton(
            header,
            text="Copy",
            width=86,
            height=32,
            corner_radius=8,
            fg_color=CHIP,
            hover_color=CARD_HOVER,
            text_color=TEXT,
            font=ctk.CTkFont(FONT_TEXT, 10, "bold"),
            command=lambda: self._copy(lines),
        ).pack(side="right")
        ctk.CTkLabel(
            shell,
            text="Every discovery, guard decision, and cleanup result is recorded locally.",
            font=ctk.CTkFont(FONT_TEXT, 11),
            text_color=MUTED,
            anchor="w",
        ).pack(anchor="w", pady=(2, 10))
        self.text = ctk.CTkTextbox(
            shell,
            fg_color=INPUT,
            border_width=1,
            border_color=BORDER,
            corner_radius=10,
            font=ctk.CTkFont(FONT_MONO, 10),
            text_color=MUTED,
            wrap="word",
        )
        self.text.pack(fill="both", expand=True)
        self.text.insert("1.0", "\n".join(lines) if lines else "No log entries yet.")
        self.text.configure(state="disabled")
        actions = ctk.CTkFrame(shell, fg_color="transparent")
        actions.pack(fill="x", pady=(12, 0))
        ctk.CTkButton(
            actions,
            text="Close",
            width=110,
            height=36,
            corner_radius=9,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            text_color=ON_ACCENT,
            font=ctk.CTkFont(FONT_TEXT, 11, "bold"),
            command=lambda: self.finish(True),
        ).pack(side="right")
        self.bind("<Escape>", lambda _event: self.finish(True))

    def _copy(self, lines: Sequence[str]) -> None:
        try:
            self.clipboard_clear()
            self.clipboard_append("\n".join(lines))
        except tk.TclError:
            pass


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------


class PureUninstallerApp(ctk.CTk):
    """The main window and all threaded workflow orchestration."""

    def __init__(self) -> None:
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        super().__init__()
        self.title(f"{APP_NAME} — {APP_TAGLINE}")
        self.configure(fg_color=BG)
        self._configure_window()
        self._apply_app_id()

        # Application state.
        self.apps: list[InstalledApp] = []
        self.filtered_apps: list[InstalledApp] = []
        self._rendered_count = 0
        self._loading_apps = True
        self._busy = False
        self._shutdown = False
        self._active_app: Optional[InstalledApp] = None
        self._pending_remove_after_flow = False
        self._modal_open = False
        self._active_operation = ""
        self._operation_started = 0.0
        self._event_queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self._cancel_event = threading.Event()
        self._logs: deque[str] = deque(maxlen=MAX_LOG_LINES)
        self._action_buttons: list[ctk.CTkButton] = []
        self._search_job: Optional[str] = None
        self._status_text = tk.StringVar(value="Preparing registry discovery…")
        self._status_tone = "info"
        self._app_count_text = tk.StringVar(value="—")
        self._app_size_text = tk.StringVar(value="—")
        self._last_scan_text = tk.StringVar(value="Not scanned yet")
        self._header_count_text = tk.StringVar(value="Reading Windows registry…")
        self._safety = SafetyGuard()

        self._build_ui()
        self._bind_shortcuts()
        self._append_log(f"{APP_NAME} {APP_VERSION} started.")
        self._append_log(f"Cleanup roots: {self._safety.describe_roots()}")
        self._append_log(
            "Protected: Windows, System32, Program Files, drive roots, known user folders."
        )
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll_events)
        self.after(120, lambda: _darken_window(self))
        self.after(250, self.refresh_installed_apps)

    # -- window and layout -------------------------------------------------

    def _configure_window(self) -> None:
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        scale = window_scale(self)
        logical_screen_w = max(1, int(screen_w / scale))
        logical_screen_h = max(1, int(screen_h / scale))
        width = min(1280, max(900, logical_screen_w - 100))
        height = min(840, max(480, logical_screen_h - 60))
        physical_w = int(round(width * scale))
        physical_h = int(round(height * scale))
        x = max(10, (screen_w - physical_w) // 2)
        y = max(10, (screen_h - physical_h) // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.minsize(
            min(900, max(800, logical_screen_w - 40)),
            min(520, max(480, logical_screen_h - 30)),
        )
        self.grid_columnconfigure(0, weight=0, minsize=286)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)

    def _apply_app_id(self) -> None:
        try:
            shell32 = ctypes.WinDLL("shell32")
            shell32.SetCurrentProcessExplicitAppUserModelID(
                ctypes.c_wchar_p("PureUninstaller.Desktop.1")
            )
        except Exception:
            pass

    def _build_ui(self) -> None:
        self._build_sidebar()
        self._build_main()
        self._build_status_bar()

    def _build_sidebar(self) -> None:
        sidebar = ctk.CTkFrame(
            self,
            width=286,
            corner_radius=0,
            fg_color=SIDEBAR,
            border_width=0,
        )
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_rowconfigure(7, weight=1)

        brand = ctk.CTkFrame(sidebar, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="ew", padx=22, pady=(22, 18))
        brand.grid_columnconfigure(1, weight=1)
        mark = ctk.CTkFrame(brand, width=42, height=42, corner_radius=12, fg_color=ACCENT)
        mark.grid(row=0, column=0, rowspan=2, sticky="w")
        mark.grid_propagate(False)
        ctk.CTkLabel(
            mark,
            text="P",
            font=ctk.CTkFont(FONT_DISPLAY, 22, "bold"),
            text_color=ON_ACCENT,
        ).place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(
            brand,
            text=APP_NAME,
            font=ctk.CTkFont(FONT_DISPLAY, 20, "bold"),
            text_color=TEXT,
            anchor="w",
        ).grid(row=0, column=1, sticky="sw", padx=(11, 0))
        ctk.CTkLabel(
            brand,
            text=APP_TAGLINE,
            font=ctk.CTkFont(FONT_TEXT, 9),
            text_color=FAINT,
            anchor="w",
        ).grid(row=1, column=1, sticky="nw", padx=(11, 0))

        separator = ctk.CTkFrame(sidebar, height=1, fg_color=BORDER_SOFT)
        separator.grid(row=1, column=0, sticky="ew", padx=22)

        ctk.CTkLabel(
            sidebar,
            text="SEARCH INSTALLED APPS",
            font=ctk.CTkFont(FONT_TEXT, 9, "bold"),
            text_color=FAINT,
            anchor="w",
        ).grid(row=2, column=0, sticky="ew", padx=22, pady=(18, 6))

        search_shell = ctk.CTkFrame(
            sidebar,
            fg_color=INPUT,
            corner_radius=10,
            border_width=1,
            border_color=BORDER,
            height=42,
        )
        search_shell.grid(row=3, column=0, sticky="ew", padx=22)
        search_shell.grid_propagate(False)
        search_shell.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            search_shell,
            text="⌕",
            font=ctk.CTkFont("Segoe UI Symbol", 16),
            text_color=FAINT,
            width=30,
        ).grid(row=0, column=0, padx=(4, 0))
        self.search_entry = ctk.CTkEntry(
            search_shell,
            placeholder_text="Name, publisher, version…",
            font=ctk.CTkFont(FONT_TEXT, 12),
            text_color=TEXT,
            placeholder_text_color=FAINT,
            fg_color="transparent",
            border_width=0,
            height=38,
        )
        self.search_entry.grid(row=0, column=1, sticky="ew", padx=(0, 2))
        self.search_entry.bind("<KeyRelease>", self._schedule_search)
        self.search_entry.bind("<Return>", lambda _event: self._apply_filter())
        self.search_clear = ctk.CTkButton(
            search_shell,
            text="×",
            width=28,
            height=28,
            corner_radius=7,
            fg_color="transparent",
            hover_color=CARD_HOVER,
            text_color=FAINT,
            font=ctk.CTkFont(FONT_TEXT, 16),
            command=self._clear_search,
        )
        self.search_clear.grid(row=0, column=2, padx=(0, 5))

        self.refresh_btn = ctk.CTkButton(
            sidebar,
            text="Refresh Installed Apps",
            height=40,
            corner_radius=10,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            text_color=ON_ACCENT,
            font=ctk.CTkFont(FONT_TEXT, 12, "bold"),
            command=self.refresh_installed_apps,
        )
        self.refresh_btn.grid(row=4, column=0, sticky="ew", padx=22, pady=(10, 16))

        stats = ctk.CTkFrame(
            sidebar,
            fg_color=CARD,
            corner_radius=12,
            border_width=1,
            border_color=BORDER_SOFT,
        )
        stats.grid(row=5, column=0, sticky="ew", padx=22)
        stats.grid_columnconfigure(0, weight=1)
        stats.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            stats,
            text="INSTALLED",
            font=ctk.CTkFont(FONT_TEXT, 8, "bold"),
            text_color=FAINT,
            anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=(14, 0), pady=(11, 0))
        ctk.CTkLabel(
            stats,
            text="REPORTED SIZE",
            font=ctk.CTkFont(FONT_TEXT, 8, "bold"),
            text_color=FAINT,
            anchor="w",
        ).grid(row=0, column=1, sticky="w", padx=(8, 12), pady=(11, 0))
        ctk.CTkLabel(
            stats,
            textvariable=self._app_count_text,
            font=ctk.CTkFont(FONT_DISPLAY, 18, "bold"),
            text_color=TEXT,
            anchor="w",
        ).grid(row=1, column=0, sticky="w", padx=(14, 0), pady=(0, 10))
        ctk.CTkLabel(
            stats,
            textvariable=self._app_size_text,
            font=ctk.CTkFont(FONT_DISPLAY, 18, "bold"),
            text_color=TEXT,
            anchor="w",
        ).grid(row=1, column=1, sticky="w", padx=(8, 12), pady=(0, 10))

        safety = ctk.CTkFrame(
            sidebar,
            fg_color=ACCENT_DARK,
            corner_radius=12,
            border_width=1,
            border_color="#124453",
        )
        safety.grid(row=6, column=0, sticky="ew", padx=22, pady=(14, 0))
        ctk.CTkLabel(
            safety,
            text="REVIEW-FIRST SAFETY",
            font=ctk.CTkFont(FONT_TEXT, 9, "bold"),
            text_color=ACCENT,
            anchor="w",
        ).pack(anchor="w", padx=14, pady=(11, 3))
        ctk.CTkLabel(
            safety,
            text=(
                "Every path is shown before deletion. Windows, Program Files, "
                "System32, drive roots, and known user folders are blocked."
            ),
            font=ctk.CTkFont(FONT_TEXT, 10),
            text_color="#9EDAE6",
            anchor="w",
            justify="left",
            wraplength=218,
        ).pack(anchor="w", padx=14, pady=(0, 11))

        footer = ctk.CTkFrame(sidebar, fg_color="transparent")
        footer.grid(row=8, column=0, sticky="sew", padx=22, pady=(12, 20))
        ctk.CTkLabel(
            footer,
            textvariable=self._last_scan_text,
            font=ctk.CTkFont(FONT_TEXT, 9),
            text_color=FAINT,
            anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            footer,
            text="Local only · no telemetry · no background service",
            font=ctk.CTkFont(FONT_TEXT, 8),
            text_color=FAINT,
            anchor="w",
        ).pack(anchor="w", pady=(3, 0))
        ctk.CTkLabel(
            footer,
            text=f"v{APP_VERSION} · Windows 11",
            font=ctk.CTkFont(FONT_TEXT, 8),
            text_color=FAINT,
            anchor="w",
        ).pack(anchor="w", pady=(3, 0))

    def _build_main(self) -> None:
        main = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(main, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=30, pady=(25, 13))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            header,
            text="Installed applications",
            font=ctk.CTkFont(FONT_DISPLAY, 29, "bold"),
            text_color=TEXT,
            anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            header,
            textvariable=self._header_count_text,
            font=ctk.CTkFont(FONT_TEXT, 11),
            text_color=MUTED,
            anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))
        ctk.CTkLabel(
            header,
            text="Registry-sourced · official uninstaller · manual leftover consent",
            font=ctk.CTkFont(FONT_TEXT, 10),
            text_color=FAINT,
            anchor="e",
        ).grid(row=0, column=1, rowspan=2, sticky="e", padx=(12, 0))

        self.results = ctk.CTkScrollableFrame(
            main,
            fg_color="transparent",
            corner_radius=0,
            scrollbar_button_color=BORDER,
            scrollbar_button_hover_color=FAINT,
        )
        self.results.grid(row=1, column=0, sticky="nsew", padx=(30, 18), pady=(0, 18))
        self.results.grid_columnconfigure(0, weight=1)

        self._render_loading()

    def _build_status_bar(self) -> None:
        bar = ctk.CTkFrame(
            self,
            height=56,
            corner_radius=0,
            fg_color="#0A1119",
            border_width=1,
            border_color=BORDER_SOFT,
        )
        bar.grid(row=1, column=0, columnspan=2, sticky="ew")
        bar.grid_propagate(False)
        bar.grid_columnconfigure(2, weight=1)

        self.status_dot = ctk.CTkLabel(
            bar,
            text="●",
            width=26,
            font=ctk.CTkFont("Segoe UI Symbol", 13),
            text_color=ACCENT,
        )
        self.status_dot.grid(row=0, column=0, padx=(20, 2), pady=17)
        self.operation_label = ctk.CTkLabel(
            bar,
            text="READY",
            font=ctk.CTkFont(FONT_TEXT, 9, "bold"),
            text_color=FAINT,
            width=76,
            anchor="w",
        )
        self.operation_label.grid(row=0, column=1, sticky="w", pady=17)
        ctk.CTkLabel(
            bar,
            textvariable=self._status_text,
            font=ctk.CTkFont(FONT_TEXT, 11),
            text_color=MUTED,
            anchor="w",
        ).grid(row=0, column=2, sticky="ew", padx=(4, 16), pady=17)

        self.progress_bar = ctk.CTkProgressBar(
            bar,
            width=110,
            height=4,
            corner_radius=2,
            fg_color=BORDER,
            progress_color=ACCENT,
            mode="determinate",
        )
        self.progress_bar.set(0)
        self.progress_bar.grid(row=0, column=3, padx=(0, 16), pady=26)

        self.log_btn = ctk.CTkButton(
            bar,
            text="View log",
            width=90,
            height=30,
            corner_radius=8,
            fg_color="transparent",
            border_width=1,
            border_color=BORDER,
            hover_color=CARD_HOVER,
            text_color=MUTED,
            font=ctk.CTkFont(FONT_TEXT, 10, "bold"),
            command=self._show_log,
        )
        self.log_btn.grid(row=0, column=4, padx=(0, 20), pady=13)

    def _bind_shortcuts(self) -> None:
        self.bind("<Control-f>", self._focus_search)
        self.bind("<Control-F>", self._focus_search)
        self.bind("<F5>", lambda _event: self.refresh_installed_apps())
        self.bind("<Escape>", self._on_escape)

    def _focus_search(self, _event: Optional[tk.Event] = None) -> str:
        self.search_entry.focus_set()
        try:
            self.search_entry.select_range(0, "end")
        except (AttributeError, tk.TclError):
            pass
        return "break"

    def _on_escape(self, _event: Optional[tk.Event] = None) -> None:
        if self.search_entry.get():
            self._clear_search()

    # -- UI state helpers --------------------------------------------------

    def _set_status(self, message: str, tone: str = "info") -> None:
        self._status_text.set(truncate_middle(" ".join(str(message).split()), 168))
        self._status_tone = tone
        colors = {
            "info": ACCENT,
            "success": SUCCESS,
            "warning": WARNING,
            "error": DANGER,
        }
        try:
            self.status_dot.configure(text_color=colors.get(tone, ACCENT))
        except tk.TclError:
            pass

    def _append_log(self, message: str, level: str = "info") -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "info": "INFO",
            "warn": "WARN",
            "error": "ERR ",
            "success": "OK  ",
        }.get(level, "INFO")
        line = f"[{stamp}] {prefix} {message}"
        self._logs.append(line)

    def _set_busy(
        self,
        busy: bool,
        operation: str = "",
        progress_mode: str = "indeterminate",
    ) -> None:
        self._busy = busy
        self._active_operation = operation if busy else ""
        if busy:
            self._operation_started = time.monotonic()
            self.operation_label.configure(text=operation.upper()[:18] if operation else "WORKING")
        else:
            self.operation_label.configure(text="READY")
        try:
            self.refresh_btn.configure(state="disabled" if busy else "normal")
        except tk.TclError:
            pass
        for button in list(self._action_buttons):
            try:
                if button.winfo_exists():
                    button.configure(state="disabled" if busy else "normal")
            except tk.TclError:
                pass
        try:
            if busy:
                if progress_mode == "determinate":
                    self.progress_bar.stop()
                    self.progress_bar.configure(mode="determinate")
                    self.progress_bar.set(0)
                else:
                    self.progress_bar.configure(mode="indeterminate")
                    self.progress_bar.start()
            else:
                self.progress_bar.stop()
                self.progress_bar.configure(mode="determinate")
                self.progress_bar.set(0)
        except tk.TclError:
            pass

    def _update_progress(self, done: int, total: int) -> None:
        if total <= 0:
            self.progress_bar.set(0)
            return
        try:
            self.progress_bar.configure(mode="determinate")
            self.progress_bar.set(min(1.0, max(0.0, done / total)))
        except tk.TclError:
            pass

    def _spawn_worker(
        self,
        worker: Callable[[], None],
        name: str,
        failure_heading: str,
        failure_detail: str,
        on_failure: Optional[Callable[[], None]] = None,
    ) -> bool:
        """Start a daemon worker and recover the UI if start-up fails."""
        try:
            threading.Thread(
                target=worker,
                name=safe_thread_name(name),
                daemon=True,
            ).start()
            return True
        except Exception as exc:
            self._set_busy(False)
            self._append_log(f"Could not start {name} worker: {exc}", "error")
            if on_failure is not None:
                try:
                    on_failure()
                except Exception:
                    pass
            MessageDialog(
                self,
                "Worker start failure",
                failure_heading,
                f"{failure_detail}\n\n{exc}",
                tone="error",
            )
            return False

    def _remove_app_from_view(self, app: InstalledApp) -> None:
        self.apps = [item for item in self.apps if item.identity != app.identity]
        self._apply_filter(force=True)
        self._update_stats()

    def _update_stats(self) -> None:
        total_bytes = sum(item.reported_size_bytes for item in self.apps)
        known = sum(1 for item in self.apps if item.estimated_size_kb > 0)
        self._app_count_text.set(str(len(self.apps)))
        self._app_size_text.set(human_size(total_bytes) if known else "—")
        self._last_scan_text.set(
            f"Last registry scan · {datetime.now().strftime('%H:%M')}"
        )
        if self.search_entry.get().strip():
            self._header_count_text.set(
                f"{len(self.filtered_apps)} fuzzy match(es) of {len(self.apps)} programs"
            )
        else:
            self._header_count_text.set(
                f"{len(self.apps)} programs · {known} report an install size"
            )

    # -- installed-app discovery ------------------------------------------

    def refresh_installed_apps(self) -> None:
        if self._busy or self._modal_open:
            self._set_status("Finish or close the open dialog first.", "warning")
            return
        self._loading_apps = True
        self._set_busy(True, "refreshing", "indeterminate")
        self._set_status("Reading uninstall registry scopes…")
        self._render_loading()
        self._cancel_event = threading.Event()
        self._append_log("Refreshing installed programs from HKLM/HKCU registry views.")

        def worker() -> None:
            try:
                apps = enumerate_installed_apps(
                    cancel_event=self._cancel_event,
                    status_callback=lambda text: self._emit("status", text),
                    log_callback=lambda text: self._emit("log", (text, "info")),
                )
                if not self._shutdown:
                    self._emit("apps_loaded", apps)
            except Exception as exc:
                if not self._shutdown:
                    self._emit("apps_error", str(exc))

        def refresh_start_failed() -> None:
            self._loading_apps = False
            self.apps = []
            self.filtered_apps = []
            self._update_stats()
            self._last_scan_text.set("Registry scan failed")
            self._render_empty(
                "Could not start the registry scan",
                "The background worker could not be created. Try Refresh again.",
            )

        self._spawn_worker(
            worker,
            "registry-refresh",
            "Registry scan did not start",
            "The installed-app refresh could not be launched.",
            on_failure=refresh_start_failed,
        )

    def _event_apps_loaded(self, payload: object) -> None:
        apps = payload if isinstance(payload, list) else []
        self.apps = [item for item in apps if isinstance(item, InstalledApp)]
        self._loading_apps = False
        self._set_busy(False)
        self._update_stats()
        self._apply_filter(force=True)
        self._set_status(
            f"Ready · {len(self.apps)} installed programs discovered.", "success"
        )
        self._append_log(
            f"Installed programs refreshed: {len(self.apps)} entries."
        )

    def _event_apps_error(self, payload: object) -> None:
        self._loading_apps = False
        self.apps = []
        self.filtered_apps = []
        self._set_busy(False)
        self._update_stats()
        self._last_scan_text.set("Registry scan failed")
        message = str(payload)
        self._set_status("Registry discovery failed.", "error")
        self._append_log(f"Registry discovery failed: {message}", "error")
        self._render_empty(
            "Could not read the uninstall registry",
            "Windows denied or interrupted the registry query. Try Refresh again.",
        )
        MessageDialog(
            self,
            "Registry discovery failed",
            "Could not read installed applications",
            message,
            tone="error",
        )

    # -- search and list rendering ----------------------------------------

    def _schedule_search(self, _event: Optional[tk.Event] = None) -> None:
        if self._search_job:
            try:
                self.after_cancel(self._search_job)
            except tk.TclError:
                pass
        self._search_job = self.after(130, self._apply_filter)

    def _clear_search(self) -> None:
        self.search_entry.delete(0, "end")
        self._apply_filter(force=True)

    @staticmethod
    def _fuzzy_score(query: str, app: InstalledApp) -> float:
        q = normalize_words(query)
        if not q:
            return 1.0
        fields = (
            (normalize_words(app.display_name), 1.0),
            (normalize_words(app.publisher), 0.72),
            (normalize_words(app.version), 0.36),
            (normalize_words(app.install_location), 0.28),
        )
        best = 0.0
        for text, weight in fields:
            if not text:
                continue
            score = 0.0
            if q in text:
                score = 100.0 + (20.0 if text.startswith(q) else 0.0)
            elif all(token in text for token in q.split()):
                score = 82.0
            elif _is_subsequence(q, text):
                score = 58.0
            else:
                ratio = SequenceMatcher(None, q, text).ratio()
                if ratio >= 0.48:
                    score = ratio * 55.0
            best = max(best, score * weight)
        return best

    def _apply_filter(self, force: bool = False) -> None:
        self._search_job = None
        query = self.search_entry.get().strip()
        if not query:
            self.filtered_apps = list(self.apps)
        else:
            scored = [
                (self._fuzzy_score(query, app), app)
                for app in self.apps
            ]
            scored = [pair for pair in scored if pair[0] > 0]
            scored.sort(key=lambda pair: (-pair[0], pair[1].display_name.casefold()))
            self.filtered_apps = [app for _score, app in scored]
        self._update_stats()
        if self._loading_apps:
            # Keep the loading state visible while the registry worker runs.
            return
        self._render_results(reset=True)

    def _render_loading(self) -> None:
        self._clear_results()
        self._action_buttons.clear()
        holder = ctk.CTkFrame(
            self.results,
            fg_color=CARD,
            corner_radius=16,
            border_width=1,
            border_color=BORDER,
        )
        holder.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        ctk.CTkLabel(
            holder,
            text="◇",
            font=ctk.CTkFont("Segoe UI Symbol", 32),
            text_color=ACCENT,
        ).pack(pady=(34, 7))
        ctk.CTkLabel(
            holder,
            text="Auditing the Windows uninstall registry",
            font=ctk.CTkFont(FONT_DISPLAY, 17, "bold"),
            text_color=TEXT,
        ).pack()
        ctk.CTkLabel(
            holder,
            text="Reading HKLM and HKCU, 64-bit and 32-bit views, and filtering OS updates.",
            font=ctk.CTkFont(FONT_TEXT, 10),
            text_color=MUTED,
        ).pack(pady=(4, 34))

    def _render_empty(self, title: str, message: str) -> None:
        self._clear_results()
        self._action_buttons.clear()
        holder = ctk.CTkFrame(
            self.results,
            fg_color=CARD,
            corner_radius=16,
            border_width=1,
            border_color=BORDER,
        )
        holder.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        ctk.CTkLabel(
            holder,
            text="◇",
            font=ctk.CTkFont("Segoe UI Symbol", 34),
            text_color=FAINT,
        ).pack(pady=(42, 8))
        ctk.CTkLabel(
            holder,
            text=title,
            font=ctk.CTkFont(FONT_DISPLAY, 18, "bold"),
            text_color=TEXT,
        ).pack()
        ctk.CTkLabel(
            holder,
            text=message,
            font=ctk.CTkFont(FONT_TEXT, 10),
            text_color=MUTED,
            wraplength=520,
            justify="center",
        ).pack(pady=(5, 18))
        if self.search_entry.get().strip():
            ctk.CTkButton(
                holder,
                text="Clear search",
                width=126,
                height=34,
                corner_radius=9,
                fg_color=CHIP,
                hover_color=CARD_HOVER,
                text_color=TEXT,
                font=ctk.CTkFont(FONT_TEXT, 10, "bold"),
                command=self._clear_search,
            ).pack(pady=(0, 38))
        else:
            ctk.CTkButton(
                holder,
                text="Refresh Installed Apps",
                width=170,
                height=34,
                corner_radius=9,
                fg_color=CHIP,
                hover_color=CARD_HOVER,
                text_color=TEXT,
                font=ctk.CTkFont(FONT_TEXT, 10, "bold"),
                command=self.refresh_installed_apps,
            ).pack(pady=(0, 38))

    def _clear_results(self) -> None:
        for child in self.results.winfo_children():
            try:
                child.destroy()
            except tk.TclError:
                pass

    def _render_results(self, reset: bool = False) -> None:
        if reset:
            self._clear_results()
            self._rendered_count = 0
            self._action_buttons.clear()
        if self._loading_apps:
            return
        if not self.filtered_apps:
            if self.search_entry.get().strip():
                self._render_empty(
                    "No matching programs",
                    "Try a shorter fuzzy query, a publisher name, or clear the search.",
                )
            else:
                self._render_empty(
                    "No user-uninstallable programs found",
                    "Windows system components and update records are intentionally hidden.",
                )
            return
        if reset:
            self._render_page()

    def _render_page(self) -> None:
        total = len(self.filtered_apps)
        end = min(self._rendered_count + PAGE_SIZE, total)
        for index in range(self._rendered_count, end):
            self._render_app_card(index, self.filtered_apps[index])
        self._rendered_count = end
        if end < total:
            remaining = total - end
            more = ctk.CTkButton(
                self.results,
                text=f"Show {min(PAGE_SIZE, remaining)} more · {remaining} remaining",
                height=38,
                corner_radius=10,
                fg_color=CARD,
                hover_color=CARD_HOVER,
                border_width=1,
                border_color=BORDER,
                text_color=MUTED,
                font=ctk.CTkFont(FONT_TEXT, 10, "bold"),
                command=self._load_more,
            )
            more.grid(row=end, column=0, sticky="ew", pady=(3, 18))

    def _load_more(self) -> None:
        for child in list(self.results.winfo_children()):
            try:
                info = child.grid_info()
            except tk.TclError:
                continue
            if info and int(info.get("row", -1)) >= self._rendered_count:
                try:
                    child.destroy()
                except tk.TclError:
                    pass
        self._render_page()

    def _render_app_card(self, index: int, app: InstalledApp) -> None:
        card = ctk.CTkFrame(
            self.results,
            fg_color=CARD,
            corner_radius=15,
            border_width=1,
            border_color=BORDER,
        )
        card.grid(row=index, column=0, sticky="ew", pady=(0, 9))
        card.grid_columnconfigure(0, weight=1)
        card.grid_columnconfigure(1, weight=0)

        name_row = ctk.CTkFrame(card, fg_color="transparent")
        name_row.grid(row=0, column=0, sticky="ew", padx=(18, 12), pady=(14, 0))
        name_row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            name_row,
            text=truncate_middle(app.display_name, 92),
            font=ctk.CTkFont(FONT_DISPLAY, 15, "bold"),
            text_color=TEXT,
            anchor="w",
            justify="left",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            card,
            text=truncate_middle(app.publisher or "Unknown publisher", 78),
            font=ctk.CTkFont(FONT_TEXT, 10),
            text_color=MUTED,
            anchor="w",
        ).grid(row=1, column=0, sticky="w", padx=18, pady=(2, 8))

        chips = ctk.CTkFrame(card, fg_color="transparent")
        chips.grid(row=2, column=0, sticky="w", padx=18, pady=(0, 15))
        chip_values = []
        if app.version:
            chip_values.append(("VERSION", f"v{app.version}"))
        if app.architecture:
            chip_values.append(("ARCH", app.architecture))
        if app.install_date:
            label = "INSTALLED" if app.date_source == "install" else "REG MODIFIED"
            chip_values.append((label, pretty_date(app.install_date)))
        chip_values.append(("SIZE", app.size_text))
        for caption, value in chip_values:
            chip = ctk.CTkFrame(
                chips,
                fg_color=CHIP,
                corner_radius=6,
                height=24,
            )
            chip.pack(side="left", padx=(0, 6))
            ctk.CTkLabel(
                chip,
                text=f"{caption}  ",
                font=ctk.CTkFont(FONT_TEXT, 8, "bold"),
                text_color=FAINT,
                height=22,
            ).pack(side="left", padx=(8, 0))
            ctk.CTkLabel(
                chip,
                text=truncate_middle(value, 32),
                font=ctk.CTkFont(FONT_TEXT, 9, "bold"),
                text_color=TEXT,
                height=22,
            ).pack(side="left", padx=(0, 8))

        action = ctk.CTkButton(
            card,
            text="Analyze & Uninstall",
            width=158,
            height=38,
            corner_radius=10,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            text_color=ON_ACCENT,
            font=ctk.CTkFont(FONT_TEXT, 11, "bold"),
            command=lambda selected=app: self._on_analyze(selected),
            state="disabled" if self._busy else "normal",
        )
        action.grid(
            row=0,
            column=1,
            rowspan=3,
            padx=(8, 18),
            pady=16,
            sticky="e",
        )
        self._action_buttons.append(action)

    # -- operation dispatch ------------------------------------------------

    def _on_analyze(self, app: InstalledApp) -> None:
        if self._busy or self._modal_open:
            self._set_status("Finish or close the open dialog first.", "warning")
            return
        if not app.has_uninstaller:
            MessageDialog(
                self,
                "Uninstall command missing",
                "No official uninstall command was published",
                "Windows does not list an UninstallString or QuietUninstallString for "
                "this program. PureUninstaller will not guess at a removal command.",
                tone="warning",
            )
            return
        self._modal_open = True
        self._active_app = app
        self._append_log(f"Opening uninstall preflight for {app.display_name}.")
        try:
            UninstallOptionsDialog(
                self,
                app,
                on_result=lambda result: self._after_uninstall_options(app, result),
            )
        except Exception as exc:
            self._modal_open = False
            self._active_app = None
            self._set_status("The uninstall preflight could not open.", "error")
            MessageDialog(
                self,
                "Uninstall preflight error",
                "Could not open the uninstall options",
                str(exc),
                tone="error",
            )

    def _after_uninstall_options(
        self, app: InstalledApp, result: Optional[dict[str, object]]
    ) -> None:
        self._modal_open = False
        if not result:
            self._active_app = None
            self._set_status("Uninstall cancelled. Nothing was changed.", "info")
            return
        mode = str(result.get("mode", "interactive"))
        elevated = bool(result.get("elevated", False))
        self._start_uninstall(app, mode, elevated)

    def _start_uninstall(
        self, app: InstalledApp, mode: str, elevated: bool
    ) -> None:
        if self._busy:
            self._set_status("Another operation is already running.", "warning")
            return
        self._active_app = app
        self._pending_remove_after_flow = False
        self._set_busy(True, "uninstalling", "indeterminate")
        self._set_status(f"Launching official uninstaller for {app.display_name}…")
        self._append_log(
            f"User consented to {mode} uninstall of {app.display_name} "
            f"(elevated={elevated})."
        )

        def worker() -> None:
            try:
                report = run_uninstaller(
                    app,
                    mode,
                    elevated,
                    status_callback=lambda text: self._emit("status", text),
                    log_callback=lambda text: self._emit("log", (text, "info")),
                )
                if not self._shutdown:
                    self._emit("uninstall_done", (app, report))
            except Exception as exc:
                if not self._shutdown:
                    self._emit("uninstall_error", str(exc))

        self._spawn_worker(
            worker,
            "uninstall",
            "Uninstaller did not start",
            "The background uninstall worker could not be created.",
            on_failure=self._finish_active_flow,
        )

    def _event_uninstall_error(self, payload: object) -> None:
        self._set_busy(False)
        message = str(payload)
        self._set_status("Uninstaller workflow crashed.", "error")
        self._append_log(f"Uninstaller workflow error: {message}", "error")
        MessageDialog(
            self,
            "Uninstaller error",
            "The uninstall workflow could not complete",
            message,
            tone="error",
        )
        self._finish_active_flow()

    def _event_uninstall_done(self, payload: object) -> None:
        if not isinstance(payload, tuple) or len(payload) != 2:
            self._set_busy(False)
            return
        app, report = payload
        if not isinstance(app, InstalledApp) or not isinstance(report, UninstallReport):
            self._set_busy(False)
            return
        self._set_busy(False)
        if report.error:
            self._set_status("Uninstaller could not complete.", "error")
            self._append_log(f"Uninstall failed: {report.error}", "error")
            tone = "warning" if report.cancelled else "error"
            heading = "Elevation cancelled" if report.cancelled else "Uninstaller did not run"
            MessageDialog(
                self,
                "Uninstaller stopped",
                heading,
                report.error,
                tone=tone,
            )
            self._finish_active_flow()
            return

        if report.exit_code not in (0, 1641, 3010):
            if report.exit_code == 1602:
                reason = "The Windows Installer reported that the user cancelled the uninstall."
            else:
                reason = (
                    f"The uninstaller exited with code {report.exit_code}. "
                    "No leftover scan was started."
                )
            self._set_status("Uninstaller reported an error.", "error")
            self._append_log(reason, "error")
            MessageDialog(
                self,
                "Uninstaller exit code",
                "The official uninstaller did not report success",
                reason,
                tone="error",
            )
            self._finish_active_flow()
            return

        if report.exit_code in (3010, 1641):
            self._append_log(
                "The official uninstaller requested a Windows restart.", "warn"
            )
        restart_note = (
            " The uninstaller requested a restart, which can also clear a pending "
            "registration entry."
            if report.exit_code in (3010, 1641)
            else ""
        )

        if report.registration_state == "removed":
            self._pending_remove_after_flow = True
            self._append_log("Registry registration removed.", "success")
            self._set_status("Uninstaller finished. Starting leftover audit…", "success")
            self._start_leftover_scan(app, still_registered=False)
            return

        if report.registration_state == "unknown":
            message = (
                "The uninstaller exited, but PureUninstaller could not verify whether "
                "the registry entry was removed. Scan anyway only if you are sure."
                + restart_note
            )
            state_text = "Registration could not be verified"
        else:
            message = (
                "The uninstaller exited successfully, but Windows still lists this "
                "application as installed. The leftover audit can still run, but "
                "deleting user data may break the remaining installation."
                + restart_note
            )
            state_text = "Application is still registered"
        self._set_status(
            "Uninstaller finished; registration present or unverified.", "warning"
        )
        self._append_log(state_text, "warn")
        self._modal_open = True
        try:
            DecisionDialog(
                self,
                "Uninstaller finished",
                state_text,
                message,
                "Scan anyway",
                "Stop here",
                primary_tone="warning",
                on_result=lambda proceed: self._after_scan_anyway(app, proceed),
            )
        except Exception as exc:
            self._modal_open = False
            MessageDialog(
                self,
                "Decision dialog error",
                "Could not open the post-uninstall choice",
                str(exc),
                tone="error",
            )
            self._finish_active_flow()

    def _after_scan_anyway(self, app: InstalledApp, proceed: bool) -> None:
        self._modal_open = False
        if not proceed:
            self._active_app = None
            self._set_status("Stopped after uninstall; no leftovers were changed.", "info")
            return
        self._append_log("User chose to audit leftovers despite registration present.", "warn")
        self._start_leftover_scan(app, still_registered=True)

    def _start_leftover_scan(self, app: InstalledApp, still_registered: bool) -> None:
        if self._busy:
            self._set_status("Another operation is already running.", "warning")
            return
        self._set_busy(True, "auditing", "indeterminate")
        self._set_status("Scanning user data for app-correlated leftovers…")
        self._cancel_event = threading.Event()
        self._active_app = app
        self._append_log(
            f"Leftover audit started (still registered: {still_registered})."
        )

        def worker() -> None:
            try:
                report = scan_leftovers(
                    app,
                    self._safety,
                    cancel_event=self._cancel_event,
                    status_callback=lambda text: self._emit("status", text),
                    log_callback=lambda text: self._emit("log", (text, "info")),
                    still_registered=still_registered,
                )
                if not self._shutdown:
                    self._emit("scan_done", report)
            except Exception as exc:
                if not self._shutdown:
                    self._emit("scan_error", str(exc))

        self._spawn_worker(
            worker,
            "leftover-scan",
            "Leftover audit did not start",
            "The background scan worker could not be created.",
            on_failure=self._finish_active_flow,
        )

    def _event_scan_error(self, payload: object) -> None:
        self._set_busy(False)
        message = str(payload)
        self._set_status("Leftover audit failed.", "error")
        self._append_log(f"Leftover audit failed: {message}", "error")
        MessageDialog(
            self,
            "Leftover audit failed",
            "The scan stopped before completion",
            message,
            tone="error",
        )
        self._finish_active_flow()

    def _event_scan_done(self, payload: object) -> None:
        self._set_busy(False)
        if not isinstance(payload, ScanReport):
            return
        report = payload
        if not report.items:
            self._set_status("No leftovers found. Nothing will be deleted.", "success")
            self._append_log(
                f"Audit found no leftovers for {report.app.display_name}."
            )
            details = ""
            if report.warnings:
                details = "\n".join(report.warnings)
            MessageDialog(
                self,
                "Audit complete",
                "No leftover artifacts were found",
                (
                    "The configured user-data locations did not contain a confident "
                    "name match. No files or registry keys were changed."
                ),
                tone="success",
                details=details,
            )
            self._finish_active_flow()
            return

        self._set_status(
            f"Audit complete: {len(report.items)} candidate(s). Review required.",
            "warning",
        )
        self._append_log(
            f"Audit complete for {report.app.display_name}: "
            f"{len(report.items)} candidate(s), {human_size(report.total_bytes)}."
        )
        self._modal_open = True
        try:
            LeftoverReviewDialog(
                self,
                report,
                on_result=lambda selected: self._after_leftover_review(report, selected),
            )
        except Exception as exc:
            self._modal_open = False
            MessageDialog(
                self,
                "Review dialog error",
                "Could not open the leftover review",
                str(exc),
                tone="error",
            )
            self._finish_active_flow()

    def _after_leftover_review(
        self, report: ScanReport, selected: Optional[list[LeftoverItem]]
    ) -> None:
        self._modal_open = False
        if not selected:
            self._set_status("Leftovers kept. Nothing was deleted.", "info")
            self._append_log("User chose Skip / Keep; no leftovers were deleted.")
            self._finish_active_flow()
            return
        self._append_log(
            f"User consented to delete {len(selected)} leftover item(s)."
        )
        self._start_cleanup(selected)

    def _start_cleanup(self, selected: Sequence[LeftoverItem]) -> None:
        if self._busy:
            self._set_status("Another operation is already running.", "warning")
            return
        if not selected:
            return
        self._set_busy(True, "cleaning", "determinate")
        self._set_status(f"Deleting 0 of {len(selected)} selected leftovers…")
        self._cancel_event = threading.Event()
        total = len(selected)

        def worker() -> None:
            try:
                report = cleanup_leftovers(
                    selected,
                    self._safety,
                    cancel_event=self._cancel_event,
                    status_callback=lambda text: self._emit("status", text),
                    log_callback=lambda text: self._emit("log", (text, "info")),
                    progress_callback=lambda done, count: self._emit(
                        "cleanup_progress", (done, count)
                    ),
                )
                if not self._shutdown:
                    self._emit("cleanup_done", report)
            except Exception as exc:
                if not self._shutdown:
                    self._emit("cleanup_error", str(exc))

        self._spawn_worker(
            worker,
            "cleanup",
            "Cleanup did not start",
            "The background cleanup worker could not be created.",
            on_failure=self._finish_active_flow,
        )

    def _event_cleanup_progress(self, payload: object) -> None:
        if isinstance(payload, tuple) and len(payload) == 2:
            self._update_progress(int(payload[0]), int(payload[1]))

    def _event_cleanup_error(self, payload: object) -> None:
        self._set_busy(False)
        message = str(payload)
        self._set_status("Cleanup workflow failed.", "error")
        self._append_log(f"Cleanup workflow error: {message}", "error")
        MessageDialog(
            self,
            "Cleanup error",
            "The cleanup workflow stopped unexpectedly",
            message,
            tone="error",
        )
        self._finish_active_flow()

    def _event_cleanup_done(self, payload: object) -> None:
        self._set_busy(False)
        if not isinstance(payload, CleanupReport):
            return
        report = payload
        if report.failed:
            tone = "warning"
            heading = "Cleanup finished with issues"
        elif report.deleted:
            tone = "success"
            heading = "Selected leftovers removed"
        else:
            tone = "info"
            heading = "Nothing needed deletion"
        details_parts = [
            f"Removed: {len(report.deleted)}",
            f"Freed: {human_size(report.freed_bytes)}",
            f"Already gone: {len(report.skipped)}",
            f"Failed: {len(report.failed)}",
            f"Elapsed: {report.elapsed_seconds:.1f}s",
        ]
        if report.failed:
            details_parts.append("")
            details_parts.append("Failures:")
            details_parts.extend(
                f"• {failure.path}\n  {failure.reason}"
                for failure in report.failed[:12]
            )
            if len(report.failed) > 12:
                details_parts.append(f"…and {len(report.failed) - 12} more (see log).")
        self._set_status(
            f"Cleanup complete · {human_size(report.freed_bytes)} freed.",
            tone,
        )
        self._append_log(
            f"Cleanup complete: {len(report.deleted)} deleted, "
            f"{len(report.failed)} failed, {human_size(report.freed_bytes)} freed.",
            "success" if not report.failed else "warn",
        )
        if report.deleted:
            summary_text = (
                f"{len(report.deleted)} selected item(s) were removed. "
                "Deletion was permanent and did not use the Recycle Bin."
            )
        elif report.failed:
            summary_text = (
                "No selected item was fully removed. Review the failure details and "
                "the operation log; this was a partial or blocked cleanup."
            )
        else:
            summary_text = (
                "All selected items were already absent, so nothing needed deletion."
            )
        MessageDialog(
            self,
            "Cleanup summary",
            heading,
            summary_text,
            tone=tone,
            details="\n".join(details_parts),
        )
        self._finish_active_flow()

    def _finish_active_flow(self) -> None:
        if self._pending_remove_after_flow and self._active_app is not None:
            self._remove_app_from_view(self._active_app)
            self._pending_remove_after_flow = False
        self._active_app = None

    # -- worker event plumbing --------------------------------------------

    def _emit(self, event: str, payload: object = None) -> None:
        if self._shutdown:
            return
        try:
            self._event_queue.put((event, payload))
        except Exception:
            pass

    def _poll_events(self) -> None:
        if self._shutdown or not self.winfo_exists():
            return
        handled = 0
        while handled < 300:
            try:
                event, payload = self._event_queue.get_nowait()
            except queue.Empty:
                break
            handler = getattr(self, f"_event_{event}", None)
            try:
                if handler:
                    handler(payload)
                elif event == "status":
                    self._set_status(str(payload))
                elif event == "log":
                    message, level = payload  # type: ignore[misc]
                    self._append_log(str(message), str(level))
                    self._set_status(str(message))
            except Exception as exc:
                self._append_log(f"UI event handler error ({event}): {exc}", "error")
                try:
                    self._set_status("An internal UI error occurred; see the log.", "error")
                except tk.TclError:
                    pass
            handled += 1
        try:
            self.after(EVENT_POLL_MS, self._poll_events)
        except tk.TclError:
            pass

    def _show_log(self) -> None:
        LogDialog(self, list(self._logs))

    def _on_close(self) -> None:
        if self._busy:
            proceed = tk_messagebox.askyesno(
                "Operation in progress",
                "A registry scan, uninstaller, or cleanup may still be running.\n\n"
                "Close PureUninstaller anyway? An already-launched vendor uninstaller "
                "will continue independently.",
                parent=self,
            )
            if not proceed:
                return
        self._shutdown = True
        self._cancel_event.set()
        try:
            self.destroy()
        except tk.TclError:
            pass


def _is_subsequence(needle: str, haystack: str) -> bool:
    iterator = iter(haystack)
    return all(character in iterator for character in needle)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Create the main window and enter the Tk event loop."""
    if sys.platform != "win32":
        raise SystemExit("PureUninstaller requires Windows 10 or Windows 11.")
    try:
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
    except Exception:
        pass
    app = PureUninstallerApp()
    try:
        app.mainloop()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
