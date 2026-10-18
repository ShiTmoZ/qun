"""
PureUninstaller - Windows 11 Fluent Desktop Uninstaller & Leftover Auditor
Architecture: Python 3.10+, CustomTkinter, WinReg, Ctypes, Subprocess, Threading
"""

import ctypes
import datetime
import difflib
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import threading
import winreg
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

import customtkinter as ctk
from PIL import Image
from tkinter import messagebox

# ==============================================================================
# THEME & FLUENT DESIGN CONSTANTS
# ==============================================================================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

PALETTE = {
    "bg_root": "#0B0D13",        # Sleek Obsidian Fluent Canvas
    "bg_surface": "#12151E",     # Deep translucent acrylic container
    "bg_card": "#181B26",        # Compact elevated card
    "bg_card_hover": "#222736",  # Subtle luminous card highlight
    "border": "#232838",         # Micro-fine 1px border stroke
    "border_light": "#31384E",   # Subtle elevated component border
    "accent": "#0EA5E9",         # Modern Windows 11 Sky Cyan
    "accent_hover": "#0284C7",   # Sky Cyan hover state
    "accent_subtle": "#0F2942",  # Ghost badge background
    "danger": "#EF4444",         # Destructive action red
    "danger_hover": "#DC2626",   # Destructive hover
    "danger_subtle": "#3B181E",  # Soft destructive background
    "success": "#10B981",        # Emerald clean badge
    "success_subtle": "#0F2F24", # Subtle emerald fill
    "warning": "#F59E0B",        # Amber badge
    "text_primary": "#F8FAFC",   # High-clarity primary text
    "text_secondary": "#94A3B8", # Fluent subtext slate
    "text_muted": "#64748B",     # Technical metadata muted text
}

# Generic publisher/app words excluded from leftover matching to avoid false positives
STOP_TOKENS: Set[str] = {
    "app", "application", "software", "program", "setup", "installer",
    "uninstall", "uninstaller", "client", "desktop", "windows", "microsoft",
    "corporation", "corp", "inc", "incorporated", "llc", "ltd", "limited",
    "gmbh", "co", "company", "studio", "studios", "tech", "technologies",
    "technology", "systems", "system", "net", "org", "com", "the", "for",
    "and", "bin", "data", "common", "shared", "user", "users", "local",
    "roaming", "temp", "cache", "config", "settings", "default", "packages",
    "programs", "update", "updater", "helper", "service", "services", "driver",
    "drivers", "runtime", "redistributable", "x64", "x86", "amd64", "arm64",
    "release", "stable", "beta", "alpha", "launcher", "engine", "core", "sdk"
}


# ==============================================================================
# DATA MODELS
# ==============================================================================
@dataclass
class InstalledApp:
    """Represents a normalized Windows application entry from the Registry."""
    name: str
    publisher: str
    install_date: str
    estimated_size_kb: int
    uninstall_string: str
    quiet_uninstall_string: str
    install_location: str
    display_icon: str
    registry_path: str
    registry_hive_name: str
    arch_view: str

    @property
    def formatted_size(self) -> str:
        if self.estimated_size_kb <= 0:
            return "Size Unknown"
        size_mb = self.estimated_size_kb / 1024.0
        if size_mb >= 1024.0:
            return f"{size_mb / 1024.0:.2f} GB"
        return f"{size_mb:.1f} MB"

    @property
    def formatted_date(self) -> str:
        raw = self.install_date.strip()
        if len(raw) == 8 and raw.isdigit():
            try:
                dt = datetime.datetime.strptime(raw, "%Y%m%d")
                return dt.strftime("%b %d, %Y")
            except ValueError:
                pass
        return raw if raw else "Unknown Date"

    @property
    def preferred_uninstall_cmd(self) -> str:
        return self.uninstall_string or self.quiet_uninstall_string


@dataclass
class LeftoverItem:
    """Represents a detected leftover artifact (Filesystem or Registry)."""
    item_type: str  # "FILE", "FOLDER", or "REGISTRY"
    path: str
    size_bytes: int = 0
    matched_reason: str = ""
    selected: bool = True

    @property
    def formatted_size(self) -> str:
        if self.item_type == "REGISTRY":
            return "Registry Key"
        return format_bytes(self.size_bytes)


# ==============================================================================
# UTILITY & SAFETY FUNCTIONS
# ==============================================================================
# ==============================================================================
# WINDOWS NATIVE ICON EXTRACTOR
# ==============================================================================
class IconExtractor:
    """Extracts native Windows icons from DisplayIcon paths using Shell32 ExtractIconEx."""

    _cache: Dict[str, Optional[ctk.CTkImage]] = {}

    @classmethod
    def get_app_icon(cls, icon_path_raw: str, size: Tuple[int, int] = (24, 24)) -> Optional[ctk.CTkImage]:
        if not icon_path_raw or sys.platform != "win32":
            return None

        clean_path = icon_path_raw.strip().strip('"').strip("'")
        if not clean_path:
            return None

        icon_index = 0
        if "," in clean_path:
            parts = clean_path.rsplit(",", 1)
            clean_path = parts[0].strip().strip('"')
            try:
                icon_index = int(parts[1].strip())
            except ValueError:
                icon_index = 0

        clean_path = os.path.expandvars(clean_path)
        if clean_path in cls._cache:
            return cls._cache[clean_path]

        # 1. Direct .ico file
        if clean_path.lower().endswith(".ico") and os.path.isfile(clean_path):
            try:
                pil_img = Image.open(clean_path).convert("RGBA")
                ctk_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=size)
                cls._cache[clean_path] = ctk_img
                return ctk_img
            except Exception:
                pass

        # 2. Extract from .exe / .dll via win32 API
        if (clean_path.lower().endswith((".exe", ".dll")) or "." not in os.path.basename(clean_path)) and os.path.isfile(clean_path):
            try:
                import win32gui
                import win32ui
                import win32con

                large, small = win32gui.ExtractIconEx(clean_path, icon_index)
                hicon = None
                if small and len(small) > 0:
                    hicon = small[0]
                elif large and len(large) > 0:
                    hicon = large[0]

                if hicon:
                    hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
                    hbmp = win32ui.CreateBitmap()
                    hbmp.CreateCompatibleBitmap(hdc, 32, 32)
                    memdc = hdc.CreateCompatibleDC()
                    memdc.SelectObject(hbmp)
                    win32gui.DrawIconEx(memdc.GetSafeHdc(), 0, 0, hicon, 32, 32, 0, 0, win32con.DI_NORMAL)

                    bmpinfo = hbmp.GetInfo()
                    bmpstr = hbmp.GetBitmapBits(True)
                    pil_img = Image.frombuffer(
                        "RGBA", (bmpinfo["bmWidth"], bmpinfo["bmHeight"]), bmpstr, "raw", "BGRA", 0, 1
                    )

                    win32gui.DestroyIcon(hicon)
                    for h in (large or []):
                        try:
                            win32gui.DestroyIcon(h)
                        except Exception:
                            pass
                    for h in (small or []):
                        try:
                            win32gui.DestroyIcon(h)
                        except Exception:
                            pass

                    ctk_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=size)
                    cls._cache[clean_path] = ctk_img
                    return ctk_img
            except Exception:
                pass

        cls._cache[clean_path] = None
        return None
    if num_bytes <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(num_bytes)
    unit_idx = 0
    while size >= 1024.0 and unit_idx < len(units) - 1:
        size /= 1024.0
        unit_idx += 1
    return f"{size:.2f} {units[unit_idx]}" if unit_idx >= 2 else f"{size:.0f} {units[unit_idx]}"


def is_user_admin() -> bool:
    """Checks if the current Python process holds Windows Administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> None:
    """Requests UAC elevation by re-executing the current script/binary via ShellExecuteW."""
    try:
        params = " ".join([f'"{arg}"' for arg in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        sys.exit(0)
    except Exception as exc:
        messagebox.showerror("Elevation Failed", f"Could not obtain Administrator privileges:\n{exc}")


class SafetyValidator:
    """
    Absolute Safety Gate enforcing strict blacklists on Windows system paths,
    shallow directories, and protected registry branches.
    """

    @staticmethod
    def get_blacklisted_roots() -> List[Path]:
        """Returns normalized Paths that must NEVER be deleted or modified."""
        sys_drive = os.environ.get("SystemDrive", "C:") + "\\"
        windir = os.environ.get("WINDIR", r"C:\Windows")
        prog_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        prog_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        user_profile = os.environ.get("USERPROFILE", "")

        protected = [
            Path(sys_drive),
            Path(windir),
            Path(windir) / "System32",
            Path(windir) / "SysWOW64",
            Path(windir) / "WinSxS",
            Path(prog_files),
            Path(prog_files_x86),
            Path(r"C:\Program Files\Common Files"),
            Path(r"C:\Program Files (x86)\Common Files"),
            Path(r"C:\ProgramData\Microsoft"),
            Path(r"C:\ProgramData\Package Cache"),
            Path(r"C:\Users"),
            Path(r"C:\Users\Public"),
            Path(r"C:\Users\Default"),
        ]

        if user_profile:
            up = Path(user_profile)
            protected.extend([
                up,
                up / "Desktop",
                up / "Documents",
                up / "Downloads",
                up / "Pictures",
                up / "Music",
                up / "Videos",
                up / "OneDrive",
                up / "AppData",
                up / "AppData" / "Local",
                up / "AppData" / "LocalLow",
                up / "AppData" / "Roaming",
                up / "AppData" / "Local" / "Temp",
                up / "AppData" / "Local" / "Microsoft",
                up / "AppData" / "Roaming" / "Microsoft",
            ])

        resolved = []
        for p in protected:
            try:
                resolved.append(p.resolve())
            except Exception:
                pass
        return resolved

    @classmethod
    def is_safe_filesystem_target(cls, target_path: str) -> bool:
        """
        Verifies a file/folder is strictly inside an allowed user/app data boundary
        and is NOT a root directory, Windows directory, or Program Files directory.
        """
        if not target_path or not target_path.strip():
            return False

        try:
            p = Path(target_path).resolve()
        except Exception:
            return False

        # 1. Never allow drive roots or shallow folders (e.g., C:\, C:\Users, C:\Users\Name)
        if len(p.parts) < 4:
            return False

        # 2. Check exact match against all protected container roots
        blacklisted = cls.get_blacklisted_roots()
        for b_path in blacklisted:
            if p == b_path:
                return False

        # 3. Strictly block anything inside C:\Windows, C:\Program Files, or C:\Program Files (x86)
        norm_str = str(p).lower()
        strict_forbidden_prefixes = [
            os.environ.get("WINDIR", r"C:\Windows").lower(),
            os.environ.get("ProgramFiles", r"C:\Program Files").lower(),
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)").lower(),
            r"c:\windows",
            r"c:\program files",
            r"c:\program files (x86)",
            r"c:\$recycle.bin",
            r"c:\system volume information",
            r"c:\recovery",
        ]
        for prefix in strict_forbidden_prefixes:
            if prefix and (norm_str == prefix or norm_str.startswith(prefix + "\\")):
                return False

        # 4. Block Microsoft core directories inside AppData/ProgramData
        ms_protected = [
            os.path.expandvars(r"%APPDATA%\Microsoft").lower(),
            os.path.expandvars(r"%LOCALAPPDATA%\Microsoft").lower(),
            os.path.expandvars(r"%PROGRAMDATA%\Microsoft").lower(),
            os.path.expandvars(r"%LOCALAPPDATA%\Packages").lower(),
        ]
        for ms_dir in ms_protected:
            if norm_str == ms_dir or norm_str.startswith(ms_dir + "\\"):
                return False

        return True

    @staticmethod
    def is_safe_registry_key(reg_path: str) -> bool:
        """Ensures only specific subkeys under HKCU\\Software\\<Target> can be removed."""
        norm = reg_path.strip().replace("/", "\\").upper()
        if not norm.startswith("HKCU\\SOFTWARE\\"):
            return False

        parts = [part for part in norm.split("\\") if part]
        # Must be at least HKCU \ SOFTWARE \ <AppOrVendorName>
        if len(parts) < 3:
            return False

        protected_vendors = {
            "MICROSOFT", "WINDOWS", "CLASSES", "POLICIES", "CLIENTS",
            "REGISTEREDAPPLICATIONS", "WOW6432NODE", " APPDATALOW", "GOOGLE", "MOZILLA"
        }
        if parts[2] in protected_vendors and len(parts) == 3:
            return False
        if parts[2] in {"MICROSOFT", "WINDOWS", "CLASSES", "POLICIES"}:
            return False

        return True


# ==============================================================================
# REGISTRY DISCOVERY PIPELINE
# ==============================================================================
class RegistryScanner:
    """Enumerates installed Windows applications across 64-bit, 32-bit, and User hives."""

    UNINSTALL_PATH = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"

    @classmethod
    def scan_installed_apps(cls, log_callback: Optional[Callable[[str], None]] = None) -> List[InstalledApp]:
        apps_by_signature: Dict[str, InstalledApp] = {}

        scan_targets = [
            (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_READ | winreg.KEY_WOW64_64KEY, "HKLM", "x64"),
            (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_READ | winreg.KEY_WOW64_32KEY, "HKLM", "x86"),
            (winreg.HKEY_CURRENT_USER, winreg.KEY_READ, "HKCU", "User"),
        ]

        for hive, access_mask, hive_label, arch_label in scan_targets:
            if log_callback:
                log_callback(f"Scanning registry branch: {hive_label}\\{cls.UNINSTALL_PATH} ({arch_label})...")
            try:
                with winreg.OpenKey(hive, cls.UNINSTALL_PATH, 0, access_mask) as root_key:
                    num_subkeys, _, _ = winreg.QueryInfoKey(root_key)
                    for idx in range(num_subkeys):
                        try:
                            subkey_name = winreg.EnumKey(root_key, idx)
                            subkey_full_path = f"{cls.UNINSTALL_PATH}\\{subkey_name}"
                            with winreg.OpenKey(hive, subkey_full_path, 0, access_mask) as app_key:
                                app = cls._parse_subkey(app_key, subkey_full_path, hive_label, arch_label)
                                if app:
                                    sig = f"{app.name.lower().strip()}|{app.publisher.lower().strip()}"
                                    if sig not in apps_by_signature:
                                        apps_by_signature[sig] = app
                        except OSError:
                            continue
            except OSError:
                continue

        sorted_apps = sorted(apps_by_signature.values(), key=lambda a: a.name.lower())
        if log_callback:
            log_callback(f"Registry scan complete. Discovered {len(sorted_apps)} user-facing applications.")
        return sorted_apps

    @staticmethod
    def _read_reg_value(key, value_name: str, default=None):
        try:
            val, _ = winreg.QueryValueEx(key, value_name)
            return val
        except OSError:
            return default

    @classmethod
    def _parse_subkey(
        cls, app_key, subkey_path: str, hive_label: str, arch_label: str
    ) -> Optional[InstalledApp]:
        # Filter out system components, hotfixes, and updates
        sys_comp = cls._read_reg_value(app_key, "SystemComponent", 0)
        if sys_comp == 1:
            return None

        release_type = str(cls._read_reg_value(app_key, "ReleaseType", "")).lower()
        if release_type in {"security update", "update", "hotfix", "servicepack"}:
            return None

        parent_key = str(cls._read_reg_value(app_key, "ParentKeyName", "")).strip()
        if parent_key:
            return None

        display_name = str(cls._read_reg_value(app_key, "DisplayName", "")).strip()
        if not display_name:
            return None

        # Skip KB updates by pattern
        if re.match(r"^(security update|update for|hotfix for|kb\d+)", display_name.lower()):
            return None

        uninstall_str = str(cls._read_reg_value(app_key, "UninstallString", "")).strip()
        quiet_uninstall_str = str(cls._read_reg_value(app_key, "QuietUninstallString", "")).strip()
        if not uninstall_str and not quiet_uninstall_str:
            return None

        publisher = str(cls._read_reg_value(app_key, "Publisher", "Unknown Publisher")).strip()
        install_date = str(cls._read_reg_value(app_key, "InstallDate", "")).strip()
        install_loc = str(cls._read_reg_value(app_key, "InstallLocation", "")).strip()
        display_icon = str(cls._read_reg_value(app_key, "DisplayIcon", "")).strip()

        raw_size = cls._read_reg_value(app_key, "EstimatedSize", 0)
        try:
            size_kb = int(raw_size)
        except (ValueError, TypeError):
            size_kb = 0

        return InstalledApp(
            name=display_name,
            publisher=publisher if publisher else "Unknown Publisher",
            install_date=install_date,
            estimated_size_kb=size_kb,
            uninstall_string=uninstall_str,
            quiet_uninstall_string=quiet_uninstall_str,
            install_location=install_loc,
            display_icon=display_icon,
            registry_path=subkey_path,
            registry_hive_name=hive_label,
            arch_view=arch_label,
        )


# ==============================================================================
# STEP 1 & 2: UNINSTALLER RUNNER & DEEP LEFTOVER AUDITOR
# ==============================================================================
class UninstallEngine:
    """Handles execution of official uninstallers and deep post-uninstall artifact auditing."""

    @staticmethod
    def normalize_uninstall_command(raw_cmd: str) -> str:
        """
        Ensures MSIExec strings or unquoted executable paths with spaces are properly formatted.
        """
        cmd = raw_cmd.strip()
        # Convert MsiExec /I{GUID} to /X{GUID} so it triggers uninstall instead of configure
        if "msiexec" in cmd.lower() and "/i" in cmd.lower() and "/x" not in cmd.lower():
            cmd = re.sub(r"(?i)/i", "/X", cmd, count=1)

        # If path is not quoted and contains spaces before .exe, quote the executable portion
        if not cmd.startswith('"') and ".exe" in cmd.lower():
            exe_idx = cmd.lower().find(".exe") + 4
            exe_part = cmd[:exe_idx].strip()
            args_part = cmd[exe_idx:].strip()
            if " " in exe_part and os.path.exists(exe_part):
                cmd = f'"{exe_part}" {args_part}'.strip()

        return cmd

    @classmethod
    def run_official_uninstaller(
        cls, app: InstalledApp, log_callback: Callable[[str], None]
    ) -> Tuple[bool, int, str]:
        """
        Executes the application's native uninstaller and blocks the worker thread
        until the process completes.
        """
        raw_cmd = app.preferred_uninstall_cmd
        if not raw_cmd:
            return False, -1, "No valid UninstallString registered for this program."

        cmd = cls.normalize_uninstall_command(raw_cmd)
        log_callback(f"Executing native uninstaller: {cmd}")

        try:
            proc = subprocess.Popen(cmd, shell=True)
            exit_code = proc.wait()
            log_callback(f"Uninstaller process finished with exit code: {exit_code}")
            return True, exit_code, ""
        except Exception as exc:
            err_msg = f"Failed to launch uninstaller: {exc}"
            log_callback(err_msg)
            return False, -1, err_msg

    @staticmethod
    def build_search_tokens(app: InstalledApp) -> Tuple[Set[str], Set[str]]:
        """
        Extracts high-confidence search tokens from DisplayName, Publisher, InstallLocation,
        and DisplayIcon executable stem while stripping version numbers and generic noise.
        """
        primary_tokens: Set[str] = set()
        vendor_tokens: Set[str] = set()

        # 1. Clean DisplayName (strip version numbers, architectures, parentheses)
        cleaned_name = re.sub(r"\([^)]*\)", " ", app.name)
        cleaned_name = re.sub(r"\bv?\d+(\.\d+)+([a-z0-9\-_.]*)?\b", " ", cleaned_name, flags=re.IGNORECASE)
        cleaned_name = re.sub(r"\b(x64|x86|64-bit|32-bit|amd64|arm64)\b", " ", cleaned_name, flags=re.IGNORECASE)
        cleaned_name = re.sub(r"[^a-zA-Z0-9\s\-_]", " ", cleaned_name).strip()

        if len(cleaned_name) >= 3 and cleaned_name.lower() not in STOP_TOKENS:
            primary_tokens.add(cleaned_name.lower())
            # Also add condensed no-space version (e.g., "Notepad++" / "Visual Studio" -> "visualstudio")
            compact = re.sub(r"[\s\-_]+", "", cleaned_name.lower())
            if len(compact) >= 4 and compact not in STOP_TOKENS:
                primary_tokens.add(compact)

        for word in re.split(r"[\s\-_]+", cleaned_name.lower()):
            if len(word) >= 4 and word not in STOP_TOKENS and not word.isdigit():
                primary_tokens.add(word)

        # 2. Extract folder name from InstallLocation if valid
        if app.install_location:
            try:
                loc_path = Path(app.install_location.strip('"'))
                folder_name = loc_path.name.lower().strip()
                if len(folder_name) >= 3 and folder_name not in STOP_TOKENS:
                    primary_tokens.add(folder_name)
            except Exception:
                pass

        # 3. Extract executable stem from DisplayIcon or UninstallString
        for path_source in (app.display_icon, app.uninstall_string):
            if not path_source:
                continue
            exe_match = re.search(r'([a-zA-Z0-9_\-\s]+)\.exe', path_source, flags=re.IGNORECASE)
            if exe_match:
                stem = exe_match.group(1).strip().lower()
                if len(stem) >= 4 and stem not in STOP_TOKENS and "unins" not in stem and "setup" not in stem:
                    primary_tokens.add(stem)

        # 4. Extract cleaned vendor tokens from Publisher
        if app.publisher and app.publisher.lower() != "unknown publisher":
            cleaned_pub = re.sub(r"[^a-zA-Z0-9\s\-_]", " ", app.publisher.lower())
            pub_words = [
                w for w in re.split(r"[\s\-_]+", cleaned_pub)
                if len(w) >= 4 and w not in STOP_TOKENS
            ]
            for pw in pub_words:
                vendor_tokens.add(pw)

        return primary_tokens, vendor_tokens

    @classmethod
    def calculate_path_size(cls, target: Path, max_files: int = 8000) -> int:
        """Calculates total byte size of a file or directory safely without following symlinks."""
        try:
            if target.is_symlink():
                return 0
            if target.is_file():
                return target.stat().st_size
        except OSError:
            return 0

        total = 0
        count = 0
        try:
            for root, _, files in os.walk(target, followlinks=False):
                for f in files:
                    count += 1
                    if count > max_files:
                        return total
                    fp = Path(root) / f
                    try:
                        if not fp.is_symlink():
                            total += fp.stat().st_size
                    except OSError:
                        continue
        except OSError:
            pass
        return total

    @classmethod
    def scan_leftovers(
        cls, app: InstalledApp, log_callback: Callable[[str], None]
    ) -> List[LeftoverItem]:
        """
        Scans %APPDATA%, %LOCALAPPDATA%, %LOCALAPPDATA%\\Temp, %PROGRAMDATA%,
        %USERPROFILE% (dot-folders), and HKCU\\Software for remaining artifacts.
        """
        primary_tokens, vendor_tokens = cls.build_search_tokens(app)
        log_callback(f"Auditing leftovers with tokens: {', '.join(sorted(primary_tokens))}")

        discovered: Dict[str, LeftoverItem] = {}

        # Define target filesystem roots
        appdata = os.environ.get("APPDATA", "")
        localappdata = os.environ.get("LOCALAPPDATA", "")
        programdata = os.environ.get("PROGRAMDATA", "")
        userprofile = os.environ.get("USERPROFILE", "")

        search_roots: List[Tuple[str, Path, bool]] = []
        if appdata:
            search_roots.append(("%APPDATA%", Path(appdata), False))
        if localappdata:
            search_roots.append(("%LOCALAPPDATA%", Path(localappdata), False))
            search_roots.append(("%LOCALAPPDATA%\\Temp", Path(localappdata) / "Temp", False))
        if programdata:
            search_roots.append(("%PROGRAMDATA%", Path(programdata), False))
        if userprofile:
            search_roots.append(("%USERPROFILE% (Dot-Folders)", Path(userprofile), True))

        # 1. Scan Filesystem Roots
        for label, root_path, dot_only in search_roots:
            if not root_path.exists():
                continue
            log_callback(f"Auditing directory: {label}...")

            try:
                entries = list(os.scandir(root_path))
            except OSError:
                continue

            for entry in entries:
                entry_name = entry.name
                entry_lower = entry_name.lower()

                if dot_only and not entry_name.startswith("."):
                    continue

                check_name = entry_lower.lstrip(".")
                matched_token = cls._match_name_against_tokens(check_name, primary_tokens)

                if matched_token:
                    full_path = entry.path
                    if SafetyValidator.is_safe_filesystem_target(full_path):
                        p_obj = Path(full_path)
                        item_type = "FOLDER" if entry.is_dir(follow_symlinks=False) else "FILE"
                        sz = cls.calculate_path_size(p_obj)
                        discovered[full_path.lower()] = LeftoverItem(
                            item_type=item_type,
                            path=full_path,
                            size_bytes=sz,
                            matched_reason=f"Matched '{matched_token}' in {label}",
                            selected=True,
                        )
                    continue

                # Check 2nd-level vendor subdirectories (e.g., %APPDATA%\<Publisher>\<AppName>)
                if not dot_only and entry.is_dir(follow_symlinks=False):
                    vendor_match = cls._match_name_against_tokens(check_name, vendor_tokens)
                    if vendor_match:
                        try:
                            for sub_entry in os.scandir(entry.path):
                                sub_match = cls._match_name_against_tokens(
                                    sub_entry.name.lower(), primary_tokens
                                )
                                if sub_match and SafetyValidator.is_safe_filesystem_target(sub_entry.path):
                                    p_obj = Path(sub_entry.path)
                                    item_type = "FOLDER" if sub_entry.is_dir(follow_symlinks=False) else "FILE"
                                    sz = cls.calculate_path_size(p_obj)
                                    discovered[sub_entry.path.lower()] = LeftoverItem(
                                        item_type=item_type,
                                        path=sub_entry.path,
                                        size_bytes=sz,
                                        matched_reason=f"Matched vendor '{vendor_match}' + '{sub_match}'",
                                        selected=True,
                                    )
                        except OSError:
                            continue

        # 2. Scan Safe User Registry Keys under HKCU\Software
        log_callback(r"Auditing registry branch: HKCU\Software...")
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software", 0, winreg.KEY_READ) as sw_key:
                num_subkeys, _, _ = winreg.QueryInfoKey(sw_key)
                for idx in range(num_subkeys):
                    try:
                        sub_name = winreg.EnumKey(sw_key, idx)
                        sub_lower = sub_name.lower()

                        # Direct match under HKCU\Software\<AppName>
                        matched_tok = cls._match_name_against_tokens(sub_lower, primary_tokens)
                        reg_full = f"HKCU\\Software\\{sub_name}"
                        if matched_tok and SafetyValidator.is_safe_registry_key(reg_full):
                            discovered[reg_full.lower()] = LeftoverItem(
                                item_type="REGISTRY",
                                path=reg_full,
                                size_bytes=0,
                                matched_reason=f"Matched registry key '{matched_tok}'",
                                selected=True,
                            )
                            continue

                        # Nested match under HKCU\Software\<Publisher>\<AppName>
                        vendor_tok = cls._match_name_against_tokens(sub_lower, vendor_tokens)
                        if vendor_tok:
                            with winreg.OpenKey(sw_key, sub_name, 0, winreg.KEY_READ) as vendor_key:
                                v_count, _, _ = winreg.QueryInfoKey(vendor_key)
                                for v_idx in range(v_count):
                                    nested_name = winreg.EnumKey(vendor_key, v_idx)
                                    nested_match = cls._match_name_against_tokens(
                                        nested_name.lower(), primary_tokens
                                    )
                                    nested_reg_full = f"HKCU\\Software\\{sub_name}\\{nested_name}"
                                    if nested_match and SafetyValidator.is_safe_registry_key(nested_reg_full):
                                        discovered[nested_reg_full.lower()] = LeftoverItem(
                                            item_type="REGISTRY",
                                            path=nested_reg_full,
                                            size_bytes=0,
                                            matched_reason=f"Matched vendor key '{vendor_tok}\\{nested_match}'",
                                            selected=True,
                                        )
                    except OSError:
                        continue
        except OSError:
            pass

        results = sorted(
            discovered.values(),
            key=lambda item: (0 if item.item_type != "REGISTRY" else 1, -item.size_bytes, item.path.lower()),
        )
        log_callback(f"Leftover audit complete. Identified {len(results)} candidate items.")
        return results

    @staticmethod
    def _match_name_against_tokens(candidate_name: str, tokens: Set[str]) -> Optional[str]:
        """
        Determines whether a folder/file/key name matches one of the application's search tokens
        using exact match, boundary token match, or high-similarity fuzzy matching.
        """
        if not candidate_name or candidate_name in STOP_TOKENS:
            return None

        compact_candidate = re.sub(r"[\s\-_.]+", "", candidate_name)
        candidate_words = set(re.split(r"[\s\-_.]+", candidate_name))

        for token in tokens:
            if len(token) < 3:
                continue
            # 1. Exact or compact match
            if candidate_name == token or compact_candidate == token:
                return token
            # 2. Word-boundary match for tokens >= 4 chars
            if len(token) >= 4 and token in candidate_words:
                return token
            # 3. Prefix/Substring match if token is strong (>= 5 chars)
            if len(token) >= 5 and token in compact_candidate:
                return token
            # 4. High-threshold fuzzy ratio
            if len(token) >= 5 and difflib.SequenceMatcher(None, compact_candidate, token).ratio() >= 0.86:
                return token

        return None

    @classmethod
    def wipe_selected_leftovers(
        cls, items: List[LeftoverItem], log_callback: Callable[[str], None]
    ) -> Tuple[int, int, int, List[str]]:
        """
        Deletes user-approved leftover files, directories, and HKCU registry keys
        after re-verifying every path through SafetyValidator.
        """
        deleted_count = 0
        bytes_freed = 0
        errors: List[str] = []

        def _force_remove_readonly(func, path, _exc_info):
            try:
                os.chmod(path, stat.S_IWRITE)
                func(path)
            except Exception:
                pass

        for item in items:
            if not item.selected:
                continue

            if item.item_type == "REGISTRY":
                if not SafetyValidator.is_safe_registry_key(item.path):
                    errors.append(f"Blocked unsafe registry path: {item.path}")
                    continue
                log_callback(f"Removing registry key: {item.path}")
                ok, err = cls._delete_registry_tree_hkcu(item.path)
                if ok:
                    deleted_count += 1
                else:
                    errors.append(f"{item.path} -> {err}")

            else:
                if not SafetyValidator.is_safe_filesystem_target(item.path):
                    errors.append(f"Safety Gate blocked protected path: {item.path}")
                    continue

                p = Path(item.path)
                if not p.exists():
                    continue

                log_callback(f"Deleting {item.item_type.lower()}: {item.path}")
                try:
                    if p.is_dir() and not p.is_symlink():
                        shutil.rmtree(p, onerror=_force_remove_readonly)
                    else:
                        os.chmod(p, stat.S_IWRITE)
                        p.unlink()
                    deleted_count += 1
                    bytes_freed += item.size_bytes
                except Exception as exc:
                    errors.append(f"{item.path} -> {exc}")

        return deleted_count, bytes_freed, len(errors), errors

    @classmethod
    def _delete_registry_tree_hkcu(cls, full_hkcu_path: str) -> Tuple[bool, str]:
        """Recursively deletes a subkey tree strictly under HKEY_CURRENT_USER."""
        rel_path = re.sub(r"^HKCU\\", "", full_hkcu_path, flags=re.IGNORECASE).strip("\\")
        if not rel_path.upper().startswith("SOFTWARE\\"):
            return False, "Registry deletion outside HKCU\\Software is prohibited."

        def _recursive_del(hive, subkey_path: str):
            with winreg.OpenKey(hive, subkey_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as current_key:
                while True:
                    try:
                        child_name = winreg.EnumKey(current_key, 0)
                        _recursive_del(hive, f"{subkey_path}\\{child_name}")
                    except OSError:
                        break
            winreg.DeleteKey(hive, subkey_path)

        try:
            _recursive_del(winreg.HKEY_CURRENT_USER, rel_path)
            return True, ""
        except OSError as exc:
            return False, str(exc)


# ==============================================================================
# STEP 3: INTERACTIVE CONSENT DIALOG (MODAL SAFETY GATE)
# ==============================================================================
class LeftoverConsentModal(ctk.CTkToplevel):
    """
    Modal dialog presenting every detected leftover file, directory, and registry key
    with individual checkboxes, disk space calculation, and explicit user consent controls.
    """

    def __init__(
        self,
        parent: ctk.CTk,
        app: InstalledApp,
        leftovers: List[LeftoverItem],
        on_confirm_wipe: Callable[[List[LeftoverItem]], None],
        on_skip: Callable[[], None],
    ):
        super().__init__(parent)
        self.app_entry = app
        self.leftovers = leftovers
        self.on_confirm_wipe = on_confirm_wipe
        self.on_skip = on_skip
        self.checkbox_vars: List[Tuple[ctk.BooleanVar, LeftoverItem]] = []

        self.title(f"PureUninstaller — Leftover Audit: {app.name}")
        self.geometry("880x620")
        self.minsize(760, 500)
        self.configure(fg_color=PALETTE["bg_root"])

        # Make modal
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._handle_skip)

        self._build_ui()
        self._update_summary_label()

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Header Banner
        header = ctk.CTkFrame(
            self, fg_color=PALETTE["bg_surface"], corner_radius=12, border_width=1, border_color=PALETTE["border"]
        )
        header.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        title_lbl = ctk.CTkLabel(
            header,
            text=f"Deep Leftover Transparency Audit — {self.app_entry.name}",
            font=ctk.CTkFont(family="Segoe UI Variable Display", size=18, weight="bold"),
            text_color=PALETTE["text_primary"],
            anchor="w",
        )
        title_lbl.grid(row=0, column=0, padx=18, pady=(14, 2), sticky="ew")

        subtitle_lbl = ctk.CTkLabel(
            header,
            text=(
                "Review all detected leftover files, caches, and HKCU registry keys below. "
                "Protected system directories (C:\\Windows, Program Files, System32) are strictly excluded."
            ),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=PALETTE["text_secondary"],
            anchor="w",
            justify="left",
        )
        subtitle_lbl.grid(row=1, column=0, padx=18, pady=(0, 12), sticky="ew")

        # Selection Toolbar
        toolbar = ctk.CTkFrame(header, fg_color="transparent")
        toolbar.grid(row=2, column=0, padx=18, pady=(0, 12), sticky="ew")

        btn_select_all = ctk.CTkButton(
            toolbar,
            text="Select All",
            width=100,
            height=28,
            corner_radius=6,
            fg_color=PALETTE["bg_card"],
            hover_color=PALETTE["bg_card_hover"],
            command=lambda: self._set_all_checkboxes(True),
        )
        btn_select_all.pack(side="left", padx=(0, 8))

        btn_deselect_all = ctk.CTkButton(
            toolbar,
            text="Deselect All",
            width=100,
            height=28,
            corner_radius=6,
            fg_color=PALETTE["bg_card"],
            hover_color=PALETTE["bg_card_hover"],
            command=lambda: self._set_all_checkboxes(False),
        )
        btn_deselect_all.pack(side="left")

        self.summary_badge = ctk.CTkLabel(
            toolbar,
            text="",
            font=ctk.CTkFont(family="Segoe UI Semibold", size=13),
            text_color=PALETTE["accent"],
        )
        self.summary_badge.pack(side="right")

        # Scrollable Artifact List
        self.scroll_frame = ctk.CTkScrollableFrame(
            self,
            fg_color=PALETTE["bg_surface"],
            corner_radius=12,
            border_width=1,
            border_color=PALETTE["border"],
        )
        self.scroll_frame.grid(row=1, column=0, padx=20, pady=8, sticky="nsew")
        self.scroll_frame.grid_columnconfigure(0, weight=1)

        for idx, item in enumerate(self.leftovers):
            row_card = ctk.CTkFrame(
                self.scroll_frame,
                fg_color=PALETTE["bg_card"],
                corner_radius=8,
                border_width=1,
                border_color=PALETTE["border"],
            )
            row_card.grid(row=idx, column=0, padx=8, pady=5, sticky="ew")
            row_card.grid_columnconfigure(1, weight=1)

            var = ctk.BooleanVar(value=item.selected)
            self.checkbox_vars.append((var, item))

            cb = ctk.CTkCheckBox(
                row_card,
                text="",
                variable=var,
                width=24,
                checkbox_width=20,
                checkbox_height=20,
                corner_radius=5,
                fg_color=PALETTE["accent"],
                hover_color=PALETTE["accent_hover"],
                command=self._on_checkbox_toggle,
            )
            cb.grid(row=0, column=0, rowspan=2, padx=(14, 6), pady=10, sticky="w")

            path_lbl = ctk.CTkLabel(
                row_card,
                text=item.path,
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color=PALETTE["text_primary"],
                anchor="w",
            )
            path_lbl.grid(row=0, column=1, padx=6, pady=(8, 0), sticky="ew")

            meta_lbl = ctk.CTkLabel(
                row_card,
                text=f"[{item.item_type}]  •  {item.matched_reason}",
                font=ctk.CTkFont(family="Segoe UI", size=11),
                text_color=PALETTE["text_muted"],
                anchor="w",
            )
            meta_lbl.grid(row=1, column=1, padx=6, pady=(0, 8), sticky="ew")

            badge_color = PALETTE["warning"] if item.item_type == "REGISTRY" else PALETTE["success"]
            size_lbl = ctk.CTkLabel(
                row_card,
                text=item.formatted_size,
                font=ctk.CTkFont(family="Segoe UI Semibold", size=12),
                text_color=badge_color,
                anchor="e",
            )
            size_lbl.grid(row=0, column=2, rowspan=2, padx=14, pady=10, sticky="e")

        # Footer Action Bar
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=2, column=0, padx=20, pady=(10, 20), sticky="ew")
        footer.grid_columnconfigure(0, weight=1)

        safety_note = ctk.CTkLabel(
            footer,
            text="100% Consent Policy: Only checked items will be permanently removed.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=PALETTE["text_secondary"],
            anchor="w",
        )
        safety_note.grid(row=0, column=0, sticky="w")

        btn_skip = ctk.CTkButton(
            footer,
            text="Skip / Keep All",
            width=140,
            height=38,
            corner_radius=8,
            fg_color=PALETTE["bg_card"],
            hover_color=PALETTE["bg_card_hover"],
            text_color=PALETTE["text_primary"],
            font=ctk.CTkFont(family="Segoe UI Semibold", size=13),
            command=self._handle_skip,
        )
        btn_skip.grid(row=0, column=1, padx=(10, 10))

        self.btn_wipe = ctk.CTkButton(
            footer,
            text="Wipe Selected Leftovers",
            width=210,
            height=38,
            corner_radius=8,
            fg_color=PALETTE["danger"],
            hover_color=PALETTE["danger_hover"],
            text_color="#FFFFFF",
            font=ctk.CTkFont(family="Segoe UI Semibold", size=13),
            command=self._handle_confirm,
        )
        self.btn_wipe.grid(row=0, column=2)

    def _set_all_checkboxes(self, state: bool) -> None:
        for var, item in self.checkbox_vars:
            var.set(state)
            item.selected = state
        self._update_summary_label()

    def _on_checkbox_toggle(self) -> None:
        for var, item in self.checkbox_vars:
            item.selected = bool(var.get())
        self._update_summary_label()

    def _update_summary_label(self) -> None:
        selected_items = [item for _, item in self.checkbox_vars if item.selected]
        total_bytes = sum(i.size_bytes for i in selected_items)
        self.summary_badge.configure(
            text=f"Selected: {len(selected_items)} / {len(self.leftovers)} items  ({format_bytes(total_bytes)} to free)"
        )
        if selected_items:
            self.btn_wipe.configure(state="normal", text=f"Wipe Selected ({format_bytes(total_bytes)})")
        else:
            self.btn_wipe.configure(state="disabled", text="Wipe Selected Leftovers")

    def _handle_confirm(self) -> None:
        selected = [item for _, item in self.checkbox_vars if item.selected]
        self.grab_release()
        self.destroy()
        self.on_confirm_wipe(selected)

    def _handle_skip(self) -> None:
        self.grab_release()
        self.destroy()
        self.on_skip()


# ==============================================================================
# MAIN WINDOWS 11 FLUENT APPLICATION
# ==============================================================================
class PureUninstallerApp(ctk.CTk):
    """Main Desktop GUI Controller for PureUninstaller."""

    MAX_VISIBLE_CARDS = 150  # Virtualized display cap for smooth scrolling

    def __init__(self):
        super().__init__()

        self.title("PureUninstaller — Windows 11 Deep Application & Artifact Cleaner")
        self.geometry("1120x740")
        self.minsize(920, 600)
        self.configure(fg_color=PALETTE["bg_root"])

        self.all_apps: List[InstalledApp] = []
        self.filtered_apps: List[InstalledApp] = []
        self.card_widgets: List[ctk.CTkFrame] = []
        self.is_busy: bool = False
        self._search_after_id: Optional[str] = None

        self._build_layout()
        self.after(150, self.refresh_installed_apps)

    # --------------------------------------------------------------------------
    # UI CONSTRUCTION
    # --------------------------------------------------------------------------
    def _build_layout(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 1. Left Fluent Sidebar
        self.sidebar = ctk.CTkFrame(
            self,
            width=260,
            fg_color=PALETTE["bg_surface"],
            corner_radius=0,
            border_width=1,
            border_color=PALETTE["border"],
        )
        self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_columnconfigure(0, weight=1)

        brand_title = ctk.CTkLabel(
            self.sidebar,
            text="PureUninstaller",
            font=ctk.CTkFont(family="Segoe UI Variable Display", size=24, weight="bold"),
            text_color=PALETTE["text_primary"],
            anchor="w",
        )
        brand_title.grid(row=0, column=0, padx=22, pady=(26, 2), sticky="ew")

        brand_sub = ctk.CTkLabel(
            self.sidebar,
            text="Fluent Leftover Auditor v1.2.0",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=PALETTE["accent"],
            anchor="w",
        )
        brand_sub.grid(row=1, column=0, padx=22, pady=(0, 20), sticky="ew")

        # Privilege Status Card
        admin_active = is_user_admin()
        priv_card = ctk.CTkFrame(
            self.sidebar,
            fg_color=PALETTE["bg_card"],
            corner_radius=10,
            border_width=1,
            border_color=PALETTE["border"],
        )
        priv_card.grid(row=2, column=0, padx=18, pady=(0, 18), sticky="ew")

        priv_status_text = "Administrator Mode" if admin_active else "Standard User Mode"
        priv_color = PALETTE["success"] if admin_active else PALETTE["warning"]

        priv_lbl = ctk.CTkLabel(
            priv_card,
            text=f"●  {priv_status_text}",
            font=ctk.CTkFont(family="Segoe UI Semibold", size=12),
            text_color=priv_color,
            anchor="w",
        )
        priv_lbl.pack(fill="x", padx=14, pady=(10, 4))

        priv_desc = ctk.CTkLabel(
            priv_card,
            text=(
                "Full HKLM & ProgramData access enabled."
                if admin_active
                else "Some system-wide uninstallers may request elevation."
            ),
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=PALETTE["text_secondary"],
            anchor="w",
            justify="left",
            wraplength=195,
        )
        priv_desc.pack(fill="x", padx=14, pady=(0, 10))

        if not admin_active:
            btn_elevate = ctk.CTkButton(
                priv_card,
                text="Restart as Administrator",
                height=28,
                corner_radius=6,
                fg_color=PALETTE["bg_surface"],
                hover_color=PALETTE["bg_card_hover"],
                text_color=PALETTE["warning"],
                font=ctk.CTkFont(family="Segoe UI Semibold", size=11),
                command=relaunch_as_admin,
            )
            btn_elevate.pack(fill="x", padx=12, pady=(0, 10))

        # Stats Counter Panel
        self.stats_card = ctk.CTkFrame(
            self.sidebar,
            fg_color=PALETTE["bg_card"],
            corner_radius=10,
            border_width=1,
            border_color=PALETTE["border"],
        )
        self.stats_card.grid(row=3, column=0, padx=18, pady=(0, 18), sticky="ew")

        self.lbl_total_apps = ctk.CTkLabel(
            self.stats_card,
            text="Installed Apps: —",
            font=ctk.CTkFont(family="Segoe UI Semibold", size=13),
            text_color=PALETTE["text_primary"],
            anchor="w",
        )
        self.lbl_total_apps.pack(fill="x", padx=14, pady=(12, 2))

        self.lbl_total_size = ctk.CTkLabel(
            self.stats_card,
            text="Estimated Footprint: —",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=PALETTE["text_secondary"],
            anchor="w",
        )
        self.lbl_total_size.pack(fill="x", padx=14, pady=(0, 12))

        # Refresh Installed Apps Button
        self.btn_refresh = ctk.CTkButton(
            self.sidebar,
            text="↻  Refresh Installed Apps",
            height=40,
            corner_radius=8,
            fg_color=PALETTE["accent"],
            hover_color=PALETTE["accent_hover"],
            text_color="#FFFFFF",
            font=ctk.CTkFont(family="Segoe UI Semibold", size=13),
            command=self.refresh_installed_apps,
        )
        self.btn_refresh.grid(row=4, column=0, padx=18, pady=(0, 16), sticky="ew")

        # Safety Architecture Callout
        safety_card = ctk.CTkFrame(
            self.sidebar,
            fg_color=PALETTE["bg_card"],
            corner_radius=10,
            border_width=1,
            border_color=PALETTE["border"],
        )
        safety_card.grid(row=5, column=0, padx=18, pady=(8, 18), sticky="ew")

        safety_title = ctk.CTkLabel(
            safety_card,
            text="Safety Guard Active",
            font=ctk.CTkFont(family="Segoe UI Semibold", size=12),
            text_color=PALETTE["success"],
            anchor="w",
        )
        safety_title.pack(fill="x", padx=14, pady=(10, 4))

        safety_body = ctk.CTkLabel(
            safety_card,
            text=(
                "• Official uninstaller runs first\n"
                "• 100% Opt-in leftover consent\n"
                "• System32, Windows & Program Files hard-locked"
            ),
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=PALETTE["text_secondary"],
            justify="left",
            anchor="w",
        )
        safety_body.pack(fill="x", padx=14, pady=(0, 10))

        # 2. Main Right Content Area
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.grid(row=0, column=1, padx=22, pady=(20, 10), sticky="nsew")
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(1, weight=1)

        # Top Search Bar & Filter Header
        top_bar = ctk.CTkFrame(
            self.main_container,
            fg_color=PALETTE["bg_surface"],
            corner_radius=12,
            border_width=1,
            border_color=PALETTE["border"],
        )
        top_bar.grid(row=0, column=0, pady=(0, 14), sticky="ew")
        top_bar.grid_columnconfigure(0, weight=1)

        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", self._on_search_modified)

        self.search_entry = ctk.CTkEntry(
            top_bar,
            textvariable=self.search_var,
            placeholder_text="Search installed programs by name or publisher (fuzzy real-time filter)...",
            height=40,
            corner_radius=8,
            border_width=1,
            border_color=PALETTE["border"],
            fg_color=PALETTE["bg_card"],
            text_color=PALETTE["text_primary"],
            font=ctk.CTkFont(family="Segoe UI", size=13),
        )
        self.search_entry.grid(row=0, column=0, padx=(14, 10), pady=12, sticky="ew")

        btn_clear_search = ctk.CTkButton(
            top_bar,
            text="Clear",
            width=72,
            height=40,
            corner_radius=8,
            fg_color=PALETTE["bg_card"],
            hover_color=PALETTE["bg_card_hover"],
            text_color=PALETTE["text_secondary"],
            command=lambda: self.search_var.set(""),
        )
        btn_clear_search.grid(row=0, column=1, padx=(0, 14), pady=12)

        # Scrollable Application List
        self.apps_scroll = ctk.CTkScrollableFrame(
            self.main_container,
            fg_color=PALETTE["bg_surface"],
            corner_radius=12,
            border_width=1,
            border_color=PALETTE["border"],
        )
        self.apps_scroll.grid(row=1, column=0, sticky="nsew")
        self.apps_scroll.grid_columnconfigure(0, weight=1)

        # 3. Bottom Real-Time Status & Activity Log Bar
        self.status_bar = ctk.CTkFrame(
            self,
            height=44,
            fg_color=PALETTE["bg_surface"],
            corner_radius=0,
            border_width=1,
            border_color=PALETTE["border"],
        )
        self.status_bar.grid(row=1, column=1, sticky="ew")
        self.status_bar.grid_columnconfigure(0, weight=1)

        self.lbl_status = ctk.CTkLabel(
            self.status_bar,
            text="Ready.",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=PALETTE["text_secondary"],
            anchor="w",
        )
        self.lbl_status.grid(row=0, column=0, padx=18, pady=10, sticky="ew")

        self.progress_bar = ctk.CTkProgressBar(
            self.status_bar,
            width=180,
            height=8,
            corner_radius=4,
            progress_color=PALETTE["accent"],
            mode="indeterminate",
        )
        self.progress_bar.grid(row=0, column=1, padx=18, pady=10, sticky="e")
        self.progress_bar.grid_remove()

    # --------------------------------------------------------------------------
    # THREAD-SAFE LOGGING & BUSY STATE
    # --------------------------------------------------------------------------
    def log_status(self, message: str) -> None:
        """Thread-safe update of the bottom status/log bar."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}]  {message}"
        self.after(0, lambda: self.lbl_status.configure(text=formatted))

    def set_busy_state(self, busy: bool) -> None:
        """Toggles progress indicator and disables/enables action buttons during background jobs."""
        self.is_busy = busy

        def _apply():
            if busy:
                self.btn_refresh.configure(state="disabled")
                self.progress_bar.grid()
                self.progress_bar.start()
            else:
                self.btn_refresh.configure(state="normal")
                self.progress_bar.stop()
                self.progress_bar.grid_remove()

        self.after(0, _apply)

    # --------------------------------------------------------------------------
    # REGISTRY LOADING & FUZZY SEARCH FILTERING
    # --------------------------------------------------------------------------
    def refresh_installed_apps(self) -> None:
        """Spawns a background worker thread to enumerate all installed applications."""
        if self.is_busy:
            return
        self.set_busy_state(True)

        def _worker():
            apps = RegistryScanner.scan_installed_apps(log_callback=self.log_status)
            self.after(0, lambda: self._on_apps_loaded(apps))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_apps_loaded(self, apps: List[InstalledApp]) -> None:
        self.all_apps = apps
        total_kb = sum(a.estimated_size_kb for a in apps if a.estimated_size_kb > 0)
        total_gb = total_kb / (1024.0 * 1024.0)

        self.lbl_total_apps.configure(text=f"Installed Apps: {len(apps)}")
        self.lbl_total_size.configure(text=f"Estimated Footprint: {total_gb:.2f} GB")

        self._apply_search_filter()
        self.set_busy_state(False)

    def _on_search_modified(self, *_args) -> None:
        """Debounces real-time search keystrokes by 120ms for smooth responsiveness."""
        if self._search_after_id:
            self.after_cancel(self._search_after_id)
        self._search_after_id = self.after(120, self._apply_search_filter)

    def _apply_search_filter(self) -> None:
        query = self.search_var.get().strip().lower()
        if not query:
            self.filtered_apps = list(self.all_apps)
        else:
            scored: List[Tuple[float, InstalledApp]] = []
            for app in self.all_apps:
                haystack = f"{app.name} {app.publisher}".lower()
                if query in haystack:
                    # Prioritize prefix and exact substring hits
                    score = 1.0 if app.name.lower().startswith(query) else 0.9
                    scored.append((score, app))
                else:
                    # Fuzzy match fallback against name and publisher
                    name_ratio = difflib.SequenceMatcher(None, query, app.name.lower()).ratio()
                    pub_ratio = difflib.SequenceMatcher(None, query, app.publisher.lower()).ratio()
                    best_ratio = max(name_ratio, pub_ratio)
                    if best_ratio >= 0.52:
                        scored.append((best_ratio, app))

            scored.sort(key=lambda pair: (-pair[0], pair[1].name.lower()))
            self.filtered_apps = [pair[1] for pair in scored]

        self._render_app_cards()

    def _render_app_cards(self) -> None:
        """Renders filtered application cards into the scrollable viewport."""
        for widget in self.card_widgets:
            widget.destroy()
        self.card_widgets.clear()

        visible_slice = self.filtered_apps[: self.MAX_VISIBLE_CARDS]

        if not visible_slice:
            empty_lbl = ctk.CTkLabel(
                self.apps_scroll,
                text="No matching installed programs found.",
                font=ctk.CTkFont(family="Segoe UI", size=14),
                text_color=PALETTE["text_muted"],
            )
            empty_lbl.grid(row=0, column=0, pady=50)
            self.card_widgets.append(empty_lbl)
            return

        for idx, app in enumerate(visible_slice):
            card = self._create_app_card(self.apps_scroll, app)
            card.grid(row=idx, column=0, padx=10, pady=6, sticky="ew")
            self.card_widgets.append(card)

    def _create_app_card(self, parent, app: InstalledApp) -> ctk.CTkFrame:
        card = ctk.CTkFrame(
            parent,
            fg_color=PALETTE["bg_card"],
            corner_radius=8,
            border_width=1,
            border_color=PALETTE["border"],
        )
        card.grid_columnconfigure(1, weight=1)

        # Micro indicator badge / icon placeholder
        icon_box = ctk.CTkFrame(
            card,
            width=36,
            height=36,
            corner_radius=8,
            fg_color=PALETTE["accent_subtle"],
            border_width=1,
            border_color=PALETTE["border_light"],
        )
        icon_box.grid(row=0, column=0, padx=(14, 10), pady=10, sticky="w")
        icon_box.grid_propagate(False)

        initial_letter = app.name[:1].upper() if app.name else "A"
        app_icon = IconExtractor.get_app_icon(app.display_icon, size=(22, 22))

        if app_icon:
            icon_lbl = ctk.CTkLabel(
                icon_box,
                image=app_icon,
                text="",
            )
        else:
            icon_lbl = ctk.CTkLabel(
                icon_box,
                text=initial_letter,
                font=ctk.CTkFont(family="Segoe UI Variable Display", size=15, weight="bold"),
                text_color=PALETTE["accent"],
            )
        icon_lbl.place(relx=0.5, rely=0.5, anchor="center")

        # Center Info Column
        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.grid(row=0, column=1, padx=(0, 10), pady=10, sticky="ew")
        info_frame.grid_columnconfigure(0, weight=1)

        name_row = ctk.CTkFrame(info_frame, fg_color="transparent")
        name_row.grid(row=0, column=0, sticky="ew")

        title_lbl = ctk.CTkLabel(
            name_row,
            text=app.name,
            font=ctk.CTkFont(family="Segoe UI Variable Display", size=14, weight="bold"),
            text_color=PALETTE["text_primary"],
            anchor="w",
        )
        title_lbl.pack(side="left", padx=(0, 8))

        # Modern Arch Badge (x64 / x86 / User)
        arch_color = PALETTE["success"] if "64" in app.arch_view else PALETTE["warning"]
        arch_badge = ctk.CTkLabel(
            name_row,
            text=f" {app.arch_view.upper()} ",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=arch_color,
            fg_color=PALETTE["bg_surface"],
            corner_radius=4,
        )
        arch_badge.pack(side="left")

        sub_text = f"{app.publisher}  •  {app.formatted_date}  •  {app.registry_hive_name}"
        sub_lbl = ctk.CTkLabel(
            info_frame,
            text=sub_text,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=PALETTE["text_secondary"],
            anchor="w",
        )
        sub_lbl.grid(row=1, column=0, pady=(2, 0), sticky="ew")

        # Right Actions Frame
        right_frame = ctk.CTkFrame(card, fg_color="transparent")
        right_frame.grid(row=0, column=2, padx=14, pady=10, sticky="e")

        size_badge = ctk.CTkLabel(
            right_frame,
            text=app.formatted_size,
            font=ctk.CTkFont(family="Segoe UI Semibold", size=12),
            text_color=PALETTE["text_secondary"],
            width=85,
            anchor="e",
        )
        size_badge.pack(side="left", padx=(0, 14))

        # Modern Ghost/Outline Action Button
        btn_action = ctk.CTkButton(
            right_frame,
            text="Uninstall",
            width=110,
            height=30,
            corner_radius=6,
            fg_color=PALETTE["bg_surface"],
            hover_color=PALETTE["accent_hover"],
            border_width=1,
            border_color=PALETTE["border_light"],
            text_color=PALETTE["text_primary"],
            font=ctk.CTkFont(family="Segoe UI Semibold", size=11),
            command=lambda target_app=app: self.initiate_uninstall_workflow(target_app),
        )
        btn_action.pack(side="left")

        # Hover Effect on card
        def _on_enter(_e):
            card.configure(fg_color=PALETTE["bg_card_hover"], border_color=PALETTE["accent"])

        def _on_leave(_e):
            card.configure(fg_color=PALETTE["bg_card"], border_color=PALETTE["border"])

        card.bind("<Enter>", _on_enter)
        card.bind("<Leave>", _on_leave)
        info_frame.bind("<Enter>", _on_enter)
        info_frame.bind("<Leave>", _on_leave)

        return card

    # --------------------------------------------------------------------------
    # THREE-STEP UNINSTALL & AUDIT PIPELINE
    # --------------------------------------------------------------------------
    def initiate_uninstall_workflow(self, app: InstalledApp) -> None:
        """
        Coordinates Step 1 (Official Uninstall), Step 2 (Deep Leftover Scan),
        and Step 3 (Interactive Consent Dialog).
        """
        if self.is_busy:
            messagebox.showinfo(
                "Operation in Progress",
                "Please wait for the current operation to complete before starting another uninstall.",
            )
            return

        confirm = messagebox.askyesno(
            "Confirm Official Uninstallation",
            f"Launch the official uninstaller for '{app.name}'?\n\n"
            f"Publisher: {app.publisher}\n"
            f"Command: {app.preferred_uninstall_cmd}\n\n"
            "After the official uninstaller finishes, PureUninstaller will perform a "
            "read-only transparency scan for leftover files and registry entries.",
        )
        if not confirm:
            return

        self.set_busy_state(True)

        def _pipeline_worker():
            # Step 1: Official Uninstallation
            ok, exit_code, err = UninstallEngine.run_official_uninstaller(app, self.log_status)
            if not ok:
                self.after(
                    0,
                    lambda: messagebox.showerror(
                        "Uninstaller Launch Error",
                        f"Could not execute the official uninstaller for {app.name}:\n\n{err}",
                    ),
                )
                self.set_busy_state(False)
                return

            # Step 2: Deep Leftover Scan & Transparency Audit
            self.log_status(f"Official uninstaller exited ({exit_code}). Starting deep leftover audit...")
            leftovers = UninstallEngine.scan_leftovers(app, self.log_status)

            # Dispatch Step 3 on the main UI thread
            self.after(0, lambda: self._present_audit_results(app, leftovers))

        threading.Thread(target=_pipeline_worker, daemon=True).start()

    def _present_audit_results(self, app: InstalledApp, leftovers: List[LeftoverItem]) -> None:
        self.set_busy_state(False)

        if not leftovers:
            self.log_status(f"Clean uninstall verified for '{app.name}'. Zero leftover artifacts found.")
            messagebox.showinfo(
                "Clean Uninstall Complete",
                f"'{app.name}' was uninstalled and zero leftover files or registry entries were detected.",
            )
            self.refresh_installed_apps()
            return

        # Step 3: Interactive Consent Modal
        LeftoverConsentModal(
            parent=self,
            app=app,
            leftovers=leftovers,
            on_confirm_wipe=lambda selected: self._execute_leftover_wipe(app, selected),
            on_skip=lambda: self._on_leftover_skip(app),
        )

    def _execute_leftover_wipe(self, app: InstalledApp, selected_items: List[LeftoverItem]) -> None:
        if not selected_items:
            self._on_leftover_skip(app)
            return

        self.set_busy_state(True)

        def _wipe_worker():
            deleted_count, bytes_freed, err_count, errors = UninstallEngine.wipe_selected_leftovers(
                selected_items, self.log_status
            )

            def _finish():
                self.set_busy_state(False)
                freed_str = format_bytes(bytes_freed)
                self.log_status(
                    f"Wipe complete for '{app.name}': {deleted_count} items removed ({freed_str} freed)."
                )
                summary = (
                    f"Cleanup Summary for {app.name}:\n\n"
                    f"• Removed Items: {deleted_count}\n"
                    f"• Disk Space Freed: {freed_str}\n"
                    f"• Skipped / Errors: {err_count}"
                )
                if errors:
                    summary += "\n\nDetails (first 5):\n" + "\n".join(errors[:5])
                messagebox.showinfo("Leftover Cleanup Complete", summary)
                self.refresh_installed_apps()

            self.after(0, _finish)

        threading.Thread(target=_wipe_worker, daemon=True).start()

    def _on_leftover_skip(self, app: InstalledApp) -> None:
        self.log_status(f"Leftover cleanup skipped by user for '{app.name}'. All files kept intact.")
        self.refresh_installed_apps()


# ==============================================================================
# APPLICATION ENTRY POINT
# ==============================================================================
if __name__ == "__main__":
    if sys.platform != "win32":
        raise SystemExit("PureUninstaller requires Windows 10/11 (win32 platform).")

    # Enable High-DPI awareness on Windows 11 displays
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

    app_instance = PureUninstallerApp()
    app_instance.mainloop()