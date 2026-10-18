# PureUninstaller (qun)

> Ultra-lightweight, zero-bloat Windows 11 Fluent Desktop Uninstaller & Deep Leftover Auditor.

![Windows 11 Fluent](https://img.shields.io/badge/Platform-Windows_11-0078D4?style=flat-square&logo=windows11)
![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![CustomTkinter](https://img.shields.io/badge/UI-CustomTkinter-00A8E8?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## ⚡ Highlights

- **Zero Bloat & Native Speed**: No Electron, no hidden telemetry services, < 35 MB RAM footprint.
- **Complete Registry Discovery**: Enumerates 64-bit and 32-bit apps (`HKLM` & `HKCU`) without missing legacy or modern software.
- **Non-Freezing Multithreaded Engine**: Native uninstaller runs safely in background threads.
- **Deep Leftover Footprint Scanner**: Audits `%APPDATA%`, `%LOCALAPPDATA%`, `%LOCALAPPDATA%\Temp`, `%PROGRAMDATA%`, `%USERPROFILE%` dot-folders, and safe `HKCU\Software` keys.
- **100% User Consent Gate**: Interactive modal dialog showing exact disk size and individual checkboxes for every leftover item before deletion.
- **Hard-Locked Safety Guard**: Strict blacklists protecting `C:\Windows`, `System32`, `Program Files`, and core OS directories.

---

## 🚀 Running from Source

```powershell
git clone https://github.com/ShiTmoZ/qun.git
cd qun
pip install -r requirements.txt
python pure_uninstaller.py
```

---

## 📦 Automated GitHub Actions CI/CD

Every push to `main` automatically triggers `.github/workflows/build.yml` to package a standalone, self-contained `PureUninstaller.exe` for 64-bit Windows.
