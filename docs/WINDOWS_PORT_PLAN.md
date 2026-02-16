# AngelClaw — Windows Port Plan

## Overview

ANGELNODE currently targets Linux. This document outlines the work needed
to support Windows endpoints (workstations, servers, AI hosts) with full
policy enforcement and Cloud API connectivity.

**Goal:** Ship a Windows ANGELNODE agent alongside the existing Linux agent,
sharing the same Cloud API and policy engine.

---

## 1. Platform-Specific Changes

### 1.1 File Paths & OS Detection

| Area | Linux | Windows |
|------|-------|---------|
| Config dir | `/etc/angelnode/` | `%PROGRAMDATA%\AngelNode\` |
| Log dir | `/var/log/angelnode/` | `%PROGRAMDATA%\AngelNode\logs\` |
| Default policy | `/etc/angelnode/policy.json` | `%PROGRAMDATA%\AngelNode\policy.json` |
| Temp/cache | `/tmp/angelnode/` | `%TEMP%\AngelNode\` |

**Action:** Abstract all path construction through `pathlib.Path` and a
`platform_paths.py` module that returns correct paths per `sys.platform`.

### 1.2 Sensitive Path Detection

`shared/security/secret_scanner.py:is_sensitive_path()` currently checks
Linux-specific paths (`.env`, `/etc/shadow`, `~/.ssh/`). Windows needs:

- `C:\Users\*\.ssh\`
- `%APPDATA%\*\credentials`
- Windows Credential Manager paths
- `*.pfx`, `*.p12` certificate files
- Registry export files (`*.reg`)

### 1.3 Shell / Process Monitoring

| Area | Linux | Windows |
|------|-------|---------|
| Shell events | `/bin/bash`, `/bin/sh` | `cmd.exe`, `powershell.exe`, `pwsh.exe` |
| Process exec | `execve` via audit/eBPF | ETW (Event Tracing for Windows) |
| File watches | `inotify` | `ReadDirectoryChangesW` / `FileSystemWatcher` |

**Action:** Create `angelnode/platform/` with `linux.py` and `windows.py`
backends implementing a common `EventSource` interface.

### 1.4 Network Monitoring

- Replace `ss`/`netstat` parsing with `psutil` (cross-platform)
- Windows Firewall integration via `netsh` or WMI for blocking actions
- WFP (Windows Filtering Platform) for advanced blocking

---

## 2. Service Management

### 2.1 Linux (current)
- systemd unit file (`angelnode.service`)
- PID file in `/var/run/`

### 2.2 Windows
- **Windows Service** via `pywin32` or `nssm` wrapper
- Service name: `AngelNodeAgent`
- Auto-start on boot
- Recovery actions: restart on failure (3 attempts, then stop)
- Event log integration for service lifecycle events

### 2.3 Installer

| Approach | Pros | Cons |
|----------|------|------|
| MSI (WiX) | Standard, GPO-deployable | Complex build |
| MSIX | Modern, auto-update | Requires signing cert |
| PyInstaller + NSIS | Simple, fast | Less polished |

**Recommendation:** Start with **PyInstaller + NSIS** for the MVP, then
move to MSI for enterprise deployment.

---

## 3. Policy Engine — Cross-Platform Validation

The `PolicyEngine` is already cross-platform (pure Python with no OS deps).
Changes needed:

- Path separators in `source_pattern` regex: support both `/` and `\`
- Category mappings for Windows event types:
  - `shell` → covers `cmd.exe`, PowerShell, WSL
  - `file` → covers NTFS operations
  - `auth` → covers Windows logon events (Event ID 4624/4625)
  - `system` → covers Windows Event Log entries

---

## 4. Testing Matrix

### 4.1 CI Matrix Extension

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, windows-latest]
    python-version: ["3.11", "3.12"]
```

### 4.2 Platform-Specific Test Tags

```python
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_windows_service_install(): ...

@pytest.mark.skipif(sys.platform == "win32", reason="Linux only")
def test_linux_systemd_unit(): ...
```

### 4.3 Tests That Must Pass on Both Platforms

- `test_policy_engine.py` — All tests (pure Python, no OS deps)
- `test_auth_full.py` — All auth tests
- `test_detection.py` — All detection tests
- `test_security.py` — Secret detection (with Windows path additions)
- `test_orchestrator.py` — All orchestrator tests
- `test_sub_agents.py` — All agent tests
- `test_incident_lifecycle.py` — All model tests

---

## 5. Implementation Phases

### Phase W1: Foundation (1 week)
- [ ] Create `angelnode/platform/` abstraction layer
- [ ] Implement `WindowsEventSource` stub
- [ ] Add Windows paths to `secret_scanner.py`
- [ ] Verify all existing tests pass on Windows CI

### Phase W2: Agent Core (1 week)
- [ ] Windows service wrapper (pywin32)
- [ ] ETW event collection for shell/process monitoring
- [ ] Cloud sync working on Windows
- [ ] Basic installer (PyInstaller)

### Phase W3: Full Feature Parity (1 week)
- [ ] Windows Firewall integration for blocking actions
- [ ] Windows Event Log forwarding
- [ ] File system monitoring via ReadDirectoryChangesW
- [ ] PowerShell command analysis

### Phase W4: Enterprise (1 week)
- [ ] MSI installer with GPO support
- [ ] Active Directory integration for agent auto-enrollment
- [ ] Windows Defender integration (optional)
- [ ] Full E2E test suite on Windows

---

## 6. Dependencies

New Windows-only dependencies (optional extras in `pyproject.toml`):

```toml
[project.optional-dependencies]
windows = [
    "pywin32>=306",
    "psutil>=5.9",
    "wmi>=1.5",
]
```

---

## 7. Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| ETW complexity | HIGH | Start with process creation only, expand later |
| pywin32 stability | LOW | Well-maintained, widely used |
| Path separator bugs | MEDIUM | Use `pathlib.Path` everywhere, test on both OS |
| Service crash recovery | MEDIUM | Windows SCM handles restarts automatically |
| Signing certificate | LOW | Required for MSIX, not for MSI/PyInstaller |

---

## 8. Non-Goals (for initial release)

- macOS support (defer to Phase W5)
- ARM Windows (defer)
- Windows Server Core (container variant — defer)
- Kernel-level monitoring (eBPF equivalent on Windows)
