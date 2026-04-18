# 🛡️ Home SIEM Lab — Splunk + Sysmon + Atomic Red Team

> **Author:** Feroz Khan &nbsp; &nbsp;|&nbsp; **April 2026**

A fully functional home SIEM lab built entirely with free tools — simulating a corporate blue team environment on a single machine. Ingests real Windows + Sysmon logs, simulates 5 MITRE ATT&CK techniques with Atomic Red Team, detects them with custom SPL queries, and visualises everything on a live Splunk dashboard.

Visit the project website: https://ferozahmadkhan.github.io/Home-SIEM-Lab-Splunk-Sysmon-Atomic-Red-Team/

---

## 📊 Lab Results

| Metric | Result |
|---|---|
| Total Threat Events Detected | **49** |
| MITRE ATT&CK Techniques Covered | **5** |
| Custom SPL Detection Rules | **5** |
| Splunk Dashboard Panels | **6** |
| Build Time | **~10-12 hours** |
| Cost | **$0 — all free tools** |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    HOST MACHINE                          │
│   Splunk Enterprise (Free) — localhost:8000              │
│   Receives logs on port 9997                             │
└─────────────────────┬───────────────────────────────────┘
                      │ port 9997
                      │ (Splunk Universal Forwarder)
┌─────────────────────▼───────────────────────────────────┐
│                  VIRTUAL MACHINE (VirtualBox)            │
│   Windows 10 Pro — DESKTOP-P8DU7UE                       │
│   ├── Sysmon v15 + SwiftOnSecurity config               │
│   ├── Splunk Universal Forwarder (runs as SYSTEM)        │
│   └── Atomic Red Team (attack simulator)                │
└─────────────────────────────────────────────────────────┘
```

**Indexes:**
- `index=windows` — Security, System, Application Event Logs
- `index=sysmon` — Deep process/network/file/registry telemetry

---

## 🔧 Tools Used

| Tool | Purpose | Cost |
|---|---|---|
| [VirtualBox](https://virtualbox.org) | Hypervisor for victim VM | Free |
| [Windows 10 Enterprise ISO](https://microsoft.com/en-us/evalcenter) | Victim OS (90-day eval) | Free |
| [Splunk Enterprise](https://splunk.com) | SIEM (60 days) | Free |
| [Splunk Universal Forwarder](https://splunk.com) | Log shipper | Free |
| [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) | Deep telemetry agent | Free |
| [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config) | Tuned Sysmon ruleset | Free |
| [Atomic Red Team](https://github.com/redcanaryco/invoke-atomicredteam) | MITRE ATT&CK simulators | Free |

---

## 🎯 Detections Built

### T1087.001 — Account Discovery
**Tactic:** Discovery | **Source:** Sysmon EID 1

Detects post-exploitation recon commands run after initial access.

```spl
index=sysmon EventCode=1
| search CommandLine="*net user*" OR CommandLine="*whoami*" OR CommandLine="*net localgroup*"
| table _time, host, User, CommandLine, ParentCommandLine
| sort - _time
```

---

### T1110.001 — Brute Force
**Tactic:** Credential Access | **Source:** Windows Security EID 4625

Detects repeated failed logins against local accounts.

```spl
index=windows EventCode=4625
| stats count by Source_Network_Address, Account_Name, host, Logon_Type
| where count > 3
| sort - count
```

> ⚠️ **Note:** Use `Account_Name` and `Logon_Type` — not `user`/`LogonType`. Splunk parses Windows logs with different field names.

---

### T1059.001 — Suspicious PowerShell
**Tactic:** Execution | **Source:** Sysmon EID 1

Catches encoded commands, download cradles, bypass flags, and offensive toolkits.

```spl
index=sysmon EventCode=1 Image="*powershell.exe*"
| eval suspicious=if(
    match(CommandLine, "(?i)(-enc|-EncodedCommand|-ExecutionPolicy Bypass|-WindowStyle Hidden|-nop|-noni|IEX|Invoke-Expression|DownloadString|WebClient)"),
    "YES", "NO")
| where suspicious="YES"
| table _time, host, User, CommandLine, ParentImage, suspicious
| sort - _time
```

---

### T1136.001 — Backdoor Admin Account
**Tactic:** Persistence | **Source:** Windows Security EID 4720 + 4732

Catches new local admin accounts — correlates account creation with admin group addition.

```spl
index=windows (EventCode=4720 OR EventCode=4732)
| eval action=case(
    EventCode=4720, "New Account Created",
    EventCode=4732, "Added to Administrators Group")
| table _time, host, Account_Name, action, src_user
| sort - _time
```

---

### T1003.001 — Credential Dumping
**Tactic:** Credential Access | **Source:** Sysmon EID 1

Catches Mimikatz, ProcDump, Invoke-Mimikatz (in-memory), comsvcs.dll LOLBin, xordump.

```spl
index=sysmon EventCode=1
| search CommandLine="*lsass*" OR CommandLine="*mimikatz*" OR CommandLine="*sekurlsa*" OR CommandLine="*procdump*"
| table _time, host, User, CommandLine, ParentCommandLine
| sort - _time
```

---

## ⚙️ Quick Setup

### 1. Environment
```
1. Install VirtualBox + Extension Pack
2. Download Windows 10 Enterprise ISO (90-day eval)
3. Create VM: 4096MB RAM, 60GB disk, SATA controller
4. Install Windows → use "Domain join instead" for local account
5. Install Guest Additions → Take snapshot: Clean-Install
```

### 2. Log Pipeline
```
1. Install Splunk Enterprise on host PC → http://localhost:8000
2. Settings → Receiving → port 9997
3. Create indexes: "windows" and "sysmon"
4. Run ipconfig → note VirtualBox Host-Only adapter IP
5. Install Splunk Universal Forwarder on VM → point to host IP:9997
6. Create inputs.conf (open Notepad as Administrator)
7. Install Sysmon: sysmon64.exe -accepteula -i sysmonconfig-export.xml
8. CRITICAL: SplunkForwarder service → Log On → Local System account → Restart
```

### 3. Attack Simulation
```powershell
# PowerShell as Administrator (inside VM)
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name powershell-yaml -Force -AllowClobber
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force

# Import each session
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

# Run attacks
Invoke-AtomicTest T1087.001   # Account Discovery
Invoke-AtomicTest T1110.001   # Brute Force
Invoke-AtomicTest T1059.001   # Suspicious PowerShell
Invoke-AtomicTest T1136.001   # Backdoor Account
Invoke-AtomicTest T1003.001   # Credential Dumping
```

---

## 🗺️ MITRE ATT&CK Coverage

| ID | Name | Tactic | Event Source |
|---|---|---|---|
| T1087.001 | Account Discovery: Local Account | Discovery | Sysmon EID 1 |
| T1110.001 | Brute Force: Password Guessing | Credential Access | Security EID 4625 |
| T1059.001 | Command & Scripting: PowerShell | Execution | Sysmon EID 1 |
| T1136.001 | Create Account: Local Account | Persistence | Security EID 4720/4732 |
| T1003.001 | OS Cred Dumping: LSASS Memory | Credential Access | Sysmon EID 1 |

---

## 🔑 Key Windows Event IDs

| Event ID | Log | Meaning |
|---|---|---|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon — brute force |
| 4720 | Security | User account created |
| 4732 | Security | User added to group |
| 1 | Sysmon | Process created |
| 3 | Sysmon | Network connection |
| 10 | Sysmon | Process accessed LSASS |
| 11 | Sysmon | File created |
| 13 | Sysmon | Registry value set |

---

## 🐛 Known Issues & Fixes

| Problem | Fix |
|---|---|
| No driver during Windows install | Settings → Storage → NVMe → SATA (AHCI) |
| `index=windows` empty | Create index in Splunk: Settings → Indexes |
| `index=sysmon` empty | SplunkForwarder → Log On → Local System account |
| Atomic Red Team yaml error | `Install-AtomicRedTeam -getAtomics -Force` |
| powershell-yaml missing | `Install-Module powershell-yaml -Force -AllowClobber` |

---


## 📄 License

MIT — free to use, fork, and adapt with attribution.

---

> *"The best way to learn blue team is to play red team in your own lab."*

**Built by Feroz Khan · April 2026 · github.com/ferozahmadkhan**
