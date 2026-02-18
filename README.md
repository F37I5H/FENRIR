# FENRIR v2.0

**Entra ID & Hybrid AD Privilege Escalation Scanner**

```
┌───────────────────────────────────────────────┐
│  ░█▀▀░█▀▀░█▀█░█▀▄░▀█▀░█▀▄                     │
│  ░█▀▀░█▀▀░█░█░█▀▄░░█░░█▀▄                     │
│  ░▀░░░▀▀▀░▀░▀░▀░▀░▀▀▀░▀░▀                     │
│  >> Entra ID Privilege Escalation Scanner <<  │
│  Pure PowerShell | Graph + Azure REST API     │
└───────────────────────────────────────────────┘
```

Pure PowerShell scanner that identifies privilege escalation paths across the full hybrid attack surface: **Entra ID** (Azure AD), **Azure resources**, **on-prem Active Directory**, and the **local Windows workstation** — all in a single `.ps1` file with zero dependencies.

## Key Features

- **Zero dependencies** — no modules, no binaries, no .NET assemblies. Just PowerShell 5.1+
- **Single authentication** — Device Code Flow gets both Graph API and Azure Management tokens in one login (supports MFA and Conditional Access)
- **40-section scan** covering cloud, hybrid, and local attack vectors
- **Severity classification** — PE (privilege escalation), RED (high risk), LOW (medium), INFO (informational)
- **Attack path generation** — actionable exploitation chains, not just findings
- **Visual output** — progress bar, colored findings, box-drawing UI
- **Optional file report** via `-OutputFile` parameter

## Quick Start

```powershell
# Run directly from GitHub
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/<user>/<repo>/main/fenrir.ps1')

# Or download and run locally
.\fenrir.ps1

# Save report to file
.\fenrir.ps1 -OutputFile "C:\temp\fenrir_report.txt"
```

A device code prompt will appear — authenticate in your browser once and the scan begins automatically.

## Requirements

| Requirement | Details |
|-------------|---------|
| PowerShell | 5.1+ (built into Windows) |
| Network | HTTPS to `login.microsoftonline.com`, `graph.microsoft.com`, `management.azure.com` |
| Privileges | **No admin required.** Runs as standard user. Findings scale with permissions — admin tokens yield deeper results |
| Domain | On-prem AD checks require domain-joined machine. Cloud-only checks work from anywhere |

## Scan Sections (40)

### Entra ID / Cloud Identity (Sections 1–12)

| # | Section | What it checks |
|---|---------|---------------|
| 01 | **Current User Identity** | UPN, roles, group memberships, licenses |
| 02 | **Directory Roles** | All role assignments, custom roles with dangerous permissions |
| 03 | **MFA & Auth Methods** | MFA registration status, auth method gaps |
| 04 | **Conditional Access** | Policy analysis, exclusions, gaps |
| 05 | **App Registrations** | Secrets (expiry, lifetime), certificates, dangerous API permissions (RoleAssignment, Mail.ReadWrite, etc.) |
| 06 | **Service Principals & MI** | Managed Identities, app role assignments |
| 07 | **Dangerous Permission Grants** | OAuth2 delegated/application grants with admin consent, user consent abuse |
| 08 | **Guest Users** | Guest accounts with directory roles |
| 09 | **Password & Domain Policies** | Domains, SSPR config, password policies |
| 10 | **Stale & Risky Accounts** | Inactive accounts, never-signed-in users |
| 11 | **On-Prem AD Flags** | MAQ, PASSWD_NOTREQD, Kerberoastable SPNs, AS-REP roastable, domain/forest trusts |
| 12 | **PIM** | Eligible role assignments, activation requirements |

### Azure Resources (Sections 13–20)

| # | Section | What it checks |
|---|---------|---------------|
| 13 | **Azure RBAC** | Subscription access, role assignments (Owner, Contributor, UAA) |
| 14 | **Virtual Machines** | VMs with public IPs, extensions, managed identity |
| 15 | **Key Vault** | Access policies, RBAC, secret/key/cert enumeration |
| 16 | **Storage Accounts** | Public access, shared keys, SAS tokens |
| 17 | **Intune / Endpoint Manager** | Device configs, compliance policies, PowerShell scripts |
| 18 | **Mail Permissions** | Mail-enabled apps, mailbox delegations |
| 19 | **VM Run Command** | Cloud-to-local code execution via Run Command |
| 20 | **IMDS Managed Identity** | Token acquisition from instance metadata (169.254.169.254) |

### Hybrid / Cloud-to-Local (Sections 21–24)

| # | Section | What it checks |
|---|---------|---------------|
| 21 | **Device Join & PRT** | Azure AD join status, PRT token presence, SSO state, NGC |
| 22 | **Cloud LAPS** | Windows LAPS via Entra, on-prem LAPS (ms-Mcs-AdmPwd) |
| 23 | **Security Defaults & Legacy Auth** | Security defaults, named locations, token lifetime policies |
| 24 | **AD Object ACL Abuse** | ACLs on computers/admins, GPO write permissions, **DCSync rights** (DS-Replication), **passwords in AD description fields** |

### Local Privilege Escalation (Sections 25–30)

| # | Section | What it checks |
|---|---------|---------------|
| 25 | **Local Machine Security** | Token privileges, local admins, LSA/Credential Guard, AMSI/CLM, OS patch level, Defender, AppLocker, BitLocker, writable ProgramData, **process token impersonation** (Potato family), **Docker/WSL/Hyper-V breakout**, **logged-in sessions** (tscon hijack), **UAC settings**, WDAC/HVCI |
| 26 | **Windows Services** | Unquoted paths, writable binaries, writable registry keys |
| 27 | **Scheduled Tasks** | SYSTEM tasks with writable binaries |
| 28 | **Stored Credentials** | AutoLogon, cmdkey, WiFi, unattend/sysprep, DPAPI blobs, SAM/SYSTEM backups, credential files, **SSH private keys**, **GPP cpassword** (MS14-025), **KeePass databases**, **browser credentials** (Chrome, Edge, Firefox, Brave) |
| 29 | **AlwaysInstallElevated & DLL Hijack** | AlwaysInstallElevated, writable PATH dirs, app dir DLL hijack, **phantom DLL hijacking** (known missing DLLs), PrintNightmare/PrintSpooler |
| 30 | **Autoruns & Persistence** | Registry Run keys, startup folders, **COM object hijacking** (CLSID InprocServer32), **WMI event subscriptions** |

### Network & Application Security (Sections 31–35)

| # | Section | What it checks |
|---|---------|---------------|
| 31 | **Network & SMB** | SMB signing, LLMNR/NBT-NS poisoning, firewall, RDP/NLA, WinRM, accessible shares, DNS zone transfer |
| 32 | **App Redirect URIs** | Wildcard/localhost/HTTP redirect URIs, consent settings, owned apps |
| 33 | **Azure Automation** | Automation accounts, runbooks, App Services |
| 34 | **Installed Software** | Known CVEs in installed applications |
| 35 | **Cross-Tenant & B2B** | Cross-tenant access policies, guest invite settings |

### Advanced AD & Modern Vectors (Sections 36–40)

| # | Section | What it checks |
|---|---------|---------------|
| 36 | **Dynamic Groups** | Abusable membership rules, role-assignable groups |
| 37 | **Administrative Units** | Scoped admin roles, restricted management AUs |
| 38 | **Entra Connect / AD Sync** | Sync status, connector accounts, password hash sync |
| 39 | **ADCS (Certificate Services)** | **ESC1** (ENROLLEE_SUPPLIES_SUBJECT), **ESC2** (Any Purpose), **ESC3** (Enrollment Agent), **ESC4** (writable templates), **ESC6** (EDITF_ATTRIBUTESUBJECTALTNAME2), **ESC7** (ManageCA perms), **ESC8** (HTTP enrollment / NTLM relay) |
| 40 | **Modern PE Vectors** | Coercion endpoints (PetitPotam, PrinterBug, DFSCoerce), **named pipe permissions**, gMSA password read, Kerberos delegation (unconstrained, constrained, RBCD), Shadow Credentials (msDS-KeyCredentialLink), WSUS HTTP abuse, noPac (CVE-2021-42278), Azure Arc agent |

## Severity Levels

| Level | Meaning | Example |
|-------|---------|---------|
| **PE!!** | Direct privilege escalation path for current user | DCSync rights, SeImpersonate + SYSTEM processes, writable GPO |
| **RED** | High-risk finding requiring attention | LSA protection disabled, unencrypted SSH keys, WMI persistence |
| **LOW** | Medium-risk configuration issue | SMB signing disabled, LLMNR enabled, long-lived app secrets |
| **INFO** | Informational / reconnaissance data | Managed Identities count, IMDS metadata, guest user count |

## Output Example

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  FENRIR v2.0 - SCAN COMPLETE                                                 ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  PE!!    ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░    2  (2%)                          ║
║  RED     ██████████████░░░░░░░░░░░░░░░░░░   22 (24%)                          ║
║  LOW     ██████████████████████████████     55 (60%)                          ║
║  INFO    ███████░░░░░░░░░░░░░░░░░░░░░░░░   13 (14%)                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Total: 92 findings  |  Duration: 5m 21s                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## Attack Path Generation

FENRIR doesn't just list findings — it chains them into actionable attack paths:

```
[ATTACK PATH] SeImpersonatePrivilege → GodPotato/PrintSpoofer/JuicyPotatoNG → SYSTEM
[ATTACK PATH] GPP cpassword → gpp-decrypt / Get-GPPPassword → plaintext credentials
[ATTACK PATH] DCSync as J-LABS\svc_sync → secretsdump.py / Mimikatz lsadump::dcsync → all NTLM hashes → DA
[ATTACK PATH] Modify GPO 'Default Domain Policy' → add scheduled task → code exec on linked OUs
[ATTACK PATH] SSH private key → ssh -i key user@target → lateral movement
[ATTACK PATH] Enroll 'WebServer' as agent → use agent cert to enroll as DA on another template
```

## Coverage Comparison

| Category | FENRIR | WinPEAS | ADPEAS | PowerUp | AzureHound |
|----------|--------|---------|--------|---------|------------|
| Entra ID (roles, MFA, CA, PIM) | 14 checks | - | 8 | - | 6 |
| Azure resources (RBAC, VMs, KV) | 8 checks | - | partial | - | partial |
| ADCS ESC1-8 | all 7 | - | ESC1,8 | - | - |
| AD (Kerberos, delegation, ACLs) | 12 checks | - | 6 | - | 5 |
| Local PE (services, DLL, tokens) | 20 checks | 25 | - | 10 | - |
| Credential harvesting | 10 checks | 8 | - | 2 | - |
| **IMDS, Azure Arc, Dynamic Groups** | **unique** | - | - | - | - |
| **Total vectors** | **~50** | ~26 | ~14 | ~10 | ~11 |

FENRIR is the only tool that covers all three layers (cloud + AD + local) in a single script.

## How It Works

```
┌──────────────────────────────────────────────────────┐
│                    FENRIR v2.0                        │
├──────────────────────────────────────────────────────┤
│                                                      │
│  ┌─────────┐   Device Code Flow    ┌──────────────┐ │
│  │ User    │ ──────────────────── │ Entra ID     │ │
│  │ Browser │   (MFA supported)    │ OAuth2       │ │
│  └─────────┘                      └──────┬───────┘ │
│                                          │         │
│                              ┌───────────┼────┐    │
│                              ▼           ▼    │    │
│                    ┌──────────────┐ ┌────────┐│    │
│                    │ Graph API    │ │ ARM    ││    │
│                    │ Token        │ │ Token  ││    │
│                    └──────┬───────┘ └───┬────┘│    │
│                           │             │     │    │
│  ┌────────────────────────┼─────────────┼─────┘    │
│  ▼                        ▼             ▼          │
│ ┌──────────┐  ┌───────────────┐  ┌────────────┐   │
│ │ On-Prem  │  │ Graph REST    │  │ Azure      │   │
│ │ AD/LDAP  │  │ API calls     │  │ Management │   │
│ │ (ADSI)   │  │ (Sections     │  │ REST API   │   │
│ │          │  │  1-12,17-18,  │  │ (Sections  │   │
│ │ Sections │  │  32,35-38)    │  │  13-16,19, │   │
│ │ 11,24,   │  └───────────────┘  │  33)       │   │
│ │ 39-40    │                     └────────────┘   │
│ └──────────┘                                      │
│                                                    │
│ ┌──────────────────────────────────────────────┐   │
│ │ Local Machine (WMI, Registry, ACLs, FS)      │   │
│ │ Sections 20-22, 25-31, 34                    │   │
│ └──────────────────────────────────────────────┘   │
│                                                    │
│ ┌──────────────────────────────────────────────┐   │
│ │ Output Engine                                │   │
│ │  ├─ Colored console output                   │   │
│ │  ├─ Progress bar (0-100%)                    │   │
│ │  ├─ Finding severity classification          │   │
│ │  ├─ Attack path chaining                     │   │
│ │  └─ Optional file report                     │   │
│ └──────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────┘
```

## Authentication Details

FENRIR uses the **Azure CLI client ID** (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`) with Device Code Flow. This is the same client used by `az login` and is pre-consented in all Azure tenants — no app registration needed.

Two tokens are acquired in a single authentication:
1. **Microsoft Graph** (`https://graph.microsoft.com`) — for Entra ID enumeration
2. **Azure Management** (`https://management.azure.com`) — for Azure resource enumeration (acquired silently via refresh token)

## Ethical Use

This tool is designed for **authorized security assessments only**:

- Penetration testing engagements with written authorization
- Internal security audits by IT/security teams
- Red team / purple team exercises
- Security research and education

**Do not** use this tool against environments you don't have explicit permission to test.

## Disclaimer

This tool is provided **as-is**, without any warranty. Use at your own risk. The author takes no responsibility for any damage, data loss, or legal consequences resulting from the use of this tool. You are solely responsible for ensuring you have proper authorization before running it against any environment.

## License

For authorized security testing and research purposes only.
