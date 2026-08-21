# Real-Time Windows File Integrity Monitoring (FIM) & Threat Simulation

An end-to-end detection engineering and security monitoring project showcasing real-time **File Integrity Monitoring (FIM)** and **Who-Data Auditing** using **Wazuh SIEM/XDR** on a Windows endpoint (`SOC-Target-Windows`).

---

## 📌 Project Overview
This lab simulates realistic insider threat and attacker behaviors against enterprise corporate assets—including database tampering, financial ledger manipulation, data staging/exfiltration, and defensive log/file destruction. Using Wazuh's native `syscheck` engine configured with real-time tracking and Windows SACL auditing (`whodata`), all unauthorized modifications were captured, analyzed, and attributed in the Wazuh dashboard.

```
+-------------------------------------------------------------+
|                     Wazuh SIEM Manager                      |
|                (ip-172-31-45-246 / Agent: 001)              |
+------------------------------▲------------------------------+
                               │ Real-Time FIM & Whodata Logs
+------------------------------┴------------------------------+
|               Target Windows Endpoint (Agent)               |
|            - Directory Auditing & SACL Tracking             |
|            - Detection of Added, Modified & Deleted Files   |
+-------------------------------------------------------------+
```

---

## 🏗️ Monitored Environment & Baseline Architecture

The simulated business structure contains core corporate documents across HR, Finance, and Database systems:

```text
C:\Users\Saf1Hckr\Documents\
│
├── test/
│   ├── CompanyDatabase/
│   │   ├── employees.csv           # Employee IDs and department records
│   │   └── database_config.txt     # Production DB server connection strings
│   ├── Finance/
│   │   └── accounts.csv            # Corporate ledger balances
│   └── HR/
│       └── employee_records.txt    # Confidential personnel records
│
└── tunsec/
    └── Backups/
        └── database_backup.txt     # Cold backup archive
```

---

## ⚙️ Wazuh Configuration

### Agent Syscheck Configuration (`ossec.conf`)
Located on the Windows target at `C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>300</frequency>
  <scan_on_start>yes</scan_on_start>

  <!-- Real-time monitoring + Whodata audit on enterprise directories -->
  <directories check_all="yes" realtime="yes" whodata="yes">C:\Users\Saf1Hckr\Documents\test</directories>
  <directories check_all="yes" realtime="yes" whodata="yes">C:\Users\Saf1Hckr\Documents\tunsec</directories>
</syscheck>
```

---

## 🧪 Simulation Scenarios & Attack Lifecycle

### 1. Lab Setup (PowerShell Baseline)
```powershell
$test = "C:\Users\Saf1Hckr\Documents\test"
$tunsec = "C:\Users\Saf1Hckr\Documents\tunsec"

# Create directories
New-Item -ItemType Directory -Force "$test\CompanyDatabase"
New-Item -ItemType Directory -Force "$test\HR"
New-Item -ItemType Directory -Force "$test\Finance"
New-Item -ItemType Directory -Force "$tunsec\Backups"

# Populate baseline enterprise records
"EMPLOYEE_ID,NAME,DEPARTMENT`n1001,John Smith,IT`n1002,Jane Doe,Finance`n1003,Michael Brown,HR" | Out-File "$test\CompanyDatabase\employees.csv"
"ACCOUNT_ID,ACCOUNT_TYPE,BALANCE`nACC001,Checking,12500`nACC002,Savings,45000`nACC003,Checking,8200" | Out-File "$test\Finance\accounts.csv"
"CONFIDENTIAL - COMPANY HR RECORD`nEmployee benefits and internal HR information." | Out-File "$test\HR\employee_records.txt"
"DatabaseServer=DB-SERVER-01`nDatabaseName=CorporateDB`nEnvironment=Production" | Out-File "$test\CompanyDatabase\database_config.txt"
"Corporate database backup created for security testing." | Out-File "$tunsec\Backups\database_backup.txt"
```

### 2. Attack Simulation Execution
```powershell
# Scenario 1: Unauthorized Database Tampering (Data Manipulation)
Add-Content "C:\Users\Saf1Hckr\Documents\test\CompanyDatabase\employees.csv" "9999,ATTACKER,Unknown"

# Scenario 2: Financial Ledger Fraud
Add-Content "C:\Users\Saf1Hckr\Documents\test\Finance\accounts.csv" "HACKED,Unknown,999999"

# Scenario 3: Staging Configuration Data for Exfiltration (File Move)
Move-Item "C:\Users\Saf1Hckr\Documents\test\CompanyDatabase\database_config.txt" "C:\Users\Saf1Hckr\Documents\tunsec\database_config.txt"

# Scenario 4: Defense Evasion & Evidence Destruction (File Deletion)
Remove-Item "C:\Users\Saf1Hckr\Documents\test\HR\employee_records.txt"
```

---

## 📊 Detection & SIEM Analysis

### MITRE ATT&CK Mapping & Event Attribution

| Event Action | Target File / Resource | Wazuh Rule ID | MITRE ATT&CK Technique | User / Process Attribution (`whodata`) |
| :--- | :--- | :--- | :--- | :--- |
| **File Modified** | `...\CompanyDatabase\employees.csv` | `550` (syscheck) | **T1565.001** (Data Manipulation) | `Administrators` / `Saf1Hckr` (`powershell.exe`) |
| **File Modified** | `...\Finance\accounts.csv` | `550` (syscheck) | **T1565.001** (Data Manipulation) | `Administrators` / `Saf1Hckr` (`powershell.exe`) |
| **File Added** | `...\tunsec\database_config.txt` | `554` (syscheck) | **T1074.001** (Data Staged) | `Administrators` / `Saf1Hckr` (`powershell.exe`) |
| **File Deleted** | `...\HR\employee_records.txt` | `553` (syscheck) | **T1070.004** (File Deletion) | `Administrators` / `Saf1Hckr` (`powershell.exe`) |

---
## 📸 Image Findings




---
## 🔍 Key Findings & Security Insights
1. **Zero-Latency Ingestion:** Wazuh's `realtime="yes"` flag leverages the Windows ReadDirectoryChangesW API, triggering immediate alert generation without waiting for the scheduled 300-second audit scan.
2. **Attribution via Whodata:** Utilizing Microsoft SACL auditing, `whodata="yes"` captures exact process paths, parent PIDs, user SIDs, and account usernames responsible for modifications.
3. **Cryptographic Checksum Tracking:** SHA-256 and MD5 hash divergence immediately flagged unauthorized inline record injection in CSV database targets.
