# Breach Analysis with Azure Sentinel 

A hands-on walkthrough of a full-stack intrusion—from phishing to exfiltration

---

## TL;DR  
This repo reconstructs a multi-phase breach using Azure Sentinel. It includes KQL queries, dashboards, Logic Apps, and a narrative-style breakdown of how a single phishing email led to full network compromise. Ideal for SOC leads, recruiters, and detection engineers looking for real-world detection logic and response workflows.

---

## About This Project  
This is a personal deep dive into a full-stack intrusion scenario, rebuilt using Azure Sentinel. It’s not a theoretical write-up—it’s a practical breakdown of how a single phishing email can unravel an entire network. I walk through each attack phase and show how to detect, correlate, and respond using KQL, Logic Apps, and custom dashboards.

If you're a recruiter, SOC lead, or fellow detection engineer, this is a glimpse into how I think, build, and hunt.

---

## Attack Path Breakdown  
The attacker followed a familiar but effective strategy:

1. **Reconnaissance**  
   Nmap scans and LDAP enumeration to map hosts, services, and users.

2. **Initial Access**  
   A phishing campaign delivers a malicious PDF macro that launches a reverse shell.

3. **Execution & Persistence**  
   SMB exploitation, credential dumping (Mimikatz), and scheduled tasks for persistence.

4. **Lateral Movement & Exfiltration**  
   DNS tunneling and RDP pivoting used to extract sensitive data.

Each phase is monitored and stitched together using Azure Sentinel’s data model and custom KQL queries.

---

## What You'll Find Here

- KQL queries for each attack phase  
- Composite detection rule to unify alerts  
- Logic App playbook structure  
- Dashboard panel ideas  
- MITRE ATT&CK mapping  
- Lessons learned and detection philosophy  
- A narrative-style write-up of the breach  

---

## Detection Logic by Attack Phase

### Reconnaissance

**Nmap Scan Detection**  
```kql
Heartbeat
| where RemoteIPCountry != "Local"
| summarize PortCount = dcount(RemotePort) by RemoteIP, bin(TimeGenerated, 5m)
| where PortCount > 50
```

**LDAP Enumeration**  
```kql
DeviceEvents
| where InitiatingProcessFileName == "powershell.exe"
| where AdditionalFields contains "Get-ADUser"
```
Dual-Boot Detection Considerations

Attackers or insiders who might use a second OS to bypass endpoint monitoring.Crosschecking system time with OS logins is a powerful way to uncover anomalies like dual-boot activity, time spoofing, or overlapping sessions across operating systems

union 
    DeviceLogonEvents, 
    Syslog 
| where UserName != "" 
| project TimeGenerated, OSName, UserName, LogonType
| summarize count() by bin(TimeGenerated, 5m), OSName, UserName, LogonType


---

### Initial Access

**Phishing Email Detection**  
```kql
let suspiciousAttachments = EmailAttachmentInfo
    | where FileType == "pdf";

EmailEvents
| where Subject has "Invoice"
| join kind=inner (suspiciousAttachments) on NetworkMessageId
| where SenderFromDomain != RecipientDomain
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, FileName, FileType

```

**Reverse Shell Launch from Office App**  
```kql
DeviceProcessEvents
| where InitiatingProcessFileName in ("winword.exe", "excel.exe")
| where FileName in ("powershell.exe", "cmd.exe", "wscript.exe")
```

---

### Execution & Persistence

**Credential Dumping (Mimikatz)**  
```kql
DeviceProcessEvents
| where FileName == "mimikatz.exe" or ProcessCommandLine contains "sekurlsa"
```

**Scheduled Task Creation**  
```kql
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, AdditionalFields
```

---

### Lateral Movement & Exfiltration

**RDP Pivoting**  
```kql
DeviceNetworkEvents
| where RemotePort == 3389 and InitiatingProcessFileName == "mstsc.exe"
| summarize SessionCount = count() by DeviceName, RemoteIP
```

**DNS Tunneling Detection**  
```kql
DnsEvents
| where strlen(QueryName) > 50
| summarize QueryCount = count() by ClientIP, bin(TimeGenerated, 5m)
| where QueryCount > 100
```

---

## Unusual Admin Account Activity

**New Admin Account Added**  
```kql
DeviceEvents
| where ActionType == "UserAccountAddedtoLocalGroup"
| where AdditionalFields contains "Administrators"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, AdditionalFields
```

**Admin Logons from Unusual Locations**  
```kql
let Admins = AADGroupMembers
    | where GroupName == "Global Administrators"
    | project UserPrincipalName;

SigninLogs
| where UserPrincipalName in (Admins)
| summarize Locations = make_set(Location), Devices = make_set(DeviceDetail) by UserPrincipalName
| where array_length(Locations) > 3 or array_length(Devices) > 3

```

**Off-Hours Admin Logons**  
```kql
let Admins = AADGroupMembers
    | where GroupName == "Global Administrators"
    | project UserPrincipalName;

SigninLogs
| where UserPrincipalName in (Admins)
| extend Hour = datetime_part("hour", TimeGenerated), DayOfWeek = datetime_part("dayofweek", TimeGenerated)
| where Hour < 6 or Hour > 20 or DayOfWeek in (0, 6)

```

**Local Admin Enumeration**  
```kql
DeviceProcessEvents
| where ProcessCommandLine contains "net localgroup administrators"
```

---

## MITRE ATT&CK Mapping

| Phase                     | Technique ID | Technique Name                                |
|--------------------------|--------------|-----------------------------------------------|
| Reconnaissance           | T1595        | Active Scanning                               |
| Initial Access           | T1566.001    | Phishing: Spearphishing Attachment            |
| Execution & Persistence  | T1059.001    | Command and Scripting Interpreter: PowerShell |
|                          | T1053.005    | Scheduled Task/Job: Scheduled Task            |
|                          | T1003.001    | Credential Dumping: LSASS Memory              |
| Lateral Movement         | T1021.001    | Remote Services: Remote Desktop Protocol      |
| Exfiltration             | T1048.003    | Exfiltration Over Alternative Protocol: DNS   |
| Privilege Escalation     | T1069.001    | Permission Groups Discovery: Local Groups     |
|                          | T1078        | Valid Accounts                                |

---

## Threat Intelligence Integration

IOC enrichment was performed using Microsoft Threat Intelligence and VirusTotal. Suspicious IPs, domains, and file hashes were correlated with known campaigns. This helped validate alerts and reduce false positives.

---

## Response Automation

Logic Apps were used to trigger automated responses:

- Isolate host via Defender for Endpoint  
- Send alert to Teams channel  
- Create ticket in ServiceNow  

These workflows are modular and can be adapted to any SOC environment.

---

## Lessons Learned

- Behavioral detections outperform static signatures in noisy environments  
- DNS tunneling is still under-detected in many orgs  
- Scheduled tasks remain a popular persistence method  
- Admin account hygiene is often overlooked—monitoring is essential  

---

## Detection Philosophy

I prioritize low-noise, behavior-based detections that can be correlated across multiple data sources. This repo reflects my approach: layered logic, clear mapping to ATT&CK, and automation-ready workflows.
