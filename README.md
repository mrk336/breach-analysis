# Breach Analysis with Azure Sentinel  
*A hands-on walkthrough of a full-stack intrusion—from phishing to exfiltration*

---

## About This Project

This repo is a personal deep dive into a multi-phase cyberattack, reconstructed using Azure Sentinel. It’s not a theoretical write-up—it’s a practical breakdown of how a single phishing email can unravel an entire network, and how we security engineers can detect, correlate, and respond using KQL, Logic Apps, and custom dashboards.

If you're a recruiter, SOC lead, or fellow detection engineer, this is a glimpse into how I think, build, and hunt.

---

## Attack Path Breakdown

The attacker followed a familiar but effective strategy:

1. **Reconnaissance**  
   Nmap scans + custom graphing to map hosts, services, and users.

2. **Initial Access**  
   A phishing campaign delivers a malicious PDF macro that launches a reverse shell.

3. **Execution & Persistence**  
   SMB exploitation, credential dumping (Mimikatz), and scheduled tasks for persistence.

4. **Lateral Movement & Exfiltration**  
   DNS tunneling and RDP pivoting used to extract sensitive data.

Each phase is monitored and stitched together using Azure Sentinel’s data model and custom KQL queries.

---

## What You'll Find Here

- ✅ KQL queries for each attack phase  
- ✅ Composite detection rule to unify alerts  
- ✅ Logic App playbook structure  
- ✅ Dashboard panel ideas  
- ✅ A narrative-style write-up of the breach

---



