# Threat Hunting Scenario: Accidental Exposure of Devices to the Internet

## 📚 Scenario Overview
During routine maintenance, a misconfiguration led to devices within a shared services cluster (handling DNS, Domain Services, DHCP) being exposed to the public internet. Due to the lack of account lockout policies, the devices became vulnerable to potential brute-force attacks from external actors.

## 🎯 Objective
- Identify exposed VMs.
- Detect any brute-force login attempts from external IP addresses.
- Investigate successful logins following failed attempts.
- Provide recommendations to harden infrastructure.

## 🛠 Tools and Data Sources
- Microsoft Defender for Endpoint (MDE)
- Microsoft Sentinel (Log Analytics Workspace)
- Kusto Query Language (KQL)

## 🔍 Hunting Methodology
Following a structured threat hunting process:
1. [Hypothesis Formation](https://github.com/sunilselvaraj1/brute-force-detection/hypothesis-formation)
2. Data Collection
3. Data Enrichment
4. KQL Querying and Analysis
5. Validation of Findings
6. Reporting and Recommendations

## 📈 MITRE ATT&CK Mapping
- **T1110.001** - Brute Force: Password Guessing
- **T1078** - Valid Accounts

## 📋 References
- [Microsoft Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
