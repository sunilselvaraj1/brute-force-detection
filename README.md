# 🛡️ Threat Hunting Scenario: Public Exposure and Brute-Force Attempts

In this project, we simulate a real-world **threat hunting investigation** where critical infrastructure systems (DNS, DHCP, Domain Controllers) were unintentionally exposed to the public internet, resulting in **brute-force login attempts**.

_**Inception State:**_ Organization had no external access controls or public exposure monitoring.

_**Completion State:**_ Threat exposure is validated, brute-force attempts are analyzed, and actionable recommendations are delivered based on hunt findings.

---

## 🛠️ Technology Utilized
- Microsoft Sentinel (SIEM)
- Kusto Query Language (KQL)
- MITRE ATT&CK Framework (Threat Modeling)
- NIST SP 800-61 (Incident Handling Guidelines)

---

## 📚 Table of Contents

- [🎯 Hypothesis Development](#-hypothesis-development)
- [🧠 Defining Data Sources and Detection Strategy](#-defining-data-sources-and-detection-strategy)
- [🔍 Threat Hunt Execution](#-threat-hunt-execution)
- [📝 Findings and Observations](#-findings-and-observations)
- [🛠️ Recommendations and Remediation Planning](#-recommendations-and-remediation-planning)
- [🚀 Post-Hunt Reflections and Lessons Learned](#-post-hunt-reflections-and-lessons-learned)

---

## 🎯 Hypothesis Development

We initiated the hunt by formulating a clear hypothesis:

> **"Publicly exposed critical servers are actively targeted with brute-force login attempts, potentially leading to unauthorized access."**

🔵 Assumptions:
- Lack of firewall protections.
- Absence of lockout policies.
- Critical assets (Domain Controllers, DNS Servers) exposed without proper segmentation.

---

## 🧠 Defining Data Sources and Detection Strategy

Identifying the right data was crucial to validate the hypothesis:

**Primary Data Sources:**
- 🔐 Authentication Logs (Azure Sign-In Logs, Windows Event 4625/4624)
- 🌐 Firewall/NSG Flow Logs (Public Access Detection)

**Detection Techniques:**
- 🧩 Pattern matching brute-force login attempts.
- 🚨 Correlating successful logins post multiple failures.
- 🗺️ Mapping activities to MITRE ATT&CK:
  - **T1110**: Brute Force
  - **T1078**: Valid Accounts

---

### 🛡️ Sample Detection Query (KQL)

```kql
SigninLogs
| where ResultType in ("50126", "50053") // Failed Logins
| summarize AttemptCount = count() by IPAddress, TargetUserName, bin(TimeGenerated, 1h)
| where AttemptCount > 10
| order by AttemptCount desc
```

## 🔍 Threat Hunt Execution

Using Microsoft Sentinel, a series of KQL queries were executed to:

- Detect 🚨 high-volume failed authentication attempts.
- Identify 🌎 external IPs targeting critical systems.
- Confirm any 🔑 successful logins.

Sample Threat Hunting Visualization:
<!-- Insert visualization image here when available -->

## 📝 Findings and Observations

- 🌍 Multiple external IPs detected with sustained brute-force attacks (~500 attempts/hour).
- 🔥 One external IP achieved successful authentication after numerous failures.
- 🖥️ Compromised system had Domain Admin privileges within internal infrastructure.
- ⏳ Password policies were weak (no lockout threshold).

## 🛠️ Recommendations and Remediation Planning

### 🔒 Firewall Hardening
- Block public inbound access to critical infrastructure servers.

### 🔑 Authentication Improvements
- Enforce Multi-Factor Authentication (MFA) for all administrative accounts.
- Apply account lockout policies after 5 failed attempts.

### ⚡ Real-Time Alerting
- Build SIEM alert rules for abnormal login activities (e.g., >10 failures/hour).

### 🕵️ Forensic Analysis
- Investigate compromised systems for signs of lateral movement or persistence mechanisms.

### 🛡️ Exposure Monitoring
- Implement regular public IP exposure assessments (e.g., Shodan alerts, external scans).

## 🚀 Post-Hunt Reflections and Lessons Learned

### 📈 Key Takeaways:
- Visibility gaps (e.g., missing network flow logs) delayed detection.
- Public exposure + poor authentication = Critical Risk Factor.
- Automation of brute-force detection workflows would reduce response time significantly.

### 🔔 Next Steps:
- Build continuous monitoring pipelines for public exposure.
- Integrate MITRE ATT&CK threat modeling into incident handling runbooks.

## 📊 Final Summary

This project highlights the importance of structured threat hunting and hypothesis-driven investigation techniques. It showcased a real-world approach to identifying, analyzing, and remediating potential security breaches resulting from misconfigurations.
