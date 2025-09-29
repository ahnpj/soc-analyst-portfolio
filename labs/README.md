# 🛡️ SOC Analyst Labs Portfolio

This repository contains a collection of hands-on cybersecurity labs I’ve built to practice **SIEM analysis, network traffic investigation, scanning/recon, and playbook documentation**.  
Each lab is designed to **increase in complexity and depth as the lab number goes up**. For example, `Lab01` focuses on introductory concepts, while `Lab02` and higher require more advanced investigation, correlation, and analysis skills.

---

<details>
<summary><strong>📂 Repository Structure</strong></summary>

```text
labs/
  siem/
    siem-basics/
      Lab01-intro-to-siem/
      Lab01-suspicious-process-investigation/
    splunk/
      Lab01-splunk-vpn-log-analysis/
  end-point-triage/
    powershell/
      Lab01-powershell-endpoint-triage-basics
    windows-cli
      Lab01-windows-cli-endpoint-triage-basics
  playbooks/
```
</details>


## 🔎 Lab Highlights

### SIEM Basics
- **[Lab01 – Intro to SIEM](labs/siem/siem-basics/Lab01-intro-to-siem/Lab01-intro-to-siem.md)**  
  *Level: Beginner* → Introduction to SIEM purpose, data sources, and alert workflows.  

- **[Lab01 – Suspicious Process Investigation](labs/siem/siem-basics/Lab01-suspicious-process-investigation/Lab01-suspicious-process-investigation.md)**  
  *Level: Beginner* → Investigating abnormal process activity in logs, understanding correlation rules.  

### Splunk Labs
- **[Lab01 – VPN Log Analysis](labs/siem/splunk/Lab01-splunk-vpn-log-analysis/Lab01-splunk-vpn-log-analysis.md)**  
  *Level: Beginner* → Detecting unusual VPN login activity, analyzing login patterns by user and source country, and identifying suspicious travel or account compromise.

### Endpoint Triage Labs
- **[Lab01 – Windows CLI/CMD Basics](https://github.com/ahnpj/soc-analyst-portfolio/blob/main/labs/endpoint-triage/windows-cli/Lab01-windows-cli-endpoint-triage-basics/Lab01-windows-cli-endpoint-triage-basics.md)**  
  *Level: Beginner* → Using Windows command-line tools to investigate processes, review system information, and identify suspicious activity.
- **[Lab01 – PowerShell Basics](https://github.com/ahnpj/soc-analyst-portfolio/blob/main/labs/endpoint-triage/powershell/Lab01-powershell-endpoint-triage-basics/Lab01-powershell-endpoint-triage-basics.md)**  
  *Level: Beginner* → Leveraging PowerShell commands to collect endpoint data, filter logs, and detect potential anomalies in process execution.  

---

## 🎯 Skills Demonstrated
- **Progression of difficulty**: Labs are numbered so complexity builds over time (Lab01 = fundamentals → Lab02+ = deeper, real-world investigations).  
- SIEM log analysis (Splunk, ELK concepts)  
- Threat detection & hunting (VPN anomalies, suspicious processes)  
- Network traffic analysis fundamentals  
- Documentation of repeatable **SOC playbooks**  
- Clear technical communication for both technical and non-technical audiences  

---

## 🚀 How to Use
- Browse the `labs/` folder to view individual exercises.  
- Each lab includes:
  - Step-by-step procedure  
  - Screenshots (`images/`)  
  - Findings & conclusions  
- To understand skill progression:
  - **Start with lower-numbered labs (Lab01)** for fundamentals.  
  - **Move to higher-numbered labs (Lab02, Lab03, …)** to see more advanced detection and analysis scenarios.  

---

## 📌 Next Steps
- Adding **Wireshark labs** (packet capture & analysis).  
- Expanding **Nmap labs** for recon & vulnerability scanning.  
- More advanced SOC scenarios (alert triage, correlation rules, incident response).  

---

## 💡 About
This repo is part of my ongoing transition into cybersecurity, showcasing practical hands-on experience that aligns with **SOC analyst / blue team roles**.  
By structuring labs in increasing difficulty, I aim to show not only **technical skills**, but also **progression and growth** in real-world SOC analyst workflows.
