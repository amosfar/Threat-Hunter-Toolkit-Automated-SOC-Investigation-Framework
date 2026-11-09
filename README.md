<div align="center">

# 🛡️ Threat Hunter Toolkit

### Automated SOC Investigation Framework

A modular PowerShell toolkit for analyzing security logs, correlating indicators of compromise, and generating an investigation report.

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Focus](https://img.shields.io/badge/Focus-Defensive%20Security-2ea44f)](#-detections)

</div>

---

## ✨ Overview

Run one command to perform a focused investigation across authentication, web access, and PowerShell activity. The toolkit runs separate detection modules, summarizes findings in the console, and writes a report to `investigation_report.txt`.

> **Academic project:** Created for the Advanced Scripting module (COMPH2705) at TU Dublin. Detection results are heuristic indicators for analyst review—not proof of compromise.

## 🔎 Detections

| Detection | Data source | What it looks for |
| --- | --- | --- |
| Brute-force activity | `auth.log` | Repeated failed SSH authentication attempts, grouped by source IP |
| Suspicious PowerShell | `powershell_log.txt` | Risky execution patterns such as encoded commands, execution-policy bypasses, and download/evaluation commands |
| IOC matches | `access.log`, `ioc.txt` | Requests matching indicators in the supplied IOC list |
| Possible data exfiltration | `powershell_log.txt`, `access.log` | Archive-staging behavior and suspicious large POST requests or upload paths |

## 🚀 Quick start

### Requirements

- Windows PowerShell 5.1 or later, or PowerShell 7+
- The supplied dataset files in `ProjectDataset/`

### Run an investigation

From the repository root, run:

```powershell
.\run.ps1
```

The script validates the dataset, loads the modules from `scripts/`, runs each detector, prints a summary, and generates `investigation_report.txt` in the repository root. The brute-force threshold defaults to **5 failed attempts**; the large-POST threshold defaults to **500,000 bytes**.

## 📁 Repository layout

```text
.
├── ProjectDataset/
│   ├── access.log
│   ├── auth.log
│   ├── ioc.txt
│   └── powershell_log.txt
├── scripts/
│   ├── Detect-BruteForce.ps1
│   ├── Detect-DataExfiltration.ps1
│   ├── Detect-IOCMatches.ps1
│   ├── Detect-SuspiciousPowerShell.ps1
│   └── Generate-Report.ps1
├── run.ps1
├── investigation_report.txt
├── LICENSE
└── README.md
```

## ⚙️ Configuration

Default paths are resolved relative to `run.ps1`, so you can launch it from the repository root without editing paths. Detection thresholds are configured near the top of `run.ps1`:

```powershell
$BruteForceThreshold     = 5
$LargePostThresholdBytes = 500000
```

Adjust these values to suit your test data and investigation needs. Lower thresholds can increase false positives.

## 🧭 Interpreting results

- Review each finding in context and corroborate it with other sources before taking action.
- Detection rules are simple pattern and threshold checks; benign activity may match, and novel behavior may not.
- Treat IOC lists and log data as untrusted input. Use authorized datasets and follow your organization's data-handling requirements.
- The supplied logs are project data and may not represent a production environment.

## 📄 License

This project is distributed under the [MIT License](LICENSE).
