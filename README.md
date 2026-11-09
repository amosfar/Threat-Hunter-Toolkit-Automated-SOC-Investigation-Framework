# Threat-Hunter-Toolkit-Automated-SOC-Investigation-Framework

An automated Security Operations Centre (SOC) investigation framework built using **PowerShell** for the Advanced Scripting module (COMPH2705) at TU Dublin.

## Project Overview
The Threat Hunter Toolkit is designed to assist security analysts by automatically parsing, analyzing, and correlating multiple log sources to uncover malicious activity. Triggered by a single execution script, the tool analyzes system logs against known Indicators of Compromise (IOCs) and outputs a comprehensive, structured investigation report.

---

## Log Sources Analyzed
The tool processes four distinct dataset files:
* **`access.log`** — Web server access logs capturing HTTP requests.
* **`auth.log`** — Authentication logs recording successful and failed SSH login attempts.
* **`powershell_log.txt`** — Host-level logs tracking PowerShell command executions.
* **`ioc.txt`** — A curated list of known Indicators of Compromise (IP addresses, URLs, file paths).

---

## Core Detection Capabilities

1. Brute Force / Failed Authentication Detection
   * Scans `auth.log` for rejected OpenSSH login attempts (`Failed password` or `Invalid user`).
   * Flags source IPs exceeding a threshold of 5 failed attempts and assigns a severity rating (Low, Medium, High) based on frequency.

2. Suspicious PowerShell Execution
   * Inspects `powershell_log.txt` line by line for high-risk execution patterns.
   * Targets dangerous commands such as `-EncodedCommand`, `-ExecutionPolicy Bypass`, `Invoke-WebRequest`, and `Invoke-Expression`.

3. Indicator of Compromise (IOC) Matching
   * Cross-references `access.log` entries against the ground-truth list in `ioc.txt`.
   * Automatically flags any contact with a known malicious indicator as **HIGH** severity.

4. Data Exfiltration Detection
   * Analyzes both `powershell_log.txt` and `access.log` for staging and transfer behaviors.
   * Identifies archive creation commands (`Compress-Archive`, `.zip`, `.tar`) and suspicious outbound large POST requests or upload paths.

---

## Getting Started & Execution

The entire investigation workflow is modular, with each detection function stored in its own script and loaded dynamically via PowerShell dot-sourcing[cite: 1].

1. Ensure all dataset files (`access.log`, `auth.log`, `powershell_log.txt`, `ioc.txt`) are in the project directory alongside the scripts.
2. Open PowerShell and run the main entry point script:
   ```powershell
   .\run.ps1
