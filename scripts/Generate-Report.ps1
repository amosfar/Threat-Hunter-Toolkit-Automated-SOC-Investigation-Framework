# =============================================================================
# Generate-Report.ps1
# Accepts all findings arrays and writes investigation_report.txt
# =============================================================================

function Generate-Report {
    param (
        [array]$BruteForcefindings,
        [array]$PowerShellFindings,
        [array]$IOCFindings,
        [array]$ExfilFindings,
        [string]$OutputPath
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $allFindings = @()
    $allFindings += $BruteForcefindings
    $allFindings += $PowerShellFindings
    $allFindings += $IOCFindings
    $allFindings += $ExfilFindings

    $highCount   = ($allFindings | Where-Object { $_.Severity -eq "HIGH" }).Count
    $medCount    = ($allFindings | Where-Object { $_.Severity -eq "MEDIUM" }).Count
    $lowCount    = ($allFindings | Where-Object { $_.Severity -eq "LOW" }).Count

    $report = @()

    $report += "=============================================================="
    $report += "         SECURITY INVESTIGATION REPORT"
    $report += "         SOC Automated Analysis Tool"
    $report += "=============================================================="
    $report += "Generated   : $timestamp"
    $report += "Analyst     : Automated SOC Script"
    $report += ""
    $report += "--------------------------------------------------------------"
    $report += " EXECUTIVE SUMMARY"
    $report += "--------------------------------------------------------------"
    $report += "Total Findings   : $($allFindings.Count)"
    $report += "  HIGH Severity  : $highCount"
    $report += "  MEDIUM Severity: $medCount"
    $report += "  LOW Severity   : $lowCount"
    $report += ""

    if ($allFindings.Count -eq 0) {
        $report += "No suspicious activity detected across all log sources."
    } else {
        $report += "ALERT: Suspicious activity was detected. Review findings below."
    }

    $report += ""

    # -----------------------------------------------------------------------
    # Section 1 - Brute Force
    # -----------------------------------------------------------------------
    $report += "=============================================================="
    $report += " SECTION 1: BRUTE FORCE / FAILED AUTHENTICATION"
    $report += " Log Source: auth.log"
    $report += " Detection Logic: >= 5 failed login attempts from a single IP"
    $report += "=============================================================="

    if ($BruteForcefindings.Count -eq 0) {
        $report += "  No brute force activity detected."
    } else {
        $report += "  $($BruteForcefindings.Count) suspicious IP(s) detected:"
        $report += ""
        foreach ($f in ($BruteForcefindings | Sort-Object FailureCount -Descending)) {
            $report += "  [!] $($f.Severity) - IP: $($f.SourceIP)"
            $report += "      Failed Attempts : $($f.FailureCount)"
            $report += "      First Seen      : $($f.FirstSeen)"
            $report += "      Last Seen       : $($f.LastSeen)"
            $report += "      Detail          : $($f.Detail)"
            $report += ""
        }
    }

    # -----------------------------------------------------------------------
    # Section 2 - Suspicious PowerShell
    # -----------------------------------------------------------------------
    $report += "=============================================================="
    $report += " SECTION 2: SUSPICIOUS POWERSHELL ACTIVITY"
    $report += " Log Source: powershell_log.txt"
    $report += " Detection Logic: Matches against known risky PS patterns"
    $report += "=============================================================="

    if ($PowerShellFindings.Count -eq 0) {
        $report += "  No suspicious PowerShell activity detected."
    } else {
        $report += "  $($PowerShellFindings.Count) suspicious line(s) detected:"
        $report += ""
        foreach ($f in $PowerShellFindings) {
            $report += "  [!] $($f.Severity) - Pattern: $($f.Pattern)"
            $report += "      Line     : $($f.LineNumber)"
            $report += "      Reason   : $($f.Reason)"
            $report += "      Detail   : $($f.Detail)"
            $report += ""
        }
    }

    # -----------------------------------------------------------------------
    # Section 3 - IOC Matches
    # -----------------------------------------------------------------------
    $report += "=============================================================="
    $report += " SECTION 3: INDICATORS OF COMPROMISE (IOC) MATCHES"
    $report += " Log Source: access.log cross-referenced with ioc.txt"
    $report += " Detection Logic: Exact match of any IOC entry in log lines"
    $report += "=============================================================="

    if ($IOCFindings.Count -eq 0) {
        $report += "  No IOC matches detected."
    } else {
        $report += "  $($IOCFindings.Count) IOC match(es) detected:"
        $report += ""
        foreach ($f in $IOCFindings) {
            $report += "  [!] $($f.Severity) - IOC: $($f.MatchedIOC)"
            $report += "      Requesting IP  : $($f.RequestingIP)"
            $report += "      Request        : $($f.RequestDetail)"
            $report += "      Log Line       : $($f.LineNumber)"
            $report += "      Detail         : $($f.Detail)"
            $report += ""
        }
    }

    # -----------------------------------------------------------------------
    # Section 4 - Data Exfiltration
    # -----------------------------------------------------------------------
    $report += "=============================================================="
    $report += " SECTION 4: POTENTIAL DATA EXFILTRATION"
    $report += " Log Sources: powershell_log.txt, access.log"
    $report += " Detection Logic: Archive creation + large POST / suspicious paths"
    $report += "=============================================================="

    if ($ExfilFindings.Count -eq 0) {
        $report += "  No data exfiltration indicators detected."
    } else {
        $report += "  $($ExfilFindings.Count) indicator(s) detected:"
        $report += ""
        foreach ($f in $ExfilFindings) {
            $report += "  [!] $($f.Severity) - Source: $($f.Source)"
            $report += "      Detail : $($f.Detail)"
            $report += ""
        }
    }

    # -----------------------------------------------------------------------
    # Footer
    # -----------------------------------------------------------------------
    $report += "=============================================================="
    $report += " END OF REPORT"
    $report += " This report was generated automatically by the SOC Investigation Tool."
    $report += " Manual review is recommended for all HIGH severity findings."
    $report += "=============================================================="

    # Write to file
    $report | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "[*] Report saved to: $OutputPath" -ForegroundColor Green
}
