# =============================================================================
# Detect-SuspiciousPowerShell.ps1
# Detects risky PowerShell execution patterns in powershell_log.txt
# =============================================================================

function Detect-SuspiciousPowerShell {
    param (
        [string]$PSLogPath
    )

    $findings = @()

    if (-not (Test-Path $PSLogPath)) {
        Write-Warning "[PowerShell] powershell_log.txt not found at: $PSLogPath"
        return $findings
    }

    $lines = Get-Content $PSLogPath

    # Define suspicious patterns with severity levels
    $suspiciousPatterns = @(
        @{ Pattern = "-EncodedCommand";         Severity = "HIGH";   Reason = "Encoded command used to obfuscate payload" },
        @{ Pattern = "-ExecutionPolicy Bypass"; Severity = "HIGH";   Reason = "Execution policy bypass to run unsigned scripts" },
        @{ Pattern = "Invoke-WebRequest";       Severity = "HIGH";   Reason = "Downloading content from the internet" },
        @{ Pattern = "DownloadString";          Severity = "HIGH";   Reason = "In-memory download and execute technique" },
        @{ Pattern = "DownloadFile";            Severity = "HIGH";   Reason = "File download from remote source" },
        @{ Pattern = "Invoke-Expression";       Severity = "HIGH";   Reason = "Dynamic code execution (common in malware)" },
        @{ Pattern = "IEX";                     Severity = "HIGH";   Reason = "Shorthand for Invoke-Expression" },
        @{ Pattern = "Start-Process";           Severity = "MEDIUM"; Reason = "Process execution via PowerShell" },
        @{ Pattern = "Net.WebClient";           Severity = "HIGH";   Reason = "WebClient object used for downloads" },
        @{ Pattern = "Hidden";                  Severity = "MEDIUM"; Reason = "Hidden window style - conceals execution" },
        @{ Pattern = "Bypass";                  Severity = "MEDIUM"; Reason = "Generic bypass keyword detected" },
        @{ Pattern = "compress-archive";        Severity = "MEDIUM"; Reason = "Archive creation - possible data staging" },
        @{ Pattern = "FromBase64String";        Severity = "HIGH";   Reason = "Base64 decoding - likely obfuscated payload" }
    )

    $lineNumber = 0

    foreach ($line in $lines) {
        $lineNumber++
        foreach ($entry in $suspiciousPatterns) {
            if ($line -match [regex]::Escape($entry.Pattern)) {
                $findings += [PSCustomObject]@{
                    DetectionType = "Suspicious PowerShell"
                    LineNumber    = $lineNumber
                    Pattern       = $entry.Pattern
                    Severity      = $entry.Severity
                    Reason        = $entry.Reason
                    Detail        = "Line $lineNumber`: $($line.Trim())"
                }
                break  # Only report first match per line to avoid duplicates
            }
        }
    }

    Write-Host "[*] Suspicious PowerShell Detection: $($findings.Count) suspicious line(s) found." -ForegroundColor Cyan
    return $findings
}
