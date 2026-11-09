# =============================================================================
# Detect-DataExfiltration.ps1
# Detects potential data exfiltration indicators
# =============================================================================

function Detect-DataExfiltration {
    param (
        [string]$PSLogPath,
        [string]$AccessLogPath,
        [int]$LargePostThresholdBytes = 500000   # 500KB default threshold
    )

    $findings = @()

    # --- Part 1: Archive creation in PowerShell log ---
    if (Test-Path $PSLogPath) {
        $psLines = Get-Content $PSLogPath
        $lineNumber = 0

        $archivePatterns = @("Compress-Archive", "\.zip", "\.tar", "\.rar", "\.7z", "ZipFile")

        foreach ($line in $psLines) {
            $lineNumber++
            foreach ($pattern in $archivePatterns) {
                if ($line -match $pattern) {
                    $findings += [PSCustomObject]@{
                        DetectionType = "Potential Data Exfiltration"
                        Source        = "powershell_log.txt"
                        LineNumber    = $lineNumber
                        Severity      = "MEDIUM"
                        Detail        = "Archive operation detected at line $lineNumber`: $($line.Trim())"
                    }
                    break
                }
            }
        }
    } else {
        Write-Warning "[Exfiltration] powershell_log.txt not found at: $PSLogPath"
    }

    # --- Part 2: Large POST requests in access.log ---
    if (Test-Path $AccessLogPath) {
        $accessLines = Get-Content $AccessLogPath
        $lineNumber = 0

        foreach ($line in $accessLines) {
            $lineNumber++

            # Common Log Format: IP - - [date] "METHOD path HTTP/x" status bytes
            if ($line -match '"POST\s+(\S+)\s+HTTP') {
                $path = $Matches[1]

                # Extract response size (field after status code)
                if ($line -match '"\s+\d{3}\s+(\d+)') {
                    $bytes = [int]$Matches[1]
                    if ($bytes -ge $LargePostThresholdBytes) {
                        $requestingIP = "Unknown"
                        if ($line -match "^(\d{1,3}(\.\d{1,3}){3})") {
                            $requestingIP = $Matches[1]
                        }

                        $findings += [PSCustomObject]@{
                            DetectionType = "Potential Data Exfiltration"
                            Source        = "access.log"
                            LineNumber    = $lineNumber
                            RequestingIP  = $requestingIP
                            Path          = $path
                            Bytes         = $bytes
                            Severity      = "HIGH"
                            Detail        = "Large POST from $requestingIP to '$path' ($bytes bytes) at line $lineNumber"
                        }
                    }
                }
            }

            # Also flag suspicious upload paths
            if ($line -match '"(POST|PUT)\s+.*(upload|exfil|transfer|backup|dump).*HTTP' ) {
                $requestingIP = "Unknown"
                if ($line -match "^(\d{1,3}(\.\d{1,3}){3})") {
                    $requestingIP = $Matches[1]
                }
                $findings += [PSCustomObject]@{
                    DetectionType = "Potential Data Exfiltration"
                    Source        = "access.log"
                    LineNumber    = $lineNumber
                    RequestingIP  = $requestingIP
                    Severity      = "HIGH"
                    Detail        = "Suspicious upload/transfer path detected at line $lineNumber`: $($line.Trim())"
                }
            }
        }
    } else {
        Write-Warning "[Exfiltration] access.log not found at: $AccessLogPath"
    }

    Write-Host "[*] Data Exfiltration Detection: $($findings.Count) indicator(s) found." -ForegroundColor Cyan
    return $findings
}
