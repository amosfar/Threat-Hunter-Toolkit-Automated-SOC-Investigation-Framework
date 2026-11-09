# =============================================================================
# Detect-IOCMatches.ps1
# Cross-references IPs and URLs from access.log against ioc.txt
# =============================================================================

function Detect-IOCMatches {
    param (
        [string]$AccessLogPath,
        [string]$IOCFilePath
    )

    $findings = @()

    if (-not (Test-Path $AccessLogPath)) {
        Write-Warning "[IOC] access.log not found at: $AccessLogPath"
        return $findings
    }

    if (-not (Test-Path $IOCFilePath)) {
        Write-Warning "[IOC] ioc.txt not found at: $IOCFilePath"
        return $findings
    }

    # Load IOC list - skip blank lines and comments
    $iocList = Get-Content $IOCFilePath | Where-Object {
        $_.Trim() -ne "" -and $_ -notmatch "^#"
    } | ForEach-Object { $_.Trim() }

    Write-Host "[*] Loaded $($iocList.Count) IOC entries from ioc.txt" -ForegroundColor Yellow

    $accessLines = Get-Content $AccessLogPath
    $lineNumber = 0

    foreach ($line in $accessLines) {
        $lineNumber++
        foreach ($ioc in $iocList) {
            if ($line -match [regex]::Escape($ioc)) {
                # Try to extract requesting IP (first field in Common Log Format)
                $requestingIP = "Unknown"
                if ($line -match "^(\d{1,3}(\.\d{1,3}){3})") {
                    $requestingIP = $Matches[1]
                }

                # Try to extract HTTP method + path
                $requestDetail = "N/A"
                if ($line -match '"([A-Z]+\s+\S+\s+HTTP/\S+)"') {
                    $requestDetail = $Matches[1]
                }

                $findings += [PSCustomObject]@{
                    DetectionType  = "IOC Match"
                    LineNumber     = $lineNumber
                    MatchedIOC     = $ioc
                    RequestingIP   = $requestingIP
                    RequestDetail  = $requestDetail
                    Severity       = "HIGH"
                    Detail         = "IOC '$ioc' matched in access.log line $lineNumber (from IP: $requestingIP)"
                }
                break  # One IOC match per line is enough
            }
        }
    }

    Write-Host "[*] IOC Match Detection: $($findings.Count) match(es) found." -ForegroundColor Cyan
    return $findings
}
