Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# =============================================================================
# Detect-BruteForce.ps1
# Detects repeated failed SSH authentication attempts from auth.log
# Threshold: 5+ failures from the same IP = suspicious
# =============================================================================

function Detect-BruteForce {
    param (
        [string]$AuthLogPath,
        [int]$Threshold = 5
    )

    $findings = @()

    if (-not (Test-Path $AuthLogPath)) {
        Write-Warning "[BruteForce] auth.log not found at: $AuthLogPath"
        return $findings
    }

    $lines = Get-Content $AuthLogPath

    # Match lines containing failed password or invalid user attempts
    $failedLines = $lines | Where-Object {
        $_ -match "Failed password" -or $_ -match "Invalid user"
    }

    # Extract IP addresses using regex
    $ipCounts   = @{}
    $ipFirstSeen = @{}
    $ipLastSeen  = @{}

    foreach ($line in $failedLines) {
        if ($line -match "from (\d{1,3}(\.\d{1,3}){3})") {
            $ip = $Matches[1]

            # PS 5.1 compatible null coalescing
            if ($ipCounts.ContainsKey($ip)) {
                $ipCounts[$ip] = $ipCounts[$ip] + 1
            } else {
                $ipCounts[$ip] = 1
            }

            # Try to extract timestamp (first 15 chars e.g. "Mar 10 04:12:33")
            $timestamp = $line.Substring(0, [Math]::Min(15, $line.Length)).Trim()

            if (-not $ipFirstSeen.ContainsKey($ip)) {
                $ipFirstSeen[$ip] = $timestamp
            }
            $ipLastSeen[$ip] = $timestamp
        }
    }

    # Filter IPs exceeding threshold
    foreach ($ip in $ipCounts.Keys) {
        if ($ipCounts[$ip] -ge $Threshold) {
            $findings += [PSCustomObject]@{
                DetectionType = "Brute Force / Failed Auth"
                SourceIP      = $ip
                FailureCount  = $ipCounts[$ip]
                FirstSeen     = $ipFirstSeen[$ip]
                LastSeen      = $ipLastSeen[$ip]
                Severity      = if ($ipCounts[$ip] -ge 20) { "HIGH" } elseif ($ipCounts[$ip] -ge 10) { "MEDIUM" } else { "LOW" }
                Detail        = "IP $ip had $($ipCounts[$ip]) failed login attempts (threshold: $Threshold)"
            }
        }
    }

    Write-Host "[*] Brute Force Detection: $($findings.Count) suspicious IP(s) found." -ForegroundColor Cyan
    return $findings
}
