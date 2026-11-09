# =============================================================================
# run.ps1  -  SOC Security Investigation Tool
#
# USAGE:
#   .\run.ps1
#
# =============================================================================
#Requires -Version 5.1
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
$ErrorActionPreference = "Stop"

# --------------------------------------------------------------------------
# Configuration - adjust paths here if needed
# --------------------------------------------------------------------------
$DatasetPath   = Join-Path $PSScriptRoot "ProjectDataset"
$ScriptsPath   = Join-Path $PSScriptRoot "scripts"
$ReportOutput  = Join-Path $PSScriptRoot "investigation_report.txt"

$AuthLog       = Join-Path $DatasetPath "auth.log"
$AccessLog     = Join-Path $DatasetPath "access.log"
$PSLog         = Join-Path $DatasetPath "powershell_log.txt"
$IOCFile       = Join-Path $DatasetPath "ioc.txt"

# Detection thresholds
$BruteForceThreshold       = 5       # failed logins before flagging
$LargePostThresholdBytes   = 500000  # 500KB POST = suspicious

# --------------------------------------------------------------------------
# Banner
# --------------------------------------------------------------------------
Clear-Host
Write-Host ""
Write-Host "==============================================================" 
Write-Host "   SOC SECURITY INVESTIGATION TOOL" 
Write-Host "   Automated Log Analysis - PowerShell" 
Write-Host "=============================================================="
Write-Host " Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" 
Write-Host " Dataset : $DatasetPath" 
Write-Host ""

# --------------------------------------------------------------------------
# Validate dataset files exist
# --------------------------------------------------------------------------
Write-Host "[*] Validating dataset files..." 
$missingFiles = @()
foreach ($file in @($AuthLog, $AccessLog, $PSLog, $IOCFile)) {
    if (-not (Test-Path $file)) {
        $missingFiles += $file
        Write-Warning "Missing: $file"
    } else {
        Write-Host "    [OK] $file" 
    }
}

if ($missingFiles.Count -eq 4) {
    Write-Host ""
    Write-Error "No dataset files found. Ensure the ProjectDataset folder is present alongside run.ps1."
    exit 1
}

Write-Host ""

# --------------------------------------------------------------------------
# Load detection modules
# --------------------------------------------------------------------------
Write-Host "[*] Loading detection modules..." 

$modules = @(
    "Detect-BruteForce.ps1",
    "Detect-SuspiciousPowerShell.ps1",
    "Detect-IOCMatches.ps1",
    "Detect-DataExfiltration.ps1",
    "Generate-Report.ps1"
)

foreach ($module in $modules) {
    $modulePath = Join-Path $ScriptsPath $module
    if (Test-Path $modulePath) {
        Unblock-File -Path $modulePath -ErrorAction SilentlyContinue
        . $modulePath
        Write-Host "    [OK] $module" -ForegroundColor Green
    } else {
        Write-Warning "Module not found: $modulePath"
    }
}

Write-Host ""

# --------------------------------------------------------------------------
# Run detections
# --------------------------------------------------------------------------
Write-Host "==============================================================" 
Write-Host " RUNNING DETECTIONS" 
Write-Host "==============================================================" 
Write-Host ""

Write-Host "[1/4] Brute Force / Failed Authentication..." 
$bruteForceResults = Detect-BruteForce `
    -AuthLogPath $AuthLog `
    -Threshold $BruteForceThreshold

Write-Host ""
Write-Host "[2/4] Suspicious PowerShell Activity..." 
$powerShellResults = Detect-SuspiciousPowerShell `
    -PSLogPath $PSLog

Write-Host ""
Write-Host "[3/4] IOC Matching (access.log vs ioc.txt)..." 
$iocResults = Detect-IOCMatches `
    -AccessLogPath $AccessLog `
    -IOCFilePath $IOCFile

Write-Host ""
Write-Host "[4/4] Data Exfiltration Indicators..." 
$exfilResults = Detect-DataExfiltration `
    -PSLogPath $PSLog `
    -AccessLogPath $AccessLog `
    -LargePostThresholdBytes $LargePostThresholdBytes

Write-Host ""

# --------------------------------------------------------------------------
# Display quick summary to console
# --------------------------------------------------------------------------
$total = $bruteForceResults.Count + $powerShellResults.Count + $iocResults.Count + $exfilResults.Count

Write-Host "==============================================================" 
Write-Host " DETECTION SUMMARY" 
Write-Host "==============================================================" 
Write-Host "  Brute Force Findings      : $($bruteForceResults.Count)" 
Write-Host "  PowerShell Findings       : $($powerShellResults.Count)" 
Write-Host "  IOC Match Findings        : $($iocResults.Count)" 
Write-Host "  Exfiltration Findings     : $($exfilResults.Count)" 
Write-Host "  -----------------------------------------------" 
Write-Host "  TOTAL FINDINGS            : $total" -ForegroundColor $(if ($total -gt 0) { "Red" } else { "Green" })
Write-Host ""

# --------------------------------------------------------------------------
# Generate report
# --------------------------------------------------------------------------
Write-Host "[*] Generating investigation report..." 

Generate-Report `
    -BruteForcefindings  $bruteForceResults `
    -PowerShellFindings  $powerShellResults `
    -IOCFindings         $iocResults `
    -ExfilFindings       $exfilResults `
    -OutputPath          $ReportOutput

Write-Host ""
Write-Host "==============================================================" 
Write-Host " INVESTIGATION COMPLETE" 
Write-Host " Report: $ReportOutput" 
Write-Host "==============================================================" 
Write-Host ""
