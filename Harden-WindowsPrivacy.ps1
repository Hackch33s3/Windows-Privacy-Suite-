<#
.SYNOPSIS
  Consolidated Windows privacy hardening script.
  Clears or blocks 15+ forensic artifacts including ShellBags, RunMRU, Jump Lists,
  Prefetch, Telemetry, and more. Modular design with -WhatIf support.

.DESCRIPTION
  Run as CURRENT USER for HKCU keys. Some actions require admin elevation
  (Prefetch, Event Logs, Services) - script will warn and skip if not elevated.

  Switches:
    -BlockShellBags     Apply Deny Write ACLs to ShellBag keys (default: clear only)
    -ClearTelemetry     Stop and disable DiagTrack, dmwappushservice, OneSyncSvc
    -ClearEventLogs     Clear Security, System, Shell-Core operational logs
    -ClearBrowserData   Clear history/cache for Edge, Chrome, Firefox (profile-based)
    -WhatIf             Show what would be done without making changes

  Logs all actions to: $env:TEMP\PrivacyHardening_YYYYMMDD_HHMMSS.log

.EXAMPLE
  .\Harden-WindowsPrivacy.ps1 -BlockShellBags -ClearTelemetry -WhatIf
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$BlockShellBags,
    [switch]$ClearTelemetry,
    [switch]$ClearEventLogs,
    [switch]$ClearBrowserData
)

# === CONFIG ===
$LogPath = Join-Path $env:TEMP "PrivacyHardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$AdminRequired = $ClearTelemetry -or $ClearEventLogs -or $ClearBrowserData
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $entry -Force
    switch ($Level) {
        "ERROR" { Write-Host $Message -ForegroundColor Red }
        "WARN"  { Write-Host $Message -ForegroundColor Yellow }
        "OK"    { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message }
    }
}

if ($AdminRequired -and -not $IsAdmin) {
    Write-Log "Some requested actions require administrator privileges. Re-run as Admin for full effect." "WARN"
}

# === SHELLBAGS ===
function Clear-ShellBags {
    param([switch]$Block)
    $paths = @(
        "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags",
        "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
        "HKCU:\Software\Microsoft\Windows\Shell\Bags",
        "HKCU:\Software\Microsoft\Windows\Shell\BagMRU",
        "HKCU:\Software\Microsoft\Windows\ShellNoRoam\Bags",
        "HKCU:\Software\Microsoft\Windows\ShellNoRoam\BagMRU"
    )
    if ([Environment]::Is64BitOperatingSystem) {
        $paths += @(
            "HKCU:\Software\Classes\Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\Bags",
            "HKCU:\Software\Classes\Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"
        )
    }

    foreach ($p in $paths) {
        if (Test-Path $p) {
            if ($PSCmdlet.ShouldProcess($p, "Delete registry key")) {
                try {
                    Remove-Item -Path $p -Recurse -Force -ErrorAction Stop
                    Write-Log "Cleared: $p" "OK"
                } catch {
                    Write-Log "Failed to clear $p : $_" "ERROR"
                }
            }
            if ($Block) {
                try {
                    if (-not (Test-Path $p)) { New-Item -Path $p -Force -ErrorAction SilentlyContinue | Out-Null }
                    $acl = Get-Acl -Path $p
                    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                    $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
                        $user,
                        [System.Security.AccessControl.RegistryRights]::WriteKey,
                        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
                        [System.Security.AccessControl.PropagationFlags]::None,
                        [System.Security.AccessControl.AccessControlType]::Deny
                    )
                    $acl.AddAccessRule($rule)
                    if ($PSCmdlet.ShouldProcess($p, "Apply Deny Write ACL")) {
                        Set-Acl -Path $p -AclObject $acl -ErrorAction Stop
                        Write-Log "ACL applied (Deny Write): $p" "OK"
                    }
                } catch {
                    Write-Log "Failed to set ACL on $p : $_" "ERROR"
                }
            }
        }
    }
}

# === RUNMRU / TYPEDPATHS / USERASSIST / RECENTDOCS ===
function Clear-ExplorerArtifacts {
    $keys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"
    )
    foreach ($k in $keys) {
        if (Test-Path $k) {
            if ($PSCmdlet.ShouldProcess($k, "Delete registry key")) {
                try {
                    Remove-Item -Path $k -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log "Cleared: $k" "OK"
                } catch {
                    Write-Log "Failed to clear $k : $_" "WARN"
                }
            }
        }
    }
}

# === JUMP LISTS ===
function Clear-JumpLists {
    $paths = @(
        "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations",
        "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) {
            if ($PSCmdlet.ShouldProcess($p, "Delete Jump List files")) {
                try {
                    Get-ChildItem -Path $p -File -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
                    Write-Log "Cleared Jump Lists: $p" "OK"
                } catch {
                    Write-Log "Failed to clear Jump Lists $p : $_" "WARN"
                }
            }
        }
    }
}

# === PREFETCH / AMCACHE ===
function Clear-SystemArtifacts {
    if (-not $IsAdmin) {
        Write-Log "Skipping Prefetch/Amcache cleanup: requires administrator" "WARN"
        return
    }
    $prefetch = "C:\Windows\Prefetch"
    $amcache = "C:\Windows\AppCompat\Programs\Amcache.hve"
    $recentfilecache = "C:\Windows\AppCompat\Programs\RecentFileCache.bcf"

    if (Test-Path $prefetch) {
        if ($PSCmdlet.ShouldProcess($prefetch, "Delete Prefetch files")) {
            try {
                Get-ChildItem -Path $prefetch -Filter "*.pf" -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
                Write-Log "Cleared Prefetch entries" "OK"
            } catch {
                Write-Log "Failed to clear Prefetch: $_" "ERROR"
            }
        }
    }
    foreach ($f in @($amcache, $recentfilecache)) {
        if (Test-Path $f) {
            if ($PSCmdlet.ShouldProcess($f, "Delete compatibility cache file")) {
                try {
                    Remove-Item -Path $f -Force -ErrorAction SilentlyContinue
                    Write-Log "Cleared: $f" "OK"
                } catch {
                    Write-Log "Failed to clear $f : $_" "WARN"
                }
            }
        }
    }
}

# === TELEMETRY SERVICES ===
function Disable-TelemetryServices {
    if (-not $IsAdmin) {
        Write-Log "Skipping telemetry service disable: requires administrator" "WARN"
        return
    }
    $services = @("DiagTrack", "dmwappushservice", "OneSyncSvc")
    foreach ($svc in $services) {
        try {
            $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($service) {
                if ($PSCmdlet.ShouldProcess($svc, "Stop and disable service")) {
                    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
                    Write-Log "Disabled telemetry service: $svc" "OK"
                }
            }
        } catch {
            Write-Log "Failed to manage service $svc : $_" "WARN"
        }
    }
}

# === EVENT LOGS ===
function Clear-EventLogs {
    if (-not $IsAdmin) {
        Write-Log "Skipping event log cleanup: requires administrator" "WARN"
        return
    }
    $logs = @(
        "Security", "System", "Application",
        "Microsoft-Windows-Shell-Core/Operational",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-TaskScheduler/Operational"
    )
    foreach ($log in $logs) {
        try {
            if ($PSCmdlet.ShouldProcess($log, "Clear event log")) {
                WevtUtil.exe cl $log 2>$null
                Write-Log "Cleared event log: $log" "OK"
            }
        } catch {
            Write-Log "Failed to clear log $log : $_" "WARN"
        }
    }
}

# === BROWSER DATA (Optional) ===
function Clear-BrowserData {
    if (-not $IsAdmin) {
        Write-Log "Browser data cleanup may fail without admin for some profiles" "WARN"
    }
    $profiles = @(
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default",
        "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release"
    )
    $subpaths = @("History", "Cache", "Cache\Cache", "Network Action Predictor", "Visited Links")
    foreach ($prof in $profiles) {
        if (Test-Path $prof) {
            foreach ($sub in $subpaths) {
                $target = Join-Path $prof $sub
                if (Test-Path $target) {
                    if ($PSCmdlet.ShouldProcess($target, "Delete browser artifact")) {
                        try {
                            Remove-Item -Path $target -Recurse -Force -ErrorAction SilentlyContinue
                            Write-Log "Cleared browser data: $target" "OK"
                        } catch {
                            Write-Log "Failed to clear $target : $_" "WARN"
                        }
                    }
                }
            }
        }
    }
}

# === EXECUTION ===
Write-Log "=== Privacy Hardening Started ===" "INFO"
Clear-ShellBags -Block:$BlockShellBags
Clear-ExplorerArtifacts
Clear-JumpLists
Clear-SystemArtifacts
if ($ClearTelemetry) { Disable-TelemetryServices }
if ($ClearEventLogs) { Clear-EventLogs }
if ($ClearBrowserData) { Clear-BrowserData }
Write-Log "=== Privacy Hardening Complete ===" "INFO"
Write-Log "Log saved to: $LogPath" "OK"