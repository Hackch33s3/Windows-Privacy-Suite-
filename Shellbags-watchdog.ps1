<#
.SYNOPSIS
  Watchdog script with visual progress bar and status output.
  Monitors ShellBag keys and reapplies Deny Write ACLs if drifted.
#>

$LogPath = Join-Path $env:TEMP "ShellBagWatchdog_$(Get-Date -Format 'yyyyMMdd').log"
$BarWidth = 36

$Keys = @(
    "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags",
    "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
    "HKCU:\Software\Microsoft\Windows\Shell\Bags",
    "HKCU:\Software\Microsoft\Windows\Shell\BagMRU",
    "HKCU:\Software\Microsoft\Windows\ShellNoRoam\Bags",
    "HKCU:\Software\Microsoft\Windows\ShellNoRoam\BagMRU"
)
if ([Environment]::Is64BitOperatingSystem) {
    $Keys += @(
        "HKCU:\Software\Classes\Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\Bags",
        "HKCU:\Software\Classes\Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"
    )
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "HH:mm:ss"
    $icon = switch ($Level) { "OK"{"[OK]"}; "WARN"{"[!]"}; "ERR"{"[X]"}; default{"[·]"} }
    $color = switch ($Level) { "OK"{"Green"}; "WARN"{"Yellow"}; "ERR"{"Red"}; default{"White"} }
    Add-Content -Path $LogPath -Value "[$ts] $icon $Message" -Force
    Write-Host "$icon $Message" -ForegroundColor $color
}

function Write-ProgressMini {
    param([int]$Percent, [string]$Label = "")
    $filled = [Math]::Round(($Percent / 100) * $BarWidth)
    $bar = "[" + ("a" * $filled) + (" " * ($BarWidth - $filled)) + "]"
    Write-Host "`r$Label $bar $Percent%" -NoNewline -ForegroundColor Cyan
}

function Test-ShellBagACL {
    param([string]$Path)
    try {
        $acl = Get-Acl -Path $Path -ErrorAction Stop
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $denyRules = $acl.Access | Where-Object {
            $_.IdentityReference.Value -eq $identity -and
            $_.AccessControlType -eq 'Deny' -and
            ($_.RegistryRights -band [System.Security.AccessControl.RegistryRights]::WriteKey)
        }
        return ($denyRules.Count -gt 0)
    } catch { return $false }
}

function Enforce-ShellBagACL {
    param([string]$Path)
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force -ErrorAction SilentlyContinue | Out-Null
            Write-Log "Recreated key: $Path" "OK"
        }
        $acl = Get-Acl -Path $Path
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $user = New-Object System.Security.Principal.NTAccount($identity)

        # Remove existing deny rules first to avoid conflicts
        $existingDeny = $acl.Access | Where-Object {
            $_.IdentityReference.Value -eq $identity -and $_.AccessControlType -eq 'Deny'
        }
        foreach ($rule in $existingDeny) { $acl.RemoveAccessRule($rule) | Out-Null }

        $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $user,
            [System.Security.AccessControl.RegistryRights]::WriteKey,
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Deny
        )
        $acl.AddAccessRule($rule)
        Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop
        Write-Log "ACL enforced: $Path" "OK"
        return $true
    } catch {
        Write-Log "Failed ACL on $Path : $_" "ERR"
        return $false
    }
}

# === MAIN LOOP ===
Write-Host ""
Write-Host "=== ShellBag Watchdog Cycle ===" -ForegroundColor Magenta
Write-Host "Monitoring $($Keys.Count) keys" -ForegroundColor Gray
Write-Host ""

$total = $Keys.Count; $corrected = 0
for ($i = 0; $i -lt $total; $i++) {
    $key = $Keys[$i]
    $pct = [Math]::Round((($i + 1) / $total) * 100)
    Write-ProgressMini -Percent $pct -Label "Scanning"

    $exists = Test-Path $key
    $aclOk = if ($exists) { Test-ShellBagACL -Path $key } else { $false }

    if (-not $exists -or -not $aclOk) {
        Write-Log "Drift: $key (exists=$exists, ACL=$aclOk)" "WARN"
        if (Enforce-ShellBagACL -Path $key) { $corrected++ }
    }
    Start-Sleep -Milliseconds 100
}
Write-ProgressMini -Percent 100 -Label "Complete"
Write-Host ""
Write-Host ""
Write-Log "Cycle done. Keys corrected: $corrected / $total" "OK"
Write-Host "Log: $LogPath" -ForegroundColor Gray
