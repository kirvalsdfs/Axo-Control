<#
Registers the blocking agent as a Windows Scheduled Task that:
  - triggers "At startup" (NOT "At log on"), so it works independent of
    which user (or whether any user) is logged in;
  - runs as SYSTEM (highest privileges, no window);
  - restarts itself automatically if the process exits unexpectedly.

HOW TO RUN: open PowerShell AS ADMINISTRATOR, then:
    cd "C:\path\to\agent"
    powershell -ExecutionPolicy Bypass -File install_agent.ps1

Edit the 3 variables below before running.
#>

# ---------------- EDIT THESE 3 LINES ---------------------------------------
$ServerUrl = "http://192.168.1.50:8765"     # admin PC address
$ApiKey    = "your-secret-key"              # same key as on the server
$PythonExe = "C:\Python312\python.exe"      # full path to python.exe
# ----------------------------------------------------------------------------

$AgentDir    = $PSScriptRoot
$AgentScript = Join-Path $AgentDir "agent.py"
$TaskName    = "PCControlAgent"

if (-not (Test-Path $PythonExe)) {
    Write-Warning "Cannot find $PythonExe. Run 'where python' to get the correct path and fix the `$PythonExe variable in this file."
    exit 1
}
if (-not (Test-Path $AgentScript)) {
    Write-Warning "Cannot find agent.py next to this script ($AgentScript)."
    exit 1
}

Write-Host "Setting machine-wide environment variables..."
[Environment]::SetEnvironmentVariable("PC_CONTROL_SERVER", $ServerUrl, "Machine")
[Environment]::SetEnvironmentVariable("PC_CONTROL_API_KEY", $ApiKey, "Machine")

Write-Host "Registering scheduled task '$TaskName'..."

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

$action = New-ScheduledTaskAction `
    -Execute $PythonExe `
    -Argument "`"$AgentScript`"" `
    -WorkingDirectory $AgentDir

$trigger = New-ScheduledTaskTrigger -AtStartup

$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Force | Out-Null

Write-Host "Done. Task '$TaskName' created: starts at system boot, as SYSTEM, independent of any user."
Write-Host "Starting the task now so you don't have to reboot..."
Start-ScheduledTask -TaskName $TaskName

Start-Sleep -Seconds 2
$task = Get-ScheduledTask -TaskName $TaskName
Write-Host "Task state: $($task.State)"
Write-Host "Check the dashboard (http://<admin-pc-ip>:8765) - this PC should appear in the list if the agent started correctly."
