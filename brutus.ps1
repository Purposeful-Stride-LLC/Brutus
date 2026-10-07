#!/usr/bin/powershell
$Path = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "    BRUTUS SECURITY SCANNER - PowerShell Launcher" -ForegroundColor Cyan
Write-Host "         COMPREHENSIVE ANALYSIS TOOL" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

python "$Path\brutus_runner.py" $args

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "BRUTUS ANALYSIS COMPLETE!" -ForegroundColor Green
    Write-Host "Report saved to: $Path\report.html" -ForegroundColor Yellow
    Write-Host "Open with: start "" chrome "" $Path\report.html" -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "*** ERROR: Analysis failed. Check Python and dependencies. ***" -ForegroundColor Red
}

Read-Host -Prompt "Press Enter to exit..."
