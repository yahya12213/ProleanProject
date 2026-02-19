param(
  [Parameter(Mandatory = $true)][string]$Area,
  [Parameter(Mandatory = $true)][string]$Type,
  [Parameter(Mandatory = $true)][string]$What,
  [Parameter(Mandatory = $false)][string]$Why = "",
  [Parameter(Mandatory = $false)][string]$Validation = ""
)

$ErrorActionPreference = "Stop"

$logPath = Join-Path $PSScriptRoot "..\\Summary of Features & Changes.txt"
$utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd")

$lines = @()
$lines += ""
$lines += "[$utc UTC] Area: $Area | Type: $Type"
$lines += "- What changed:"
$lines += "  - $What"
if ($Why.Trim()) {
  $lines += "- Why:"
  $lines += "  - $Why"
}
if ($Validation.Trim()) {
  $lines += "- Validation:"
  $lines += "  - $Validation"
}

Add-Content -Path $logPath -Value ($lines -join "`r`n") -Encoding UTF8
Write-Host "Appended changelog entry to: $logPath"

