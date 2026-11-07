# Sends one indicator to the vt-triage API and prints the result.
# Usage:
#   .\test_api.ps1                       # tests spolaect.info
#   .\test_api.ps1 -Indicator 8.8.8.8
# The API key is never stored in this file. It is read from $env:VT_TRIAGE_KEY,
# or you are prompted for it. The prompt masks input and keeps the key out of PowerShell history.

param([string]$Indicator = "spolaect.info")

$uri = "https://cz4s0s2lvb.execute-api.us-east-1.amazonaws.com/prod/triage"

if (-not $env:VT_TRIAGE_KEY) {
    $secure = Read-Host "Paste API key" -AsSecureString
    $env:VT_TRIAGE_KEY = [System.Net.NetworkCredential]::new("", $secure).Password
}

Invoke-RestMethod -Method Post -Uri $uri `
  -Headers @{ "x-api-key" = $env:VT_TRIAGE_KEY } `
  -ContentType "application/json" `
  -Body (@{ indicator = $Indicator } | ConvertTo-Json)
