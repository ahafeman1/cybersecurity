# Sends one indicator to the vt-triage API and prints the result.
# Usage:
#   .\test_api.ps1                       # tests spolaect.info
#   .\test_api.ps1 -Indicator 8.8.8.8
# Neither the endpoint nor the API key is stored in this file.
#   $env:VT_TRIAGE_URL  the full invoke URL, e.g. https://<api-id>.execute-api.us-east-1.amazonaws.com/prod/triage
#   $env:VT_TRIAGE_KEY  the API key (the prompt masks input and keeps it out of PowerShell history)
# You are prompted for either one if it is not set.

param([string]$Indicator = "spolaect.info")

if (-not $env:VT_TRIAGE_URL) { $env:VT_TRIAGE_URL = Read-Host "Paste invoke URL (ending in /prod/triage)" }
$uri = $env:VT_TRIAGE_URL

if (-not $env:VT_TRIAGE_KEY) {
    $secure = Read-Host "Paste API key" -AsSecureString
    $env:VT_TRIAGE_KEY = [System.Net.NetworkCredential]::new("", $secure).Password
}

Invoke-RestMethod -Method Post -Uri $uri `
  -Headers @{ "x-api-key" = $env:VT_TRIAGE_KEY } `
  -ContentType "application/json" `
  -Body (@{ indicator = $Indicator } | ConvertTo-Json)
