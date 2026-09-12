[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId = $env:AZURE_SUBSCRIPTION_ID,

    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName = $env:AZURE_RESOURCE_GROUP,

    [Parameter(Mandatory = $false)]
    [string]$WorkspaceName = $env:AZURE_WORKSPACE_NAME,

    [Parameter(Mandatory = $false)]
    [string]$DetectionsPath = (Join-Path $PSScriptRoot "..\Detections")
)

$ErrorActionPreference = 'Stop'

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "🚀 Microsoft Sentinel Detection-as-Code Deployment" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Subscription ID : $SubscriptionId"
Write-Host "Resource Group  : $ResourceGroupName"
Write-Host "Workspace Name  : $WorkspaceName"
Write-Host "Detections Path : $DetectionsPath"
Write-Host "==========================================================" -ForegroundColor Cyan

if (-not (Test-Path $DetectionsPath)) {
    throw "Detections directory not found at $DetectionsPath"
}

$ruleFiles = Get-ChildItem -Path $DetectionsPath -Filter "*.json" -Recurse
Write-Host "Found $($ruleFiles.Count) detection rule file(s) to process." -ForegroundColor Yellow

$results = @()

foreach ($file in $ruleFiles) {
    Write-Host "`nProcessing: $($file.Name)..." -ForegroundColor White
    try {
        $jsonContent = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
        $resource = $jsonContent.resources[0]
        $ruleName = $resource.properties.displayName
        $ruleGuid = $resource.name
        $severity = $resource.properties.severity
        $enabled = $resource.properties.enabled

        Write-Host "  Rule Name : $ruleName" -ForegroundColor Gray
        Write-Host "  Rule GUID : $ruleGuid" -ForegroundColor Gray
        Write-Host "  Severity  : $severity" -ForegroundColor Gray
        Write-Host "  Enabled   : $enabled" -ForegroundColor Gray

        # Prepare request payload for Sentinel REST API
        $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules/$ruleGuid`?api-version=2023-02-01-preview"
        
        $body = @{
            kind = $resource.kind
            properties = $resource.properties
        } | ConvertTo-Json -Depth 10

        # Deploy via az rest
        $tempBodyFile = [System.IO.Path]::GetTempFileName()
        [System.IO.File]::WriteAllText($tempBodyFile, $body, [System.Text.Encoding]::UTF8)

        $azResult = az rest --method put --uri $uri --headers "Content-Type=application/json" --body "@$tempBodyFile" | ConvertFrom-Json
        Remove-Item $tempBodyFile -Force -ErrorAction SilentlyContinue

        if ($azResult.id) {
            Write-Host "  ✅ Successfully deployed/updated rule: $ruleName" -ForegroundColor Green
            $results += [PSCustomObject]@{
                RuleName = $ruleName
                Category = $file.Directory.Name
                Severity = $severity
                Status   = "Deployed"
            }
        } else {
            Write-Warning "  ⚠️ Deployment returned non-standard response for $($file.Name)"
            $results += [PSCustomObject]@{
                RuleName = $ruleName
                Category = $file.Directory.Name
                Severity = $severity
                Status   = "Warning"
            }
        }
    }
    catch {
        Write-Error "  ❌ Failed to deploy $($file.Name): $($_.Exception.Message)"
        $results += [PSCustomObject]@{
            RuleName = $file.Name
            Category = $file.Directory.Name
            Severity = "N/A"
            Status   = "Failed: $($_.Exception.Message)"
        }
    }
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "📊 Sentinel Deployment Summary" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
$results | Format-Table -AutoSize

$failedCount = ($results | Where-Object { $_.Status -like "Failed*" }).Count
if ($failedCount -gt 0) {
    throw "Deployment completed with $failedCount failure(s)."
}

Write-Host "`n🎉 All Sentinel Analytic Rules deployed successfully!" -ForegroundColor Green
