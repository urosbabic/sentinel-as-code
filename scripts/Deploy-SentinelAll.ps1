[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId = $env:AZURE_SUBSCRIPTION_ID,

    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName = $env:AZURE_RESOURCE_GROUP,

    [Parameter(Mandatory = $false)]
    [string]$WorkspaceName = $env:AZURE_WORKSPACE_NAME,

    [Parameter(Mandatory = $false)]
    [string]$DetectionsPath = "$PSScriptRoot\..\MicrosoftSentinel\Detections",

    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

$ErrorActionPreference = 'Continue'

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " 🛡️  MICROSOFT SENTINEL DETECTION-AS-CODE DEPLOYMENT ENGINE" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Tenant Subscription : $SubscriptionId" -ForegroundColor Gray
Write-Host " Resource Group      : $ResourceGroupName" -ForegroundColor Gray
Write-Host " Sentinel Workspace  : $WorkspaceName" -ForegroundColor Gray
Write-Host " Content Directory   : $DetectionsPath" -ForegroundColor Gray
Write-Host " Execution Mode      : $(if ($DryRun) { 'Dry Run (Validation Only)' } else { 'Live Production Deployment' })" -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Cyan

# Ensure Subscription is set
az account set --subscription $SubscriptionId 2>&1 | Out-Null

$yamlFiles = Get-ChildItem -Path $DetectionsPath -Recurse -Include *.yaml, *.yml | Where-Object { $_.Name -notmatch "template\.yaml" }
Write-Host "`n🔍 Discovered $($yamlFiles.Count) detection rule definition(s) across categories.`n" -ForegroundColor Yellow

$results = @()
$successCount = 0
$failCount = 0

foreach ($file in $yamlFiles) {
    $category = $file.Directory.Name
    Write-Host "⚡ Processing [$category] > $($file.Name)" -ForegroundColor White

    try {
        $armJsonString = Convert-SentinelARYamlToArm -Filename $file.FullName
        if ([string]::IsNullOrWhiteSpace($armJsonString)) {
            Write-Warning "   ⚠️ Warning: Conversion yielded empty output for $($file.Name)"
            continue
        }

        $armJson = $armJsonString | ConvertFrom-Json
        if (-not $armJson.resources -or $armJson.resources.Count -eq 0) {
            Write-Warning "   ⚠️ Warning: Missing ARM resources block in $($file.Name)"
            continue
        }

        $resource = $armJson.resources[0]
        $ruleName = if ($resource.properties.displayName) { $resource.properties.displayName } else { $file.BaseName }
        $severity = if ($resource.properties.severity) { $resource.properties.severity } else { "Medium" }
        $tactics = if ($resource.properties.tactics) { ($resource.properties.tactics -join ", ") } else { "N/A" }
        $enabled = if ($null -ne $resource.properties.enabled) { $resource.properties.enabled } else { $true }

        # Derive deterministic rule GUID
        $ruleGuid = $null
        if ($resource.properties.alertRuleTemplateName -and $resource.properties.alertRuleTemplateName -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
            $ruleGuid = $resource.properties.alertRuleTemplateName
        }
        elseif ($resource.name -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') {
            $ruleGuid = $Matches[1]
        }
        else {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($ruleName)
            $md5 = [System.Security.Cryptography.MD5]::Create().ComputeHash($bytes)
            $ruleGuid = ([System.Guid]::new($md5)).ToString()
        }

        $kind = if ($resource.kind) { $resource.kind } else { "Scheduled" }

        if ($DryRun) {
            Write-Host "   🔎 [Dry-Run] Rule valid: '$ruleName' ($severity)" -ForegroundColor Cyan
            $successCount++
            $results += [PSCustomObject]@{
                RuleName = $ruleName
                Category = $category
                Severity = $severity
                Tactics  = $tactics
                Status   = "Validated"
                GUID     = $ruleGuid
            }
            continue
        }

        # Build payload for Sentinel REST API
        $payloadObj = @{
            kind       = $kind
            properties = $resource.properties
        }
        $body = $payloadObj | ConvertTo-Json -Depth 10

        $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules/$ruleGuid`?api-version=2023-02-01-preview"

        $tempFile = [System.IO.Path]::GetTempFileName()
        [System.IO.File]::WriteAllText($tempFile, $body, [System.Text.Encoding]::UTF8)

        $azRes = az rest --method put --uri $uri --headers "Content-Type=application/json" --body "@$tempFile" 2>&1
        $exitCode = $LASTEXITCODE
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

        if ($exitCode -eq 0) {
            Write-Host "   ✅ Deployed: '$ruleName' ($severity)" -ForegroundColor Green
            $successCount++
            $results += [PSCustomObject]@{
                RuleName = $ruleName
                Category = $category
                Severity = $severity
                Tactics  = $tactics
                Status   = "Deployed"
                GUID     = $ruleGuid
            }
        }
        else {
            Write-Warning "   ❌ Deployment failed: $azRes"
            $failCount++
            $results += [PSCustomObject]@{
                RuleName = $ruleName
                Category = $category
                Severity = $severity
                Tactics  = $tactics
                Status   = "Failed"
                GUID     = $ruleGuid
            }
        }
    }
    catch {
        Write-Warning "   ❌ Error parsing $($file.Name): $($_.Exception.Message)"
        $failCount++
        $results += [PSCustomObject]@{
            RuleName = $file.BaseName
            Category = $category
            Severity = "Unknown"
            Tactics  = "N/A"
            Status   = "Error"
            GUID     = "N/A"
        }
    }
}

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host " 📊 DEPLOYMENT SUMMARY & METRICS" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  ✅ Succeeded : $successCount" -ForegroundColor Green
Write-Host "  ❌ Failed    : $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Gray" })
Write-Host "  📦 Total     : $($results.Count)" -ForegroundColor White
Write-Host "=================================================================`n" -ForegroundColor Cyan

$results | Format-Table RuleName, Category, Severity, Status -AutoSize

# Generate GitHub Step Summary (Rich Markdown for Conference Demo)
if ($env:GITHUB_STEP_SUMMARY) {
    $summaryMd = @"
# 🛡️ Microsoft Sentinel Detection-as-Code Deployment Report

### 📋 Environment Details
| Property | Value |
| :--- | :--- |
| **Azure Subscription** | `$SubscriptionId` |
| **Resource Group** | `$ResourceGroupName` |
| **Sentinel Workspace** | `$WorkspaceName` |
| **Authentication** | \`OIDC Federated Identity (Workload Identity Federation)\` |
| **Total Rules Evaluated** | **$($results.Count)** |
| **Status** | $(if ($failCount -eq 0) { '✅ **All Rules Deployed Successfully**' } else { "⚠️ **$failCount Rule(s) Failed**" }) |

---

### 🚀 Deployed Detection Rules

| Status | Rule Name | Category | Severity | MITRE ATT&CK Tactics |
| :---: | :--- | :--- | :---: | :--- |
"@

    foreach ($item in $results) {
        $statusIcon = switch ($item.Status) {
            "Deployed"  { "🟢 Deployed" }
            "Validated" { "🔵 Validated" }
            default     { "🔴 Failed" }
        }

        $sevBadge = switch ($item.Severity) {
            "High"          { "🔴 High" }
            "Medium"        { "🟠 Medium" }
            "Low"           { "🟡 Low" }
            "Informational" { "⚪ Info" }
            default         { $item.Severity }
        }

        $summaryMd += "`n| $statusIcon | **$($item.RuleName)** | `$($item.Category)` | $sevBadge | $($item.Tactics) |"
    }

    $summaryMd += "`n`n> *Report generated automatically by Detection-as-Code CI/CD Pipeline on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')*"

    Set-Content -Path $env:GITHUB_STEP_SUMMARY -Value $summaryMd -Encoding UTF8
    Write-Host "📄 GitHub Step Summary markdown generated." -ForegroundColor Green
}

if ($successCount -eq 0 -and $failCount -gt 0) {
    throw "All detection deployments failed."
}
