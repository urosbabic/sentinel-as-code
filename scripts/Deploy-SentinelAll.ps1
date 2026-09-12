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
Write-Host " Azure Subscription  : $SubscriptionId" -ForegroundColor Gray
Write-Host " Resource Group      : $ResourceGroupName" -ForegroundColor Gray
Write-Host " Sentinel Workspace  : $WorkspaceName" -ForegroundColor Gray
Write-Host " Detections Folder   : $DetectionsPath" -ForegroundColor Gray
Write-Host " Execution Mode      : $(if ($DryRun) { 'Dry Run (Validation Only)' } else { 'Live ARM Deployment' })" -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Cyan

# Set active subscription
az account set --subscription $SubscriptionId 2>&1 | Out-Null

$yamlFiles = Get-ChildItem -Path $DetectionsPath -Recurse -Include *.yaml, *.yml | Where-Object { $_.Name -notmatch "template\.yaml" }
Write-Host "`n🔍 Discovered $($yamlFiles.Count) detection rule definition(s) across categories.`n" -ForegroundColor Yellow

$results = @()
$successCount = 0
$failCount = 0

foreach ($file in $yamlFiles) {
    $category = $file.Directory.Name
    Write-Host "⚡ Processing [$category] > $($file.Name)" -ForegroundColor White

    $tempArmFile = [System.IO.Path]::GetTempFileName() + ".json"

    try {
        # 1. Convert YAML to ARM Template
        Convert-SentinelARYamlToArm -Filename $file.FullName -OutFile $tempArmFile -ErrorAction Stop
        
        if (-not (Test-Path $tempArmFile)) {
            Write-Warning "   ⚠️ Conversion did not create ARM template for $($file.Name)"
            $failCount++
            $results += [PSCustomObject]@{
                RuleName = $file.BaseName
                Category = $category
                Severity = "Unknown"
                Tactics  = "N/A"
                Status   = "Conversion Failed"
            }
            continue
        }

        # 2. Extract Metadata from converted template
        $armContent = Get-Content -Path $tempArmFile -Raw | ConvertFrom-Json
        $resource = $armContent.resources[0]
        $ruleName = if ($resource.properties.displayName) { $resource.properties.displayName } else { $file.BaseName }
        $severity = if ($resource.properties.severity) { $resource.properties.severity } else { "Medium" }
        $tactics = if ($resource.properties.tactics) { ($resource.properties.tactics -join ", ") } else { "N/A" }
        
        # Clean ARM template to ensure smooth deployment (remove null customDetails / deprecated status)
        if ($resource.properties.PSObject.Properties['status']) {
            $resource.properties.PSObject.Properties.Remove('status')
        }
        if ($resource.properties.PSObject.Properties['customDetails'] -and $null -eq $resource.properties.customDetails) {
            $resource.properties.PSObject.Properties.Remove('customDetails')
        }
        
        # Re-save cleaned ARM template
        $armContent | ConvertTo-Json -Depth 15 | Set-Content -Path $tempArmFile -Encoding UTF8

        # 3. Dry-Run Mode
        if ($DryRun) {
            Write-Host "   🔎 [Dry-Run] Rule valid: '$ruleName' ($severity)" -ForegroundColor Cyan
            $successCount++
            $results += [PSCustomObject]@{
                RuleName = $ruleName
                Category = $category
                Severity = $severity
                Tactics  = $tactics
                Status   = "Validated"
            }
            continue
        }

        # 4. Deploy ARM Template directly to Sentinel Workspace
        $deployName = ("sentinel-" + [System.Guid]::NewGuid().ToString().Substring(0, 8))
        $azOut = az deployment group create `
            --resource-group $ResourceGroupName `
            --template-file $tempArmFile `
            --parameters workspace=$WorkspaceName `
            --name $deployName `
            --output json 2>&1

        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0) {
            Write-Host "   ✅ Deployed: '$ruleName' ($severity)" -ForegroundColor Green
            $successCount++
            $results += [PSCustomObject]@{
                RuleName = $ruleName
                Category = $category
                Severity = $severity
                Tactics  = $tactics
                Status   = "Deployed"
            }
        }
        else {
            $errorMsg = ($azOut | Out-String).Trim()
            # Extract concise error message from Azure ARM response if possible
            if ($errorMsg -match '"message":\s*"([^"]+)"') {
                $errorMsg = $Matches[1]
            }
            Write-Warning "   ❌ Deployment failed: $errorMsg"
            $failCount++
            $results += [PSCustomObject]@{
                RuleName = $ruleName
                Category = $category
                Severity = $severity
                Tactics  = $tactics
                Status   = "Failed ($errorMsg)"
            }
        }
    }
    catch {
        Write-Warning "   ❌ Exception processing $($file.Name): $($_.Exception.Message)"
        $failCount++
        $results += [PSCustomObject]@{
            RuleName = $file.BaseName
            Category = $category
            Severity = "Unknown"
            Tactics  = "N/A"
            Status   = "Error: $($_.Exception.Message)"
        }
    }
    finally {
        Remove-Item $tempArmFile -Force -ErrorAction SilentlyContinue
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
| **Status** | $(if ($failCount -eq 0) { '✅ **All Rules Deployed Successfully**' } else { "⚠️ **$successCount Succeeded / $failCount Failed**" }) |

---

### 🚀 Detection Rules Deployment Details

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
