[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId = $env:AZURE_SUBSCRIPTION_ID,

    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName = $env:AZURE_RESOURCE_GROUP,

    [Parameter(Mandatory = $false)]
    [string]$WorkspaceName = $env:AZURE_WORKSPACE_NAME,

    [Parameter(Mandatory = $false)]
    [string]$DetectionsPath = "$PSScriptRoot\..\MicrosoftSentinel\Detections"
)

$ErrorActionPreference = 'Continue'

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "🚀 Microsoft Sentinel Detection-as-Code Deployment Engine" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Subscription ID : $SubscriptionId"
Write-Host "Resource Group  : $ResourceGroupName"
Write-Host "Workspace Name  : $WorkspaceName"
Write-Host "Detections Path : $DetectionsPath"
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Konvertovanje svih YAML pravila u JSON ARM strukture u memoriji
$yamlFiles = Get-ChildItem -Path $DetectionsPath -Recurse -Include *.yaml, *.yml | Where-Object { $_.Name -notmatch "template\.yaml" }
Write-Host "🔍 Pronađeno $($yamlFiles.Count) YAML detekcionih pravila za obradu..." -ForegroundColor Yellow

$successCount = 0
$failCount = 0
$summary = @()

foreach ($file in $yamlFiles) {
    Write-Host "`n➡️  Obrada pravila: $($file.Name)" -ForegroundColor White
    try {
        # Konvertuj YAML u ARM JSON string preko SentinelARConverter-a
        $armJsonString = Convert-SentinelARYamlToArm -Filename $file.FullName
        if ([string]::IsNullOrWhiteSpace($armJsonString)) {
            Write-Warning "  ⚠️ Konverzija nije vratila JSON za $($file.Name)"
            continue
        }

        $armJson = $armJsonString | ConvertFrom-Json
        if (-not $armJson.resources -or $armJson.resources.Count -eq 0) {
            Write-Warning "  ⚠️ Nema 'resources' u konvertovanom JSON-u za $($file.Name)"
            continue
        }

        $resource = $armJson.resources[0]
        $ruleName = if ($resource.properties.displayName) { $resource.properties.displayName } else { $file.BaseName }
        
        # Izvuci GUID pravila iz imena ili kreiraj deterministic GUID iz imena
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
        $properties = $resource.properties

        # Pripremi payload za REST API
        $payloadObj = @{
            kind = $kind
            properties = $properties
        }
        $body = $payloadObj | ConvertTo-Json -Depth 10

        $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules/$ruleGuid`?api-version=2023-02-01-preview"

        $tempFile = [System.IO.Path]::GetTempFileName()
        [System.IO.File]::WriteAllText($tempFile, $body, [System.Text.Encoding]::UTF8)

        $azRes = az rest --method put --uri $uri --headers "Content-Type=application/json" --body "@$tempFile" 2>&1
        $exitCode = $LASTEXITCODE
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

        if ($exitCode -eq 0) {
            Write-Host "  ✅ Uspešno postavljeno: $ruleName" -ForegroundColor Green
            $successCount++
            $summary += [PSCustomObject]@{
                Rule = $ruleName
                Status = "Deployed"
                File = $file.Name
            }
        } else {
            Write-Warning "  ⚠️ Azure REST greška za $($file.Name): $azRes"
            $failCount++
            $summary += [PSCustomObject]@{
                Rule = $ruleName
                Status = "Failed: $azRes"
                File = $file.Name
            }
        }
    }
    catch {
        Write-Warning "  ❌ Izuzetak: $($_.Exception.Message)"
        $failCount++
        $summary += [PSCustomObject]@{
            Rule = $file.Name
            Status = "Exception: $($_.Exception.Message)"
            File = $file.Name
        }
    }
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "📊 Rezultati Sentinel Deployment-a:" -ForegroundColor Cyan
Write-Host "  ✅ Uspešno: $successCount" -ForegroundColor Green
Write-Host "  ⚠️ Neuspešno: $failCount" -ForegroundColor Red
Write-Host "==========================================================" -ForegroundColor Cyan

$summary | Format-Table -AutoSize

if ($successCount -eq 0 -and $failCount -gt 0) {
    throw "Nijedno pravilo nije uspešno deployovano!"
}

Write-Host "`n🎉 Deployment uspešno završen!" -ForegroundColor Green
