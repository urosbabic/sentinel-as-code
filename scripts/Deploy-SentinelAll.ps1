[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId = $env:AZURE_SUBSCRIPTION_ID,

    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName = $env:AZURE_RESOURCE_GROUP,

    [Parameter(Mandatory = $false)]
    [string]$WorkspaceName = $env:AZURE_WORKSPACE_NAME,

    [Parameter(Mandatory = $false)]
    [string]$RootPath = "$PSScriptRoot\..\MicrosoftSentinel"
)

$ErrorActionPreference = 'Continue'

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "🚀 Microsoft Sentinel Detection-as-Code Direct Deployment Engine" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Subscription ID : $SubscriptionId"
Write-Host "Resource Group  : $ResourceGroupName"
Write-Host "Workspace Name  : $WorkspaceName"
Write-Host "Content Path    : $RootPath"
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Postavljanje aktivne pretplate
az account set --subscription $SubscriptionId

# 2. Pronalaženje svih ARM JSON fajlova detekcija i pravila
$detectionsPath = Join-Path $RootPath "Detections"
$ruleFiles = Get-ChildItem -Path $detectionsPath -Filter "*.json" -Recurse -ErrorAction SilentlyContinue

Write-Host "`n🔍 Pronađeno $($ruleFiles.Count) analitičkih pravila za deployment..." -ForegroundColor Yellow

$successCount = 0
$failCount = 0
$summary = @()

foreach ($file in $ruleFiles) {
    Write-Host "`n➡️  Obrada pravila: $($file.Name)" -ForegroundColor White
    try {
        $raw = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
        if (-not $raw.resources -or $raw.resources.Count -eq 0) {
            Write-Warning "  ⚠️ Fajl $($file.Name) nema 'resources' definiciju, preskačem."
            continue
        }

        $resource = $raw.resources[0]
        $ruleName = if ($resource.properties.displayName) { $resource.properties.displayName } else { $file.BaseName }
        $ruleGuid = $resource.name

        # Ako nema GUID ili je generičan izraz, kreiramo konzistentan GUID na osnovu imena
        if ([string]::IsNullOrWhiteSpace($ruleGuid) -or $ruleGuid -like "*[*") {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($ruleName)
            $md5 = [System.Security.Cryptography.MD5]::Create().ComputeHash($bytes)
            $ruleGuid = ([System.Guid]::new($md5)).ToString()
        }

        $kind = if ($resource.kind) { $resource.kind } else { "Scheduled" }
        $properties = $resource.properties

        # Priprema payload-a za Sentinel REST API
        $payloadObj = @{
            kind = $kind
            properties = $properties
        }
        $body = $payloadObj | ConvertTo-Json -Depth 10

        $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules/$ruleGuid`?api-version=2023-02-01-preview"

        $tempFile = [System.IO.Path]::GetTempFileName()
        [System.IO.File]::WriteAllText($tempFile, $body, [System.Text.Encoding]::UTF8)

        $azRes = az rest --method put --uri $uri --headers "Content-Type=application/json" --body "@$tempFile" 2>&1
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✅ Uspešno postavljeno: $ruleName" -ForegroundColor Green
            $successCount++
            $summary += [PSCustomObject]@{
                Rule = $ruleName
                Status = "Deployed"
                File = $file.Name
            }
        } else {
            Write-Warning "  ⚠️ Greška pri postavljanju ($($file.Name)): $azRes"
            $failCount++
            $summary += [PSCustomObject]@{
                Rule = $ruleName
                Status = "Failed"
                File = $file.Name
            }
        }
    }
    catch {
        Write-Warning "  ❌ Izuzetak pri obradi $($file.Name): $($_.Exception.Message)"
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
    throw "Svi pokušaji deploymenta su pali!"
}

Write-Host "`n🎉 Deployment završen!" -ForegroundColor Green
