param(
    [Parameter(Mandatory=$true)]
    [string]$BackupPath
)

#$BackupPath = "C:\Users\zsadmin\Downloads\Windows Server 2022 Security Baseline\Windows Server-2022-Security-Baseline-FINAL\GPOs"
$ManifestPath = Join-Path $BackupPath "manifest.xml"
$xmlContent = Get-Content -Path $ManifestPath  -Raw
$xml = New-Object System.Xml.XmlDocument
$xml.LoadXml($xmlContent)
$nsMgr = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
$nsMgr.AddNamespace("mfst", "http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest")
$backupInstances = $xml.SelectNodes("//mfst:BackupInst", $nsMgr)

$GPOMap = @{}

foreach ($backup in $backupInstances) {
    $rawId = $backup.SelectSingleNode("mfst:ID", $nsMgr).InnerText
    $id = $rawId -replace "\[|\]", ""
    $rawDisplayName = $backup.SelectSingleNode("mfst:GPODisplayName", $nsMgr).InnerText
    $displayName = $rawDisplayName -replace "\[|\]", ""
    Write-Output $id
    Write-Output $displayName
    $GPOMap[$id] = $displayName
}

$GPOMap.GetEnumerator() | Format-Table -AutoSize

$GPOFolders = Get-ChildItem -Path $BackupPath -Directory | Where-Object { $_.Name -match "^\{.*\}$" }

foreach ($GPOFolder in $GPOFolders) {
    $BackupId = $GPOFolder.Name
    $TargetName = $GPOMap[$BackupId]
    if (-not $TargetName) {
        Write-Warning "No friendly name found for $BackupId. Skipping."
        continue
    }
    Write-Host "Importing GPO: $TargetName ($BackupId)..."
    Import-GPO -BackupId $BackupId -Path $BackupPath -TargetName $TargetName -CreateIfNeeded
}
