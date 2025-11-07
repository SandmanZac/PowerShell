$Server = "ex01"

if (Test-Path $env:ExchangeInstallPath\bin\RemoteExchange.ps1)
{
    . $env:ExchangeInstallPath\bin\RemoteExchange.ps1
    Connect-ExchangeServer -auto -AllowClobber
}
else
{
    Write-Warning "Exchange Server management tools are not installed on this computer."
    EXIT
}
if ((Get-ExchangeServer $Server -ErrorAction SilentlyContinue).IsClientAccessServer)
{
	Write-Host "----------------------------------------"
	Write-Host " Querying $Server"
	Write-Host "----------------------------------------`r`n"
	Write-Host "`r`n"

	$AutoD = Get-ClientAccessServer $Server | Select AutoDiscoverServiceInternalUri
	Write-Host "Autodiscover"
	Write-Host " - Internal SCP: $($AutoD.AutoDiscoverServiceInternalUri)"
	Write-Host "`r`n"

	$ECP = Get-ECPVirtualDirectory -Server $Server -AdPropertiesOnly | Select InternalURL,ExternalURL
	Write-Host "Exchange Control Panel"
	Write-Host " - Internal: $($ECP.InternalURL)"
	Write-Host " - External: $($ECP.ExternalURL)"
	Write-Host "`r`n"

	$EWS = Get-WebServicesVirtualDirectory -Server $Server -AdPropertiesOnly | Select InternalURL,ExternalURL
	Write-Host "Exchange Web Services"
	Write-Host " - Internal: $($EWS.InternalURL)"
	Write-Host " - External: $($EWS.ExternalURL)"
	Write-Host "`r`n"
	
	$MAPI = Get-MAPIVirtualDirectory -Server $Server -AdPropertiesOnly | Select InternalURL,ExternalURL
	Write-Host "MAPI"
	Write-Host " - Internal: $($MAPI.InternalURL)"
	Write-Host " - External: $($MAPI.ExternalURL)"
	Write-Host "`r`n"

	$EAS = Get-ActiveSyncVirtualDirectory -Server $Server -AdPropertiesOnly | Select InternalURL,ExternalURL
	Write-Host "ActiveSync"
	Write-Host " - Internal: $($EAS.InternalURL)"
	Write-Host " - External: $($EAS.ExternalURL)"
	Write-Host "`r`n"

	$OAB = Get-OABVirtualDirectory -Server $Server -AdPropertiesOnly | Select InternalURL,ExternalURL
	Write-Host "Offline Address Book"
	Write-Host " - Internal: $($OAB.InternalURL)"
	Write-Host " - External: $($OAB.ExternalURL)"
	Write-Host "`r`n"

	$OWA = Get-OWAVirtualDirectory -Server $Server -AdPropertiesOnly | Select InternalURL,ExternalURL
	Write-Host "Outlook Web App"
	Write-Host " - Internal: $($OWA.InternalURL)"
	Write-Host " - External: $($OWA.ExternalURL)"
	Write-Host "`r`n"

	$PS = Get-PowerShellVirtualDirectory -Server $Server -AdPropertiesOnly | Select InternalURL,ExternalURL
	Write-Host "PowerShell"
	Write-Host " - Internal: $($PS.InternalURL)"
	Write-Host " - External: $($PS.ExternalURL)"
	Write-Host "`r`n"

	$OA = Get-OutlookAnywhere -Server $Server -AdPropertiesOnly | Select InternalHostName,ExternalHostName
	Write-Host "Outlook Anywhere"
	Write-Host " - Internal: $($OA.InternalHostName)"
	Write-Host " - External: $($OA.ExternalHostName)"
	Write-Host "`r`n"
}
else
{
	Write-Host -ForegroundColor Yellow "$Server is not a Client Access server."
}
Write-Host "Finished querying all servers specified."
