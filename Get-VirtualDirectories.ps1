$Server = "ex01"

Write-Host "----------------------------------------"
Write-Host " Querying $Server"
Write-Host "----------------------------------------`r`n"
Write-Host "`r`n"

$AutoSCP = Get-ClientAccessServer $Server | Select AutoDiscoverServiceInternalUri
$AutoVD = Get-AutodiscoverVirtualDirectory -Server $Server | Select WindowsAuthentication,WSSecurityAuthentication,OAuthAuthentication
$AutoCAS = Get-ClientAccessServer -Identity $Server | Select AutoDiscoverServiceInternalUri, AutoDiscoverSiteScope
Write-Host "Autodiscover"
Write-Host " - InternalSCP: $($AutoSCP.AutoDiscoverServiceInternalUri)"
Write-Host " - AutoDiscoverServiceInternalUri: $($AutoCAS.AutoDiscoverServiceInternalUri)"
Write-Host " - AutoDiscoverSiteScope: $($AutoCAS.AutoDiscoverSiteScope)"
Write-Host " - WindowsAuthentication: $($AutoVD.WindowsAuthentication)"
Write-Host " - WSSecurityAuthentication: $($AutoVD.WSSecurityAuthentication)"
Write-Host " - OAuthAuthentication: $($AutoVD.OAuthAuthentication)"
Write-Host "`r`n"

$ECP = Get-ECPVirtualDirectory -Server $Server -AdPropertiesOnly | Select InternalURL,ExternalURL,InternalAuthenticationMethods,ExternalAuthenticationMethods
Write-Host "Exchange Control Panel"
Write-Host " - InternalURL: $($ECP.InternalURL)"
Write-Host " - ExternalURL: $($ECP.ExternalURL)"
Write-Host " - InternalAuthenticationMethods: $($ECP.InternalAuthenticationMethods)"
Write-Host " - ExternalAuthenticationMethods: $($ECP.ExternalAuthenticationMethods)"
Write-Host "`r`n"

$EWS = Get-WebServicesVirtualDirectory -Server $Server -AdPropertiesOnly | Select InternalURL,ExternalURL,InternalAuthenticationMethods,ExternalAuthenticationMethods
Write-Host "Exchange Web Services"
Write-Host " - InternalURL: $($EWS.InternalURL)"
Write-Host " - ExternalURL: $($EWS.ExternalURL)"
Write-Host " - InternalAuthenticationMethods: $($EWS.InternalAuthenticationMethods)"
Write-Host " - ExternalAuthenticationMethods: $($EWS.ExternalAuthenticationMethods)"
Write-Host "`r`n"

$MAPI = Get-MAPIVirtualDirectory -Server $Server -AdPropertiesOnly | Select InternalURL,ExternalURL,IISAuthenticationMethods
Write-Host "MAPI"
Write-Host " - InternalURL: $($MAPI.InternalURL)"
Write-Host " - ExternalURL: $($MAPI.ExternalURL)"
Write-Host " - IISAuthenticationMethods: $($MAPI.IISAuthenticationMethods)"
Write-Host "`r`n"

$EAS = Get-ActiveSyncVirtualDirectory -Server $Server -AdPropertiesOnly | Select InternalURL,ExternalURL,InternalAuthenticationMethods,ExternalAuthenticationMethods
Write-Host "ActiveSync"
Write-Host " - InternalURL: $($EAS.InternalURL)"
Write-Host " - ExternalURL: $($EAS.ExternalURL)"
Write-Host " - InternalAuthenticationMethods: $($EAS.InternalAuthenticationMethods)"
Write-Host " - ExternalAuthenticationMethods: $($EAS.ExternalAuthenticationMethods)"
Write-Host "`r`n"

$OAB = Get-OABVirtualDirectory -Server $Server -AdPropertiesOnly | Select InternalURL,ExternalURL,WindowsAuthentication,OAuthAuthentication
Write-Host "Offline Address Book"
Write-Host " - InternalURL: $($OAB.InternalURL)"
Write-Host " - ExternalURL: $($OAB.ExternalURL)"
Write-Host " - WindowsAuthentication: $($OAB.WindowsAuthentication)"
Write-Host " - OAuthAuthentication: $($OAB.OAuthAuthentication)"
Write-Host "`r`n"

$OWA = Get-OWAVirtualDirectory -Server $Server -AdPropertiesOnly | Select InternalURL,ExternalURL,InternalAuthenticationMethods,ExternalAuthenticationMethods
Write-Host "Outlook Web App"
Write-Host " - InternalURL: $($OWA.InternalURL)"
Write-Host " - ExternalURL: $($OWA.ExternalURL)"
Write-Host " - InternalAuthenticationMethods: $($OWA.InternalAuthenticationMethods)"
Write-Host " - ExternalAuthenticationMethods: $($OWA.ExternalAuthenticationMethods)"
Write-Host "`r`n"

$PS = Get-PowerShellVirtualDirectory -Server $Server -AdPropertiesOnly | Select InternalURL,ExternalURL
Write-Host "PowerShell"
Write-Host " - InternalURL: $($PS.InternalURL)"
Write-Host " - ExternalURL: $($PS.ExternalURL)"
Write-Host "`r`n"

$OA = Get-OutlookAnywhere -Server $Server -AdPropertiesOnly | Select InternalHostName,ExternalHostName,IISAuthenticationMethods,SSLOffloading,InternalClientAuthenticationMethod,ExternalClientAuthenticationMethod
Write-Host "Outlook Anywhere"
Write-Host " - InternalHostName: $($OA.InternalHostName)"
Write-Host " - ExternalHostName: $($OA.ExternalHostName)"	
Write-Host " - IISAuthenticationMethods: $($OA.IISAuthenticationMethods)"
Write-Host " - SSLOffloading: $($OA.SSLOffloading)"
Write-Host " - InternalClientAuthenticationMethod: $($OA.InternalClientAuthenticationMethod)"
Write-Host " - ExternalClientAuthenticationMethod: $($OA.ExternalClientAuthenticationMethod)"	
Write-Host "`r`n"

