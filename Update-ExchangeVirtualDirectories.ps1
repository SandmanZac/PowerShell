$Server = "ex01"
$InternalURL = "mail.sanders-home.local"
$ExternalURL = "mail.sanders-home.com"

Get-MapiVirtualDirectory -Server $Server | Set-MapiVirtualDirectory -InternalUrl https://$InternalURL/mapi -ExternalUrl https://$ExternalURL/mapi
Get-OwaVirtualDirectory -Server $Server | Set-OwaVirtualDirectory -InternalUrl https://$InternalURL/owa -ExternalUrl https://$ExternalURL/owa
Get-ActiveSyncVirtualDirectory -Server $Server | Set-ActiveSyncVirtualDirectory -InternalUrl https://$InternalURL/Microsoft-Server-ActiveSync -ExternalUrl https://$ExternalURL/Microsoft-Server-ActiveSync
Get-EcpVirtualDirectory -Server $Server | Set-EcpVirtualDirectory -InternalUrl https://$InternalURL/ecp -ExternalUrl https://$ExternalURL/ecp
Get-WebServicesVirtualDirectory -Server $Server | Set-WebServicesVirtualDirectory -InternalUrl https://$InternalURL/EWS/Exchange.asmx -ExternalUrl https://$ExternalURL/EWS/Exchange.asmx
Get-OabVirtualDirectory -Server $Server | Set-OabVirtualDirectory -InternalUrl https://$InternalURL/OAB -ExternalUrl https://$ExternalURL/OAB
Get-PowerShellVirtualDirectory -Server $Server | Set-PowerShellVirtualDirectory -InternalUrl https://$InternalURL/powershell -ExternalUrl https://$ExternalURL/powershell
Get-ClientAccessService -Identity $i | Set-ClientAccessService -AutoDiscoverServiceInternalUri https://$InternalURL/Autodiscover/Autodiscover.xml
