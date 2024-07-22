$subdomain = "webmail"
$domain = "epcounty.com"
$servername = "op-p-hydra"

Get-ClientAccessServer -Identity $servername | Set-ClientAccessServer -AutoDiscoverServiceInternalUri "https://autodiscover.$domain/Autodiscover/Autodiscover.xml"
Get-EcpVirtualDirectory -Server $servername | Set-EcpVirtualDirectory -ExternalUrl "https://$subdomain.$domain/ecp" -InternalUrl "https://$subdomain.$domain/ecp"
Get-WebServicesVirtualDirectory -Server $servername | Set-WebServicesVirtualDirectory -ExternalUrl "https://$subdomain.$domain/EWS/Exchange.asmx" -InternalUrl "https://$subdomain.$domain/EWS/Exchange.asmx"
Get-MapiVirtualDirectory -Server $servername | Set-MapiVirtualDirectory -ExternalUrl "https://$subdomain.$domain/mapi" -InternalUrl "https://$subdomain.$domain/mapi"
Get-ActiveSyncVirtualDirectory -Server $servername | Set-ActiveSyncVirtualDirectory -ExternalUrl "https://$subdomain.$domain/Microsoft-Server-ActiveSync" -InternalUrl "https://$subdomain.$domain/Microsoft-Server-ActiveSync"
Get-OabVirtualDirectory -Server $servername | Set-OabVirtualDirectory -ExternalUrl "https://$subdomain.$domain/OAB" -InternalUrl "https://$subdomain.$domain/OAB"
Get-OwaVirtualDirectory -Server $servername | Set-OwaVirtualDirectory -ExternalUrl "https://$subdomain.$domain/owa" -InternalUrl "https://$subdomain.$domain/owa"
Get-PowerShellVirtualDirectory -Server $servername | Set-PowerShellVirtualDirectory -ExternalUrl "https://$subdomain.$domain/powershell" -InternalUrl "https://$subdomain.$domain/powershell"
Get-OutlookAnywhere -Server $servername | Set-OutlookAnywhere -ExternalHostname "$subdomain.$domain" -InternalHostname "$subdomain.$domain" -ExternalClientsRequireSsl $true -InternalClientsRequireSsl $true -DefaultAuthenticationMethod NTLM
