$server = op-p-hydra

#write-host "Get-ClientAccessService -Identity $server | select AutoDiscoverServiceInternalUri"
$cas=Get-ClientAccessService -Identity $server | select AutoDiscoverServiceInternalUri
#write-host "AutoDiscoverServiceInternalUri: "$cas.AutoDiscoverServiceInternalUri
#write-host "To Revert:"
write-host "Get-ClientAccessService -Server $server | Set-ClientAccessService -AutoDiscoverServiceInternalUri "$cas.AutoDiscoverServiceInternalUri
#write-host ""
#write-host "Get-EcpVirtualDirectory -Server $server | select ExternalUrl,InternalUrl"
$ecp=Get-EcpVirtualDirectory -Server $server | select ExternalUrl,InternalUrl
#write-host "InternalURL: " $ecp.InternalUrl
#write-host "ExternalURL: " $ecp.ExternalUrl
#write-host "To Revert:"
write-host "Get-EcpVirtualDirectory -Server $server | Set-EcpVirtualDirectory -InternalURL "$ecp.InternalUrl" -ExternalURL "$ecp.ExternalUrl
#write-host ""
#write-host "Get-WebServicesVirtualDirectory -Server $server | select ExternalUrl,InternalUrl"
$wsv=Get-WebServicesVirtualDirectory -Server $server | select ExternalUrl,InternalUrl
#write-host "InternalURL: " $wsv.InternalUrl
#write-host "ExternalURL: " $wsv.ExternalUrl
#write-host "To Revert:"
write-host "Get-WebServicesVirtualDirectory -Server $server | Set-WebServicesVirtualDirectory -InternalURL "$wsv.InternalUrl" -ExternalURL "$wsv.ExternalUrl
#write-host ""
#write-host "Get-MapiVirtualDirectory -Server $server | select ExternalUrl,InternalUrl"
$mapi=Get-MapiVirtualDirectory -Server $server | select ExternalUrl,InternalUrl
#write-host "InternalURL: " $mapi.InternalUrl
#write-host "ExternalURL: " $mapi.ExternalUrl
#write-host "To Revert:"
write-host "Get-MapiVirtualDirectory -Server $server | Set-MapiVirtualDirectory -InternalURL "$mapi.InternalUrl" -ExternalURL "$mapi.ExternalUrl
#write-host ""
#write-host "Get-ActiveSyncVirtualDirectory -Server $server | select ExternalUrl,InternalUrl"
$asv=Get-ActiveSyncVirtualDirectory -Server $server | select ExternalUrl,InternalUrl
#write-host "InternalURL: " $asv.InternalUrl
#write-host "ExternalURL: " $asv.ExternalUrl
#write-host "To Revert:"
write-host "Get-ActiveSyncVirtualDirectory -Server $server | Set-ActiveSyncVirtualDirectory -InternalURL "$asv.InternalUrl" -ExternalURL "$asv.ExternalUrl
#write-host ""
#write-host "Get-OabVirtualDirectory -Server $server | select ExternalUrl,InternalUrl"
$oab=Get-OabVirtualDirectory -Server $server | select ExternalUrl,InternalUrl
#write-host "InternalURL: " $oab.InternalUrl
#write-host "ExternalURL: " $oab.ExternalUrl
#write-host "To Revert:"
write-host "Get-OabVirtualDirectory -Server $server | Set-OabVirtualDirectory -InternalURL "$oab.InternalUrl" -ExternalURL "$oab.ExternalUrl
#write-host ""
#write-host "Get-OwaVirtualDirectory -Server $server | select ExternalUrl,InternalUrl"
$owa=Get-OwaVirtualDirectory -Server $server | select ExternalUrl,InternalUrl
#write-host "InternalURL: " $owa.InternalUrl
#write-host "ExternalURL: " $owa.ExternalUrl
#write-host "To Revert:"
write-host "Get-OwaVirtualDirectory -Server $server | Set-OwaVirtualDirectory -InternalURL "$owa.InternalUrl" -ExternalURL "$owa.ExternalUrl
#write-host ""
#write-host "Get-PowerShellVirtualDirectory -Server $server | select Identity,ExternalUrl,InternalUrl"
$psv=Get-PowerShellVirtualDirectory -Server $server | select Identity,ExternalUrl,InternalUrl
#write-host "InternalURL: " $psv.InternalUrl
#write-host "ExternalURL: " $psv.ExternalUrl
#write-host "To Revert:"
write-host "Get-PowerShellVirtualDirectory -Server $server | Set-PowerShellVirtualDirectory -InternalURL "$psv.InternalUrl" -ExternalURL "$psv.ExternalUrl
#write-host ""
#write-host "Get-OutlookAnywhere -Server $server | select ExternalHostname,InternalHostname,ExternalClientsRequireSsl,InternalClientsRequireSsl,DefaultAuthenticationMethod"
$oav=Get-OutlookAnywhere -Server $server | select ExternalHostname,InternalHostname,ExternalClientsRequireSsl,InternalClientsRequireSsl,DefaultAuthenticationMethod
#write-host "InternalHostname: " $oav.InternalHostname
#write-host "InternalClientsRequireSsl: " $oav.InternalClientsRequireSsl
#write-host "ExternalHostname: " $oav.ExternalHostname
#write-host "ExternalClientsRequireSsl: " $oav.ExternalClientsRequireSsl
#write-host "DefaultAuthenticationMethod: " $oav.DefaultAuthenticationMethod
#write-host "To Revert:"
write-host "Get-OutlookAnywhere -Server $server | Set-OutlookAnywhereDirectory -InternalURL "$oav.InternalHostname" -ExternalURL "$oav.ExternalHostname" -InternalClientsRequireSsl "$oav.InternalClientsRequireSsl" -ExternalClientsRequireSsl "$oav.ExternalClientsRequireSsl" -DefaultAuthenticationMethod "$oav.DefaultAuthenticationMethod
