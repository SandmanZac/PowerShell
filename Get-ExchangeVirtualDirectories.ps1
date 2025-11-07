$LogPath = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders').'{374DE290-123F-4565-9164-39C4925E467B}'
Start-Transcript -Path $LogPath -NoClobber
Get-MapiVirtualDirectory | FL Server,external*,internal*,iis*
Get-OwaVirtualDirectory | FL ServerName,externalurl,internalurl,*auth*,LogonFormat
Get-ActiveSyncVirtualDirectory | FL Server,external*,internal*,*authenabled*,*certauth,*ssl*
Get-WebServicesVirtualDirectory | FL Server,external*,internal*,*Authentication
Get-OABVirtualDirectory | FL Server, external*,internal*,*Authentication,*SSL
Get-EcpVirtualDirectory | FL Server, external*,internal*,*Authentication 
Get-PowerShellVirtualDirectory | FL Server, external*,internal*,*Authentication,*SSL
Get-AutodiscoverVirtualDirectory | FL Server,*Auth*
Get-ClientAccessService | FL Name,*Enabled,*Uri,*Site*
Stop-Transcript
