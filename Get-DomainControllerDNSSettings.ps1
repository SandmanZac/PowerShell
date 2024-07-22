Import-Module ActiveDirectory
$DomainControllers = Get-ADDomainController -Filter *
 
$Results = @{}
$IPs = @()

foreach ($DomainController in $DomainControllers)
{
    write-host "Discovering DNS Settings for"$DomainController
    $ReturnedObj = @{}
    $ReturnedObj['ComputerName'] = "Unknown"
    $ReturnedObj['IPAddress'] = "Unknown"
    $ReturnedObj['DNSServers'] = "Unknown"
    $IPAddress = ""
    $DNSServers = ""
    $DNSServersString  = ""
    if(Test-Connection -ComputerName $DomainController.Name -Count 1 -ea 0)
    {	
        $Networks = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $DomainController.Name | ? {$_.IPEnabled}
        foreach ($Network in $Networks)
        {
            $IPAddress  = $Network.IpAddress[0]
	    $IPs += $IPAddress
            $DNSServers  = $Network.DNSServerSearchOrder
            if ($DNSServers)
            {
                foreach ($DNSServer in $DNSServers) {
                    $DNSServersString += $DNSServer + " "
                }
            }
        }
    }
    
    if ($DomainController.Name) {
        $ReturnedObj['ComputerName'] = $DomainController.Name.ToUpper()
        $ReturnedObj['IPAddress'] = $IPAddress
        $ReturnedObj['DNSServers'] = $DNSServersString  
        $Results[$IPAddress] = $ReturnedObj
    }
}

foreach ($result in $results.keys) {
  $Hostname = $results[$result]['ComputerName']
  $IP = $results[$result]['IPAddress']
  $DNS = $results[$result]['DNSServers']
  $hasSelfListed = $False
  $hasValidSecondary = $False
  $badDNSServers = @()
  foreach ($DNSServer in $DNS.Split()) {
     if (($DNSServer -eq $IP -or $DNSServer -eq "127.0.0.1") -and -not $hasSelfListed) {
       $hasSelfListed = $True
     } elseif ($IPs -contains $DNSServer -and -not $hasValidSecondary) {
       $hasValidSecondary = $True
     } else {
       $badDNSServers += $DNSServer
     }
  }
  if (-not $hasValidSecondary -or -not $hasSelfListed) {
      write-host ""
      write-host "------------Invalid Settings detected for $Hostname------------"
      write-host $Hostname"'s IP Address: "$IP
      if (-not $hasValidSecondary) {
        write-host "Invalid Secondary Found: "$badDnsServers" This IP is not the IP of any Domain Controller in the Domain"
      }
      if (-not $hasSelfListed) {
        write-host "Does not have it's own IP in DNS Search Order: "$DNS
      }
      write-host ""
  }  
}