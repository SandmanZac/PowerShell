Import-Module ActiveDirectory
 
$localpath = Get-Location;
$CSVFileName = $localpath.Path + "\DNS-ActiveSettings-EPCO.csv";
 
#$ComputerName = Get-ADComputer -SearchBase "OU=ITD,OU=County Client Devices,DC=epcountytx,DC=gov" -Filter {OperatingSystem -Like "Windows*"} -Property "Name";
$ComputerName = Get-ADComputer -Filter {OperatingSystem -Like "Windows*"} -Property "Name";
 
$Results = @()
 
foreach ($Computer in $ComputerName)
{
    if(Test-Connection -ComputerName $Computer.Name -Count 1 -ea 0)
    {
	write-host "Pulling settings for $Computer"
        $Networks = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $Computer.Name | ? {$_.IPEnabled};
        foreach ($Network in $Networks)
        {
            $IPAddress  = $Network.IpAddress[0];
            $SubnetMask  = $Network.IPSubnet[0];
            $DefaultGateway = $Network.DefaultIPGateway;
            $DNSServers  = $Network.DNSServerSearchOrder;
            $IsDHCPEnabled = $false;
            If($network.DHCPEnabled)
            {
                $IsDHCPEnabled = $true;
            }
            $MACAddress  = $Network.MACAddress;
 
            if ($DNSServers)
            {
                $StringDNSServers = [string]::join("; ",$DNSServers);
            }
            else
            {
                $StringDNSServers = " ";
            }
 
            if($DefaultGateway)
            {
                $StringDefaultGateway = [string]::join("; ",$DefaultGateway);
            }
            else
            {
                $StringDefaultGateway = " ";
            }
 
            $ReturnedObj = New-Object -Type PSObject;
            $ReturnedObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer.Name.ToUpper();
            $ReturnedObj | Add-Member -MemberType NoteProperty -Name IPAddress -Value $IPAddress;
            $ReturnedObj | Add-Member -MemberType NoteProperty -Name SubnetMask -Value $SubnetMask;
            $ReturnedObj | Add-Member -MemberType NoteProperty -Name Gateway -Value $StringDefaultGateway;
            $ReturnedObj | Add-Member -MemberType NoteProperty -Name IsDHCPEnabled -Value $IsDHCPEnabled;
            $ReturnedObj | Add-Member -MemberType NoteProperty -Name DNSServers -Value $StringDNSServers;
            $ReturnedObj | Add-Member -MemberType NoteProperty -Name MACAddress -Value $MACAddress;
            $ReturnedObj;
            $Results += $ReturnedObj;
        }
    }
    else {
	write-host "Could not connect to $Computer.Name"
	    $IPAddress = "Unknown"
	    $SubnetMask = "Unknown"
            $StringDefaultGateway = "Unknown"
            $StringDNSServers = "Unknown"
            $IsDHCPEnabled = "Unknown"
            $MACAddress  = "Unknown" 

            $ReturnedObj = New-Object -Type PSObject;
            $ReturnedObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer.Name.ToUpper();
            $ReturnedObj | Add-Member -MemberType NoteProperty -Name IPAddress -Value $IPAddress;
            $ReturnedObj | Add-Member -MemberType NoteProperty -Name SubnetMask -Value $SubnetMask;
            $ReturnedObj | Add-Member -MemberType NoteProperty -Name Gateway -Value $StringDefaultGateway;
            $ReturnedObj | Add-Member -MemberType NoteProperty -Name IsDHCPEnabled -Value $IsDHCPEnabled;
            $ReturnedObj | Add-Member -MemberType NoteProperty -Name DNSServers -Value $StringDNSServers;
            $ReturnedObj | Add-Member -MemberType NoteProperty -Name MACAddress -Value $MACAddress;
            $ReturnedObj;
            $Results += $ReturnedObj;
    }
}
 
$Results | export-csv $CSVFileName -notype;


