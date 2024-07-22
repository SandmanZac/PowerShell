Import-Module ActiveDirectory

$DomainControllers = Get-ADDomainController -Filter *

function Get-DCIPSettings {
    $IPs = @()
    foreach ($DomainController in $DomainControllers) {
        $IPAddress = Invoke-Command -computerName $DomainController -ScriptBlock { (Get-NetIPAddress -AddressFamily ipv4 | where-object {$_.Interfaceindex -gt 1}).IPAddress }
        $IPs += $IPAddress
    }
    return $IPs
}

# Function to check DNS settings on a domain controller
function Check-DNSSettings {
    param (
        [string]$DomainController,
        [string[]]$DomainControllerIPs
    )

    # Get network adapter settings for the domain controller
    $NetworkAdapters = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $DomainController | Where-Object { $_.DNSServerSearchOrder }

    foreach ($Adapter in $NetworkAdapters) {
        $DNSServers = $Adapter.DNSServerSearchOrder

        if ($DNSServers.Count -lt 2) {
            Write-Host "[$DomainController] - Less than 2 DNS entries found." -ForegroundColor Yellow
            continue
        }

        $LocalIPs = (Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $DomainController | Where-Object { $_.IPAddress }).IPAddress
        $FirstDNS = $DNSServers[0]
        $SecondDNS = $DNSServers[1]

        if ($DomainControllerIPs -notcontains $FirstDNS -or $LocalIPs -contains $FirstDNS) {
            Write-Host "[$DomainController] - First DNS entry is not another DC's IP." -ForegroundColor Red
        } else {
            Write-Host "[$DomainController] - First DNS entry is valid." -ForegroundColor Green
        }

        # Check if the second DNS entry is 127.0.0.1 or the DC's own IP
        if ($SecondDNS -ne '127.0.0.1' -and $LocalIPs -notcontains $SecondDNS) {
            Write-Host "[$DomainController] - Second DNS entry is not valid." -ForegroundColor Red
        } else {
            Write-Host "[$DomainController] - Second DNS entry is valid." -ForegroundColor Green
        }
    }
}

# Iterate through each domain controller and check DNS settings
$DomainControllerIPs = Get-DCIPSettings
foreach ($DomainController in $DomainControllers) {
    Check-DNSSettings -DomainController $DomainController.HostName -DomainControllerIPs $DomainControllerIPs
}