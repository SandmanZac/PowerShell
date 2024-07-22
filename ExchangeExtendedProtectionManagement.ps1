<#
    MIT License

    Copyright (c) Microsoft Corporation.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE
#>

# Version 23.04.04.1055

<#
.SYNOPSIS
    This script enables extended protection on all Exchange servers in the forest.
.DESCRIPTION
    The Script does the following by default.
        1. Enables Extended Protection to the recommended value for the corresponding virtual directory and site.
    Extended Protection is a windows security feature which blocks MiTM attacks.
.PARAMETER RollbackType
    Use this parameter to execute a Rollback Type that should be executed.
.EXAMPLE
    PS C:\> .\ExchangeExtendedProtectionManagement.ps1
    This will run the default mode which does the following:
        1. It will set Extended Protection to the recommended value for the corresponding virtual directory and site on all Exchange Servers in the forest.
.EXAMPLE
    PS C:\> .\ExchangeExtendedProtectionManagement.ps1 -ExchangeServerNames <Array_of_Server_Names>
    This will set the Extended Protection to the recommended value for the corresponding virtual directory and site on all Exchange Servers provided in ExchangeServerNames
.EXAMPLE
    PS C:\> .\ExchangeExtendedProtectionManagement.ps1 -SkipExchangeServerNames <Array_of_Server_Names>
    This will set the Extended Protection to the recommended value for the corresponding virtual directory and site on all Exchange Servers in the forest except the Exchange Servers whose names are provided in the SkipExchangeServerNames parameter.
.EXAMPLE
    PS C:\> .\ExchangeExtendedProtectionManagement.ps1 -RollbackType "RestoreIISAppConfig"
    This will set the applicationHost.config file back to the original state prior to changes made with this script.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]

param(
    [Parameter (Mandatory = $false, ValueFromPipeline, ParameterSetName = 'ConfigureMitigation', HelpMessage = "Enter the list of server names on which the script should execute on")]
    [Parameter (Mandatory = $false, ValueFromPipeline, ParameterSetName = 'ValidateMitigation', HelpMessage = "Enter the list of server names on which the script should execute on")]
    [Parameter (Mandatory = $false, ValueFromPipeline, ParameterSetName = 'Rollback', HelpMessage = "Using this parameter will allow you to rollback using the type you specified.")]
    [Parameter (Mandatory = $false, ValueFromPipeline, ParameterSetName = 'ConfigureEP', HelpMessage = "Enter the list of server names on which the script should execute on")]
    [Parameter (Mandatory = $false, ValueFromPipeline, ParameterSetName = 'ShowEP', HelpMessage = "Enter the list of server names on which the script should execute on")]
    [string[]]$ExchangeServerNames = $null,

    [Parameter (Mandatory = $false, ParameterSetName = 'ConfigureMitigation', HelpMessage = "Enter the list of servers on which the script should not execute on")]
    [Parameter (Mandatory = $false, ParameterSetName = 'ValidateMitigation', HelpMessage = "Enter the list of servers on which the script should not execute on")]
    [Parameter (Mandatory = $false, ParameterSetName = 'Rollback', HelpMessage = "Using this parameter will allow you to rollback using the type you specified.")]
    [Parameter (Mandatory = $false, ParameterSetName = 'ConfigureEP', HelpMessage = "Enter the list of servers on which the script should not execute on")]
    [Parameter (Mandatory = $false, ParameterSetName = 'ShowEP', HelpMessage = "Enter the list of servers on which the script should not execute on")]
    [string[]]$SkipExchangeServerNames = $null,

    [Parameter (Mandatory = $true, ParameterSetName = 'ShowEP', HelpMessage = "Enable to provide a result of the configuration for Extended Protection")]
    [switch]$ShowExtendedProtection,

    [Parameter (Mandatory = $false, ParameterSetName = 'ConfigureEP', HelpMessage = "Used for internal options")]
    [string]$InternalOption,

    [Parameter (Mandatory = $true, ParameterSetName = 'GetExchangeIPs', HelpMessage = "Using this parameter will allow you to get the list of IPs used by Exchange Servers.")]
    [switch]$FindExchangeServerIPAddresses,

    [Parameter (Mandatory = $false, ParameterSetName = 'GetExchangeIPs', HelpMessage = "Using this parameter will allow you to specify the path to the output file.")]
    [ValidateScript({
        (Test-Path -Path $_ -IsValid) -and ([string]::IsNullOrEmpty((Split-Path -Parent $_)) -or (Test-Path -Path (Split-Path -Parent $_)))
        })]
    [string]$OutputFilePath = [System.IO.Path]::Combine((Get-Location).Path, "IPList.txt"),

    [Parameter (Mandatory = $true, ParameterSetName = 'ConfigureMitigation', HelpMessage = "Using this parameter will allow you to specify a txt file with IP range that will be used to apply IP filters.")]
    [Parameter (Mandatory = $true, ParameterSetName = 'ValidateMitigation', HelpMessage = "Using this parameter will allow you to specify a txt file with IP range that will be used to validate IP filters.")]
    [ValidateScript({
        (Test-Path -Path $_)
        })]
    [string]$IPRangeFilePath,

    [Parameter (Mandatory = $true, ParameterSetName = 'ConfigureMitigation', HelpMessage = "Using this parameter will allow you to specify the site and VDir on which you want to configure mitigation.")]
    [ValidateSet('EWSBackend')]
    [ValidateScript({
        ($null -ne $_) -and ($_.Length -gt 0)
        })]
    [string[]]$RestrictType,

    [Parameter (Mandatory = $true, ParameterSetName = 'ValidateMitigation', HelpMessage = "Using this switch will allow you to validate if the mitigations have been applied correctly.")]
    [ValidateSet('RestrictTypeEWSBackend')]
    [ValidateScript({
        ($null -ne $_) -and ($_.Length -gt 0)
        })]
    [string[]]$ValidateType,

    [Parameter (Mandatory = $true, ParameterSetName = 'Rollback', HelpMessage = "Using this parameter will allow you to rollback using the type you specified.")]
    [ValidateSet('RestrictTypeEWSBackend', 'RestoreIISAppConfig')]
    [string[]]$RollbackType,

    [Parameter (Mandatory = $false, HelpMessage = "Using this switch will prevent the script from checking for an updated version.")]
    [switch]$SkipAutoUpdate
)

begin {

function Write-VerboseLog ($Message) {
    $Script:Logger = $Script:Logger | Write-LoggerInstance $Message
}

function Write-HostLog ($Message) {
    $Script:Logger = $Script:Logger | Write-LoggerInstance $Message
}



function Invoke-CatchActionError {
    [CmdletBinding()]
    param(
        [ScriptBlock]$CatchActionFunction
    )

    if ($null -ne $CatchActionFunction) {
        & $CatchActionFunction
    }
}

# Common method used to handle Invoke-Command within a script.
# Avoids using Invoke-Command when running locally on a server.
function Invoke-ScriptBlockHandler {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ComputerName,

        [Parameter(Mandatory = $true)]
        [ScriptBlock]
        $ScriptBlock,

        [string]
        $ScriptBlockDescription,

        [object]
        $ArgumentList,

        [bool]
        $IncludeNoProxyServerOption,

        [ScriptBlock]
        $CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $returnValue = $null
    }
    process {

        if (-not([string]::IsNullOrEmpty($ScriptBlockDescription))) {
            Write-Verbose "Description: $ScriptBlockDescription"
        }

        try {

            if (($ComputerName).Split(".")[0] -ne $env:COMPUTERNAME) {

                $params = @{
                    ComputerName = $ComputerName
                    ScriptBlock  = $ScriptBlock
                    ErrorAction  = "Stop"
                }

                if ($IncludeNoProxyServerOption) {
                    Write-Verbose "Including SessionOption"
                    $params.Add("SessionOption", (New-PSSessionOption -ProxyAccessType NoProxyServer))
                }

                if ($null -ne $ArgumentList) {
                    Write-Verbose "Running Invoke-Command with argument list"
                    $params.Add("ArgumentList", $ArgumentList)
                } else {
                    Write-Verbose "Running Invoke-Command without argument list"
                }

                $returnValue = Invoke-Command @params
            } else {

                if ($null -ne $ArgumentList) {
                    Write-Verbose "Running Script Block Locally with argument list"

                    # if an object array type expect the result to be multiple parameters
                    if ($ArgumentList.GetType().Name -eq "Object[]") {
                        $returnValue = & $ScriptBlock @ArgumentList
                    } else {
                        $returnValue = & $ScriptBlock $ArgumentList
                    }
                } else {
                    Write-Verbose "Running Script Block Locally without argument list"
                    $returnValue = & $ScriptBlock
                }
            }
        } catch {
            Write-Verbose "Failed to run $($MyInvocation.MyCommand)"
            Invoke-CatchActionError $CatchActionFunction
        }
    }
    end {
        Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
        return $returnValue
    }
}

function WriteErrorInformationBase {
    [CmdletBinding()]
    param(
        [object]$CurrentError = $Error[0],
        [ValidateSet("Write-Host", "Write-Verbose")]
        [string]$Cmdlet
    )

    if ($null -ne $CurrentError.OriginInfo) {
        & $Cmdlet "Error Origin Info: $($CurrentError.OriginInfo.ToString())"
    }

    & $Cmdlet "$($CurrentError.CategoryInfo.Activity) : $($CurrentError.ToString())"

    if ($null -ne $CurrentError.Exception -and
        $null -ne $CurrentError.Exception.StackTrace) {
        & $Cmdlet "Inner Exception: $($CurrentError.Exception.StackTrace)"
    } elseif ($null -ne $CurrentError.Exception) {
        & $Cmdlet "Inner Exception: $($CurrentError.Exception)"
    }

    if ($null -ne $CurrentError.InvocationInfo.PositionMessage) {
        & $Cmdlet "Position Message: $($CurrentError.InvocationInfo.PositionMessage)"
    }

    if ($null -ne $CurrentError.Exception.SerializedRemoteInvocationInfo.PositionMessage) {
        & $Cmdlet "Remote Position Message: $($CurrentError.Exception.SerializedRemoteInvocationInfo.PositionMessage)"
    }

    if ($null -ne $CurrentError.ScriptStackTrace) {
        & $Cmdlet "Script Stack: $($CurrentError.ScriptStackTrace)"
    }
}

function Write-VerboseErrorInformation {
    [CmdletBinding()]
    param(
        [object]$CurrentError = $Error[0]
    )
    WriteErrorInformationBase $CurrentError "Write-Verbose"
}

function Write-HostErrorInformation {
    [CmdletBinding()]
    param(
        [object]$CurrentError = $Error[0]
    )
    WriteErrorInformationBase $CurrentError "Write-Host"
}

function Invoke-ConfigureMitigation {
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ExchangeServers,
        [Parameter(Mandatory = $true)]
        [object[]]$IPRangeAllowListRules ,
        [Parameter(Mandatory = $true)]
        [string[]]$SiteVDirLocations
    )

    begin {
        $FailedServersFilter = @{}
        $UnchangedFilterServers = @{}

        $progressParams = @{
            Activity        = "Applying IP filtering Rules"
            Status          = [string]::Empty
            PercentComplete = 0
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $ConfigureMitigation = {
            param(
                [Object]$Arguments
            )

            $SiteVDirLocations = $Arguments.SiteVDirLocations
            $IpRangesForFiltering = $Arguments.IpRangesForFiltering
            $WhatIf = $Arguments.PassedWhatIf

            $results = @{
                IsWindowsFeatureInstalled = $false
                IsGetLocalIPSuccessful    = $false
                LocalIPs                  = New-Object 'System.Collections.Generic.List[string]'
                ErrorContext              = $null
            }

            function BackupCurrentIPFilteringRules {
                param(
                    [Parameter(Mandatory = $true)]
                    [string]$BackupPath,
                    [Parameter(Mandatory = $true)]
                    [string]$Filter,
                    [Parameter(Mandatory = $true)]
                    [string]$IISPath,
                    [Parameter(Mandatory = $true)]
                    [string]$SiteVDirLocation,
                    [Parameter(Mandatory = $false)]
                    [object[]]$ExistingRules
                )

                $DefaultForUnspecifiedIPs = Get-WebConfigurationProperty -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "allowUnlisted"
                if ($null -eq $ExistingRules) {
                    $ExistingRules = New-Object 'System.Collections.Generic.List[object]'
                }

                $BackupFilteringConfiguration = @{Rules=$ExistingRules; DefaultForUnspecifiedIPs=$DefaultForUnspecifiedIPs }
                if (-not $WhatIf) {
                    $BackupFilteringConfiguration |  ConvertTo-Json -Depth 2 | Out-File $BackupPath
                }

                return $true
            }

            function GetLocalIPAddresses {
                $ips = New-Object 'System.Collections.Generic.List[string]'
                $interfaces = Get-NetIPAddress -ErrorAction Stop
                foreach ($interface in $interfaces) {
                    if ($interface.AddressState -eq 'Preferred') {
                        $ips += $interface.IPAddress
                    }
                }

                return $ips
            }

            # Create IP allow list from user provided IP subnets
            function CreateIPRangeAllowList {
                param (
                    [Parameter(Mandatory = $true)]
                    [string]$SiteVDirLocation,
                    [Parameter(Mandatory = $true)]
                    [object[]]$IpFilteringRules,
                    [Parameter(Mandatory = $true)]
                    [Hashtable] $state
                )

                $backupPath = "$($env:WINDIR)\System32\inetSrv\config\IpFilteringRules_" + $SiteVDirLocation.Replace('/', '-') + "_$([DateTime]::Now.ToString("yyyyMMddHHMMss")).bak"
                $Filter = 'system.webServer/security/ipSecurity'
                $IISPath = 'IIS:\'
                $ExistingRules = @(Get-WebConfigurationProperty -Filter $Filter -Location $SiteVDirLocation -name collection)
                $state.IsBackUpSuccessful = BackupCurrentIPFilteringRules -BackupPath $backupPath -Filter $Filter -IISPath $IISPath -SiteVDirLocation $SiteVDirLocation -ExistingRules $ExistingRules

                $RulesToBeAdded = @()

                foreach ($IpFilteringRule in $IpFilteringRules) {
                    $ExistingIPSubnetRule = $ExistingRules | Where-Object { $_.ipAddress -eq $IpFilteringRule.IP -and
                        ($_.subnetMask -eq $IpFilteringRule.SubnetMask -or $IpFilteringRule.Type -eq "Single IP")
                    }

                    if ($null -eq $ExistingIPSubnetRule) {
                        if ($IpFilteringRule.Type -eq "Single IP") {
                            $RulesToBeAdded += @{ipAddress=$IpFilteringRule.IP; allowed=$IpFilteringRule.Allowed; }
                        } else {
                            $RulesToBeAdded += @{ipAddress=$IpFilteringRule.IP; subnetMask=$IpFilteringRule.SubnetMask; allowed=$IpFilteringRule.Allowed; }
                        }
                    } else {
                        if ($ExistingIPSubnetRule.allowed -ne $IpFilteringRule.Allowed) {
                            if ($IpFilteringRule.Type -eq "Single IP") {
                                $IpString = $IpFilteringRule.IP
                            } else {
                                $IpString = ("{0}/{1}" -f $IpFilteringRule.IP, $IpFilteringRule.SubnetMask)
                            }

                            $state.IPsNotAdded += $IpString
                        }
                    }
                }

                if ($RulesToBeAdded.Count + $ExistingRules.Count -gt 500) {
                    $state.IPsNotAdded += $RulesToBeAdded
                    throw 'Too many IP filtering rules (Existing rules [$($ExistingRules.Count)] + New rules [$($RulesToBeAdded.Count)] > 500). Please reduce the specified entries by providing appropriate subnets.'
                }

                if ($RulesToBeAdded.Count -gt 0) {
                    $state.AreIPRulesModified = $true
                    Add-WebConfigurationProperty  -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "." -Value $RulesToBeAdded -ErrorAction Stop -WhatIf:$WhatIf
                }

                $state.IsCreateIPRulesSuccessful = $true

                # Setting default to deny
                Set-WebConfigurationProperty -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "allowUnlisted" -Value $false -WhatIf:$WhatIf
                $state.IsSetDefaultRuleSuccessful = $true
            }

            try {
                try {
                    $baseError = "Installation of IP and Domain filtering Module failed."
                    $InstallResult = Install-WindowsFeature Web-IP-Security -ErrorAction Stop -WhatIf:$WhatIf
                    if (-not $InstallResult.Success) {
                        throw $baseError
                    }
                } catch {
                    throw "$baseError Inner exception: $_"
                }

                $results.IsWindowsFeatureInstalled = $true

                $localIPs = GetLocalIPAddresses
                $results.IsGetLocalIPSuccessful = $true

                foreach ($localIP in $localIPs) {
                    if ($null -eq ($IpRangesForFiltering | Where-Object { $_.Type -eq "Single IP" -and $_.IP -eq $localIP })) {
                        $IpRangesForFiltering += @{Type="Single IP"; IP=$localIP; Allowed=$true }
                    }
                }

                $results.LocalIPs = $localIPs
                foreach ($SiteVDirLocation in $SiteVDirLocations) {
                    $state = @{
                        IsBackUpSuccessful         = $false
                        IsCreateIPRulesSuccessful  = $false
                        IsSetDefaultRuleSuccessful = $false
                        ErrorContext               = $null
                        IPsNotAdded                = New-Object 'System.Collections.Generic.List[string]'
                        AreIPRulesModified         = $false
                    }

                    try {
                        CreateIPRangeAllowList -SiteVDirLocation $SiteVDirLocation -IpFilteringRules $IpRangesForFiltering -state $state
                    } catch {
                        $state.ErrorContext = $_
                    }

                    $results[$SiteVDirLocation] = $state
                }
            } catch {
                $results.ErrorContext = $_
            }

            return $results
        }
    } process {
        $ScriptBlockArgs = [PSCustomObject]@{
            SiteVDirLocations    = $SiteVDirLocations
            IpRangesForFiltering = $IPRangeAllowListRules
            PassedWhatIf         = $WhatIfPreference
        }

        $counter = 0
        $totalCount = $ExchangeServers.Count

        if ($null -eq $IPRangeAllowListRules ) {
            $IPRangeAllowListString = "null"
        } else {
            $IPStrings = @()
            $IPRangeAllowListRules  | ForEach-Object {
                if ($_.Type -eq "Single IP") {
                    $IPStrings += $_.IP
                } else {
                    $IPStrings += ("{0}/{1}" -f $_.IP, $_.SubnetMask)
                }
            }
            $IPRangeAllowListString = [string]::Join(", ", $IPStrings)
        }

        $SiteVDirLocations | ForEach-Object {
            $FailedServersFilter[$_] = New-Object 'System.Collections.Generic.List[string]'
            $UnchangedFilterServers[$_] = New-Object 'System.Collections.Generic.List[string]'
        }

        foreach ($Server in $ExchangeServers) {
            $baseStatus = "Processing: $Server -"
            $progressParams.PercentComplete = ($counter / $totalCount * 100)
            $progressParams.Status = "$baseStatus Applying rules"
            Write-Progress @progressParams
            $counter ++;

            Write-Verbose ("Calling Invoke-ScriptBlockHandler on Server {0} with arguments SiteVDirLocation: {1}, IPRangeAllowListRules : {2}" -f $Server, $SiteVDirLocation, $IPRangeAllowListString)
            $resultsInvoke = Invoke-ScriptBlockHandler -ComputerName $Server -ScriptBlock $ConfigureMitigation -ArgumentList $ScriptBlockArgs

            Write-Verbose ("Adding IP Restriction rules on Server {0}" -f $Server)
            if ($resultsInvoke.IsWindowsFeatureInstalled) {
                Write-Verbose ("Successfully installed windows feature - Web-IP-Security on server {0}" -f $Server)
            } else {
                Write-Host ("Script failed to install windows feature - Web-IP-Security on server {0} with the Inner Exception:" -f $Server) -ForegroundColor Red
                Write-HostErrorInformation $resultsInvoke.ErrorContext
                $FailedServersFilter[$SiteVDirLocation] += $Server
                continue
            }

            if ($resultsInvoke.IsGetLocalIPSuccessful) {
                Write-Verbose ("Successfully retrieved local IPs for the server")
                if ($null -ne $resultsInvoke.LocalIPs -and $resultsInvoke.LocalIPs.Length -gt 0) {
                    Write-Verbose ("Local IPs detected for this server: {0}" -f [string]::Join(", ", [string[]]$resultsInvoke.LocalIPs))
                } else {
                    Write-Verbose ("No Local IPs detected for this server")
                }
            } else {
                Write-Host ("Script failed to retrieve local IPs for server {0}. Reapply IP filtering on server. Inner Exception:" -f $Server) -ForegroundColor Red
                Write-HostErrorInformation $resultsInvoke.ErrorContext
                $FailedServersFilter[$SiteVDirLocation] += $Server
                continue
            }

            foreach ($SiteVDirLocation in $SiteVDirLocations) {
                $state = $resultsInvoke[$SiteVDirLocation]

                if ($state.IsBackUpSuccessful) {
                    Write-Verbose ("Successfully backed up IP filtering allow list for VDir $SiteVDirLocation on server $Server")
                } else {
                    Write-Host ("Script failed to backup IP filtering allow list for VDir $SiteVDirLocation on server $Server with the Inner Exception:") -ForegroundColor Red
                    Write-HostErrorInformation $state.ErrorContext
                    $FailedServersFilter[$SiteVDirLocation] += $Server
                    continue
                }

                if ($state.IsCreateIPRulesSuccessful) {
                    if ($state.IPsNotAdded.Length -gt 0) {
                        $line = ("Some IPs provided in the IPRange file were present in deny rules, hence these IPs were not added in the Allow List for VDir $SiteVDirLocation on server $Server. If you wish to add these IPs in allow list, remove these IPs from deny list in module name and reapply IP restrictions again.")
                        Write-Warning ($line + "Check logs for further details.")
                        Write-Verbose $line
                        Write-Verbose ([string]::Join(", ", $state.IPsNotAdded))
                    }

                    if (-not $state.AreIPRulesModified) {
                        Write-Verbose ("No changes were made to IP filtering rules for VDir $SiteVDirLocation on server $Server")
                        $UnchangedFilterServers[$SiteVDirLocation] += $Server
                    } else {
                        Write-Host ("Successfully updated IP filtering allow list for VDir $SiteVDirLocation on server $Server")
                    }
                } else {
                    Write-Host ("Script failed to update IP filtering allow list for VDir $SiteVDirLocation on server $Server with the Inner Exception:") -ForegroundColor Red
                    Write-HostErrorInformation $state.ErrorContext
                    $FailedServersFilter[$SiteVDirLocation] += $Server
                    continue
                }

                if ($state.IsSetDefaultRuleSuccessful) {
                    Write-Verbose ("Successfully set the default IP filtering rule to deny for VDir $SiteVDirLocation on server $Server")
                } else {
                    Write-Host ("Script failed to set the default IP filtering rule to deny for VDir $SiteVDirLocation on server $Server with the Inner Exception:") -ForegroundColor Red
                    Write-HostErrorInformation $state.ErrorContext
                    $FailedServersFilter[$SiteVDirLocation] += $Server
                    continue
                }
            }
        }
    } end {
        foreach ($SiteVDirLocation in $SiteVDirLocations) {
            if ($FailedServersFilter[$SiteVDirLocation].Length -gt 0) {
                Write-Host ("Unable to create IP Filtering Rules for VDir $SiteVDirLocation on the following servers: {0}" -f [string]::Join(", ", $FailedServersFilter[$SiteVDirLocation])) -ForegroundColor Red
            }

            if ($UnchangedFilterServers[$SiteVDirLocation].Length -gt 0) {
                Write-Host ("IP Restrictions are applied. No changes made in IP Restriction rules for VDir $SiteVDirLocation in : {0}" -f [string]::Join(", ", $UnchangedFilterServers[$SiteVDirLocation]))
            }
        }
    }
}


function Invoke-ValidateMitigation {
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ExchangeServers,
        [Parameter(Mandatory = $false)]
        [object[]]$ipRangeAllowListRules,
        [Parameter(Mandatory = $true)]
        [string[]]$SiteVDirLocations
    )

    begin {
        $FailedServersEP = @{}
        $FailedServersFilter = @{}

        $UnMitigatedServersEP = @{}
        $UnMitigatedServersFilter = @{}

        $progressParams = @{
            Activity        = "Verifying Mitigations"
            Status          = [string]::Empty
            PercentComplete = 0
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $ValidateMitigationScriptBlock = {
            param(
                [Object]$Arguments
            )

            $SiteVDirLocations = $Arguments.SiteVDirLocations
            $IpRangesForFiltering = $Arguments.IpRangesForFiltering

            $results = @{}

            function GetLocalIPAddresses {
                $ips = New-Object 'System.Collections.Generic.List[string]'
                $interfaces = Get-NetIPAddress
                foreach ($interface in $interfaces) {
                    if ($interface.AddressState -eq 'Preferred') {
                        $ips += $interface.IPAddress
                    }
                }

                return $ips
            }

            # Set EP to None
            function GetExtendedProtectionState {
                param (
                    [Parameter(Mandatory = $true)]
                    [string]$SiteVDirLocation
                )

                $Filter = 'system.webServer/security/authentication/windowsAuthentication/extendedProtection'

                $ExtendedProtection = Get-WebConfigurationProperty -Filter $Filter -Location $SiteVDirLocation -name tokenChecking
                return $ExtendedProtection
            }

            # Create IP allow list from user provided IP subnets
            function VerifyIPRangeAllowList {
                param (
                    [Parameter(Mandatory = $true)]
                    [string]$SiteVDirLocation,
                    [Parameter(Mandatory = $true)]
                    [object[]]$IpFilteringRules,
                    [Parameter(Mandatory = $true)]
                    [Hashtable]$state
                )

                $state.IsWindowsFeatureInstalled = (Get-WindowsFeature -Name "Web-IP-Security").InstallState -eq "Installed"
                $state.IsWindowsFeatureVerified = $true

                if (-not $state.IsWindowsFeatureInstalled) {
                    return
                }

                $Filter = 'system.webServer/security/ipSecurity'
                $IISPath = 'IIS:\'

                $ExistingRules = @(Get-WebConfigurationProperty -Filter $Filter -Location $SiteVDirLocation -name collection)

                foreach ($IpFilteringRule in $IpFilteringRules) {
                    $ExistingIPSubnetRule = $ExistingRules | Where-Object {
                        $_.ipAddress -eq $IpFilteringRule.IP -and
                        ($_.subnetMask -eq $IpFilteringRule.SubnetMask -or $IpFilteringRule.Type -eq "Single IP") -and
                        $_.allowed -eq $IpFilteringRule.Allowed
                    }

                    if ($null -eq $ExistingIPSubnetRule) {
                        if ($IpFilteringRule.Type -eq "Single IP") {
                            $IpString = $IpFilteringRule.IP
                        } else {
                            $IpString = ("{0}/{1}" -f $IpFilteringRule.IP, $IpFilteringRule.SubnetMask)
                        }
                        $state.RulesNotFound += $IpString
                    }
                }

                $state.AreIPRulesVerified = $true

                $state.IsDefaultFilterDeny = -not ((Get-WebConfigurationProperty -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "allowUnlisted").Value)
                $state.IsDefaultFilterVerified = $true
            }

            foreach ($SiteVDirLocation in $SiteVDirLocations) {
                try {
                    $state = @{
                        IsEPVerified              = $false
                        IsEPOff                   = $false
                        IsWindowsFeatureInstalled = $false
                        IsWindowsFeatureVerified  = $false
                        AreIPRulesVerified        = $false
                        IsDefaultFilterVerified   = $false
                        IsDefaultFilterDeny       = $false
                        RulesNotFound             = New-Object 'System.Collections.Generic.List[string]'
                        ErrorContext              = $null
                    }

                    $EPState = GetExtendedProtectionState -SiteVDirLocation $SiteVDirLocation
                    if ($EPState -eq "None") {
                        $state.IsEPOff = $true
                    } else {
                        $state.IsEPOff = $false
                    }

                    $state.IsEPVerified = $true

                    if ($null -ne $IpRangesForFiltering) {
                        $localIPs = GetLocalIPAddresses

                        $localIPs | ForEach-Object {
                            $IpRangesForFiltering += @{Type="Single IP"; IP=$_; Allowed=$true }
                        }

                        VerifyIPRangeAllowList -SiteVDirLocation $SiteVDirLocation -IpFilteringRules $IpRangesForFiltering -state $state
                    }
                } catch {
                    $state.ErrorContext = $_
                }

                $results[$SiteVDirLocation] = $state
            }

            return $results
        }
    } process {
        $ScriptBlockArgs = [PSCustomObject]@{
            SiteVDirLocations    = $SiteVDirLocations
            IpRangesForFiltering = $ipRangeAllowListRules
        }

        $counter = 0
        $totalCount = $ExchangeServers.Count
        if ($null -eq $ipRangeAllowListRules) {
            $ipRangeAllowListString = "null"
        } else {
            $ipRangeAllowListString = [string]::Join(", ", $ipRangeAllowListRules)
        }

        $SiteVDirLocations | ForEach-Object {
            $FailedServersEP[$_] = New-Object 'System.Collections.Generic.List[string]'
            $FailedServersFilter[$_] = New-Object 'System.Collections.Generic.List[string]'

            $UnMitigatedServersEP[$_] = New-Object 'System.Collections.Generic.List[string]'
            $UnMitigatedServersFilter[$_] = New-Object 'System.Collections.Generic.List[string]'
        }

        foreach ($Server in $ExchangeServers) {
            $baseStatus = "Processing: $Server -"
            $progressParams.PercentComplete = ($counter / $totalCount * 100)
            $progressParams.Status = "$baseStatus Validating rules"
            Write-Progress @progressParams
            $counter ++;

            Write-Verbose ("Calling Invoke-ScriptBlockHandler on Server {0} with arguments SiteVDirLocations: {1}, ipRangeAllowListRules: {2}" -f $Server, [string]::Join(", ", $SiteVDirLocations), $ipRangeAllowListString)
            $resultsInvoke = Invoke-ScriptBlockHandler -ComputerName $Server -ScriptBlock $ValidateMitigationScriptBlock -ArgumentList $ScriptBlockArgs

            if ($null -eq $resultsInvoke) {
                $line = "Server Unreachable: Unable to validate IP filtering rules on server $($Server)."
                Write-Verbose $line
                Write-Warning $line
                $SiteVDirLocations | ForEach-Object { $FailedServersEP[$_].Add($Server) }
                $SiteVDirLocations | ForEach-Object { $FailedServersFilter[$_].Add($Server) }
                continue
            }

            foreach ($SiteVDirLocation in $SiteVDirLocations) {
                $state = $resultsInvoke[$SiteVDirLocation]

                if ($state.IsEPOff) {
                    Write-Verbose ("Expected: The state of Extended protection flag is None for VDir $($SiteVDirLocation) on server $Server")
                } elseif ($state.IsEPVerified) {
                    Write-Verbose ("Unexpected: The state of Extended protection flag is not set to None for VDir $($SiteVDirLocation) on server $Server")
                    $UnMitigatedServersEP[$SiteVDirLocation] += $Server
                } else {
                    Write-Host ("Unknown: Script failed to get state of Extended protection flag for VDir $($SiteVDirLocation) with Inner Exception") -ForegroundColor Red
                    Write-HostErrorInformation $results.ErrorContext
                    $FailedServersEP[$SiteVDirLocation] += $Server
                    $FailedServersFilter[$SiteVDirLocation] += $Server
                    continue
                }

                $IsFilterUnMitigated = $false

                if (-not $state.IsWindowsFeatureVerified) {
                    Write-Host ("Unknown: Script failed to verify if the Windows feature Web-IP-Security is present for VDir $($SiteVDirLocation) on server $Server with Inner Exception") -ForegroundColor Red
                    Write-HostErrorInformation $results.ErrorContext
                    $FailedServersFilter[$SiteVDirLocation] += $Server
                    continue
                } elseif (-not $state.IsWindowsFeatureInstalled) {
                    Write-Verbose ("Unexpected: Windows feature Web-IP-Security is not present on the server for VDir $($SiteVDirLocation) on server $Server")
                    $IsFilterUnMitigated = $true
                } else {
                    Write-Verbose ("Expected: Successfully verified that the Windows feature Web-IP-Security is present on the server for VDir $($SiteVDirLocation) on server $Server")
                    if (-not $state.AreIPRulesVerified) {
                        Write-Host ("Unknown: Script failed to verify IP Filtering Rules for VDir $($SiteVDirLocation) on server $Server with Inner Exception") -ForegroundColor Red
                        Write-HostErrorInformation $results.ErrorContext
                        $FailedServersFilter[$SiteVDirLocation] += $Server
                        continue
                    } elseif ($null -ne $state.RulesNotFound -and $state.RulesNotFound.Length -gt 0) {
                        Write-Verbose ("Unexpected: Some or all the rules present in the file specified aren't applied for VDir $($SiteVDirLocation) on server $Server")
                        Write-Verbose ("Following Rules weren't found: {0}" -f [string]::Join(", ", [string[]]$state.RulesNotFound))
                        $IsFilterUnMitigated = $true
                    } else {
                        Write-Verbose ("Expected: Successfully verified all the IP filtering rules for VDir $($SiteVDirLocation) on server $Server")
                    }

                    if ($state.IsDefaultFilterDeny) {
                        Write-Verbose ("Expected: The default IP Filtering rule is set to deny for VDir $($SiteVDirLocation) on server $Server")
                    } elseif ($state.IsDefaultFilterVerified) {
                        Write-Verbose ("Unexpected: The default IP Filtering rule is not set to deny for VDir $($SiteVDirLocation) on server $Server")
                        $IsFilterUnMitigated = $true
                    } else {
                        Write-Host ("Unknown: Script failed to get the default IP Filtering rule for VDir $($SiteVDirLocation) on server $Server with Inner Exception") -ForegroundColor Red
                        Write-HostErrorInformation $results.ErrorContext
                        $FailedServersFilter[$SiteVDirLocation] += $Server
                        continue
                    }
                }

                if ($IsFilterUnMitigated) {
                    $UnMitigatedServersFilter[$SiteVDirLocation] += $Server
                }
            }
        }
    } end {
        $FoundFailedOrUnmitigated = $false
        foreach ($SiteVDirLocation in $SiteVDirLocations) {
            if ($UnMitigatedServersEP[$SiteVDirLocation].Length -gt 0) {
                Write-Host ("Extended Protection on the following servers are not set to expected values for VDir {0}: {1}" -f $SiteVDirLocation, [string]::Join(", ", $UnMitigatedServersEP[$SiteVDirLocation])) -ForegroundColor Red
                $FoundFailedOrUnmitigated = $true
            }

            if ($UnMitigatedServersFilter[$SiteVDirLocation].Length -gt 0) {
                Write-Host ("IP Filtering Rules or Default IP rule on the following servers does not contain all the IP Ranges/addresses provided for validation in VDir {0}: {1}" -f $SiteVDirLocation, [string]::Join(", ", $UnMitigatedServersFilter[$SiteVDirLocation])) -ForegroundColor Red
                $FoundFailedOrUnmitigated = $true
            }

            if ($FailedServersEP[$SiteVDirLocation].Length -gt 0) {
                Write-Host ("Unable to verify Extended Protection on the following servers for VDir {0}: {1}" -f $SiteVDirLocation, [string]::Join(", ", $FailedServersEP[$SiteVDirLocation])) -ForegroundColor Red
                $FoundFailedOrUnmitigated = $true
            }

            if ($FailedServersFilter[$SiteVDirLocation].Length -gt 0) {
                Write-Host ("Unable to verify IP Filtering Rules on the following servers for VDir {0}: {1}" -f $SiteVDirLocation, [string]::Join(", ", $FailedServersFilter[$SiteVDirLocation])) -ForegroundColor Red
                $FoundFailedOrUnmitigated = $true
            }
        }

        if (-not $FoundFailedOrUnmitigated) {
            Write-Host "All the servers have been validated successfully!" -ForegroundColor Green
        }
    }
}


function Invoke-RollbackIPFiltering {
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$ExchangeServers,
        [Parameter(Mandatory = $true)]
        [string[]]$SiteVDirLocations
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $FailedServers = @{}

        $progressParams = @{
            Activity        = "Rolling back IP filtering Rules"
            Status          = [string]::Empty
            PercentComplete = 0
        }

        $RollbackIPFiltering = {
            param(
                [Object]$Arguments
            )

            $SiteVDirLocations = $Arguments.SiteVDirLocations
            $WhatIf = $Arguments.PassedWhatIf
            $Filter = 'system.webServer/security/ipSecurity'
            $FilterEP = 'system.WebServer/security/authentication/windowsAuthentication'
            $IISPath = 'IIS:\'

            $results = @{}

            function BackupCurrentIPFilteringRules {
                param(
                    [Parameter(Mandatory = $true)]
                    [string]$BackupPath,
                    [Parameter(Mandatory = $true)]
                    [string]$Filter,
                    [Parameter(Mandatory = $true)]
                    [string]$IISPath,
                    [Parameter(Mandatory = $true)]
                    [string]$SiteVDirLocation,
                    [Parameter(Mandatory = $false)]
                    [System.Collections.Generic.List[object]]$ExistingRules
                )

                $DefaultForUnspecifiedIPs = Get-WebConfigurationProperty -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "allowUnlisted"
                if ($null -eq $ExistingRules) {
                    $ExistingRules = New-Object 'System.Collections.Generic.List[object]'
                }

                $BackupFilteringConfiguration = @{Rules=$ExistingRules; DefaultForUnspecifiedIPs=$DefaultForUnspecifiedIPs }
                if (-not $WhatIf) {
                    $BackupFilteringConfiguration |  ConvertTo-Json -Depth 2 | Out-File $BackupPath
                }

                return $true
            }

            function RestoreOriginalIPFilteringRules {
                param(
                    [Parameter(Mandatory = $true)]
                    [string]$Filter,
                    [Parameter(Mandatory = $true)]
                    [string]$IISPath,
                    [Parameter(Mandatory = $true)]
                    [string]$SiteVDirLocation,
                    [Parameter(Mandatory = $false)]
                    [object[]]$OriginalIpFilteringRules,
                    [Parameter(Mandatory = $true)]
                    [object]$DefaultForUnspecifiedIPs
                )

                Clear-WebConfiguration -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -ErrorAction Stop -WhatIf:$WhatIf
                $RulesToBeAdded = New-Object 'System.Collections.Generic.List[object]'
                foreach ($IpFilteringRule in $OriginalIpFilteringRules) {
                    $RulesToBeAdded += @{ipAddress=$IpFilteringRule.ipAddress; subnetMask=$IpFilteringRule.subnetMask; domainName=$IpFilteringRule.domainName; allowed=$IpFilteringRule.allowed; }
                }
                Set-WebConfigurationProperty -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "allowUnlisted" -Value $DefaultForUnspecifiedIPs.Value -WhatIf:$WhatIf
                if ($OriginalIpFilteringRules.Length -gt 0) {
                    Add-WebConfigurationProperty  -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "." -Value $RulesToBeAdded -ErrorAction Stop -WhatIf:$WhatIf
                }

                return $true
            }

            function TurnONExtendedProtection {
                param(
                    [Parameter(Mandatory = $true)]
                    [string]$Filter,
                    [Parameter(Mandatory = $true)]
                    [string]$IISPath,
                    [Parameter(Mandatory = $true)]
                    [string]$SiteVDirLocation
                )
                $ExtendedProtection = Get-WebConfigurationProperty -Filter $Filter -Location $SiteVDirLocation -name "extendedProtection.tokenChecking"
                if ($ExtendedProtection -ne "Require") {
                    Set-WebConfigurationProperty -Filter $Filter -PSPath $IISPath -Location $SiteVDirLocation -Name "extendedProtection.tokenChecking" -Value "Require"
                }
            }

            foreach ($SiteVDirLocation in $SiteVDirLocations) {
                $state = @{
                    TurnOnEPSuccessful      = $false
                    RestoreFileExists       = $false
                    BackUpPath              = $null
                    BackupCurrentSuccessful = $false
                    RestorePath             = $null
                    RestoreSuccessful       = $false
                    ErrorContext            = $null
                }
                try {
                    $state.RestorePath = (Get-ChildItem "$($env:WINDIR)\System32\inetSrv\config\" -Filter ("*IpFilteringRules_"+  $SiteVDirLocation.Replace('/', '-') + "*.bak") | Sort-Object CreationTime | Select-Object -First 1).FullName
                    if ($null -eq $state.RestorePath) {
                        throw "Invalid operation. No backup file exists at path $($env:WINDIR)\System32\inetSrv\config\"
                    }
                    $state.RestoreFileExists = $true

                    TurnONExtendedProtection -Filter $FilterEP -IISPath $IISPath -SiteVDirLocation $SiteVDirLocation
                    $state.TurnOnEPSuccessful = $true

                    $state.BackUpPath = "$($env:WINDIR)\System32\inetSrv\config\IpFilteringRules_" + $SiteVDirLocation.Replace('/', '-') + "_$([DateTime]::Now.ToString("yyyyMMddHHMMss")).bak"
                    $ExistingRules = @(Get-WebConfigurationProperty -Filter $Filter -Location $SiteVDirLocation -name collection)
                    $state.BackupCurrentSuccessful = BackupCurrentIPFilteringRules -BackupPath $state.BackUpPath -Filter $Filter -IISPath $IISPath -SiteVDirLocation $SiteVDirLocation -ExistingRules $ExistingRules

                    $originalIpFilteringConfigurations = (Get-Content $state.RestorePath | Out-String | ConvertFrom-Json)
                    $state.RestoreSuccessful = RestoreOriginalIPFilteringRules -OriginalIpFilteringRules ($originalIpFilteringConfigurations.Rules) -DefaultForUnspecifiedIPs ($originalIpFilteringConfigurations.DefaultForUnspecifiedIPs) -Filter $Filter -IISPath $IISPath -SiteVDirLocation $SiteVDirLocation
                } catch {
                    $state.ErrorContext = $_
                }

                $results[$SiteVDirLocation] = $state
            }

            return $results
        }
    } process {
        $ScriptBlockArgs = [PSCustomObject]@{
            SiteVDirLocations = $SiteVDirLocations
            PassedWhatIf      = $WhatIfPreference
        }

        $exchangeServersProcessed = 0
        $totalExchangeServers = $ExchangeServers.Count

        $SiteVDirLocations | ForEach-Object {
            $FailedServers[$_] = New-Object 'System.Collections.Generic.List[string]'
        }

        foreach ($Server in $ExchangeServers) {
            $baseStatus = "Processing: $($Server.Name) -"
            $progressParams.PercentComplete = ($exchangeServersProcessed / $totalExchangeServers * 100)
            $progressParams.Status = "$baseStatus Rolling back rules"
            Write-Progress @progressParams
            $exchangeServersProcessed++;

            Write-Verbose ("Calling Invoke-ScriptBlockHandler on Server {0} with Arguments Site: {1}, VDir: {2}" -f $Server.Name, $Site, $VDir)
            Write-Verbose ("Restoring previous state for Server {0}" -f $Server.Name)
            $resultsInvoke = Invoke-ScriptBlockHandler -ComputerName $Server.Name -ScriptBlock $RollbackIPFiltering -ArgumentList $ScriptBlockArgs

            if ($null -eq $resultsInvoke) {
                $line = "Server Unreachable: Unable to rollback IP filtering rules on server $($Server.Name)."
                Write-Verbose $line
                Write-Warning $line
                $SiteVDirLocations | ForEach-Object { $FailedServers[$_].Add($Server.Name) }
                continue
            }

            foreach ($SiteVDirLocation in $SiteVDirLocations) {
                $Failed = $false
                $state = $resultsInvoke[$SiteVDirLocation]
                if ($state.RestoreFileExists) {
                    if ($state.TurnOnEPSuccessful) {
                        Write-Host "Turned on Extended Protection on server $($Server.Name) for VDir $SiteVDirLocation"
                        if ($state.BackupCurrentSuccessful) {
                            Write-Verbose "Successfully backed up current configuration on server $($Server.Name) at $($state.BackUpPath) for VDir $SiteVDirLocation"
                            if ($state.RestoreSuccessful) {
                                Write-Host "Successfully rolled back IP filtering rules on server $($Server.Name) from $($state.RestorePath) for VDir $SiteVDirLocation"
                            } else {
                                Write-Host "Failed to rollback IP filtering rules on server $($Server.Name). Aborting rollback on the server $($Server.Name) for VDir $SiteVDirLocation. Inner Exception:" -ForegroundColor Red
                                Write-HostErrorInformation $state.ErrorContext
                                $Failed = $true
                            }
                        } else {
                            Write-Host "Failed to backup the current configuration on server $($Server.Name). Aborting rollback on the server $($Server.Name) for VDir $SiteVDirLocation. Inner Exception:" -ForegroundColor Red
                            Write-HostErrorInformation $state.ErrorContext
                            $Failed = $true
                        }
                    } else {
                        Write-Host "Failed to turn on Extended Protection on server $($Server.Name). Aborting rollback on the server $($Server.Name) for VDir $SiteVDirLocation. Inner Exception:" -ForegroundColor Red
                        Write-HostErrorInformation $state.ErrorContext
                        $Failed = $true
                    }
                } else {
                    Write-Host "No restore file exists on server $($Server.Name). Aborting rollback on the server $($Server.Name) for VDir $SiteVDirLocation." -ForegroundColor Red
                    $Failed = $true
                }

                if ($Failed) {
                    $FailedServers[$SiteVDirLocation] += $Server.Name
                }
            }
        }
    } end {
        foreach ($SiteVDirLocation in $SiteVDirLocations) {
            if ($FailedServers[$SiteVDirLocation].Length -gt 0) {
                Write-Host ("Unable to rollback for VDir $SiteVDirLocation on the following servers: {0}" -f [string]::Join(", ", $FailedServers[$SiteVDirLocation])) -ForegroundColor Red
            }
        }
    }
}



function Get-ExtendedProtectionConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Xml.XmlNode]$ApplicationHostConfig,

        [Parameter(Mandatory = $false)]
        [System.Version]$ExSetupVersion,

        [Parameter(Mandatory = $false)]
        [bool]$IsMailboxServer = $true,

        [Parameter(Mandatory = $false)]
        [bool]$IsClientAccessServer = $true,

        [Parameter(Mandatory = $false)]
        [bool]$ExcludeEWS = $false,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Exchange Back End/EWS")]
        [string[]]$SiteVDirLocations,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    begin {
        function NewVirtualDirMatchingEntry {
            param(
                [Parameter(Mandatory = $true)]
                [string]$VirtualDirectory,
                [Parameter(Mandatory = $true)]
                [ValidateSet("Default Web Site", "Exchange Back End")]
                [string[]]$WebSite,
                [Parameter(Mandatory = $true)]
                [ValidateSet("None", "Allow", "Require")]
                [string[]]$ExtendedProtection,
                # Need to define this twice once for Default Web Site and Exchange Back End for the default values
                [Parameter(Mandatory = $false)]
                [string[]]$SslFlags = @("Ssl,Ssl128", "Ssl,Ssl128")
            )

            if ($WebSite.Count -ne $ExtendedProtection.Count) {
                throw "Argument count mismatch on $VirtualDirectory"
            }

            for ($i = 0; $i -lt $WebSite.Count; $i++) {
                # special conditions for Exchange 2013
                # powershell is on front and back so skip over those
                if ($IsExchange2013 -and $virtualDirectory -ne "Powershell") {
                    # No API virtual directory
                    if ($virtualDirectory -eq "API") { return }
                    if ($IsClientAccessServer -eq $false -and $WebSite[$i] -eq "Default Web Site") { continue }
                    if ($IsMailboxServer -eq $false -and $WebSite[$i] -eq "Exchange Back End") { continue }
                }
                # Set EWS VDir to None for known issues
                if ($ExcludeEWS -and $virtualDirectory -eq "EWS") { $ExtendedProtection[$i] = "None" }

                if ($null -ne $SiteVDirLocations -and
                    $SiteVDirLocations.Count -gt 0) {
                    foreach ($SiteVDirLocation in $SiteVDirLocations) {
                        if ($SiteVDirLocation -eq "$($WebSite[$i])/$virtualDirectory") {
                            Write-Verbose "Set Extended Protection to None because of restriction override '$($WebSite[$i])\$virtualDirectory'"
                            $ExtendedProtection[$i] = "None"
                            break;
                        }
                    }
                }

                [PSCustomObject]@{
                    VirtualDirectory   = $virtualDirectory
                    WebSite            = $WebSite[$i]
                    ExtendedProtection = $ExtendedProtection[$i]
                    SslFlags           = $SslFlags[$i]
                }
            }
        }

        # Intended for inside of Invoke-Command.
        function GetApplicationHostConfig {
            $appHostConfig = New-Object -TypeName Xml
            try {
                $appHostConfigPath = "$($env:WINDIR)\System32\inetSrv\config\applicationHost.config"
                $appHostConfig.Load($appHostConfigPath)
            } catch {
                Write-Verbose "Failed to loaded application host config file. $_"
                $appHostConfig = $null
            }
            return $appHostConfig
        }

        function GetExtendedProtectionConfiguration {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [System.Xml.XmlNode]$Xml,
                [Parameter(Mandatory = $true)]
                [string]$Path
            )
            process {
                try {
                    $nodePath = [string]::Empty
                    $extendedProtection = "None"
                    $ipRestrictionsHashTable = @{}
                    $pathIndex = [array]::IndexOf(($Xml.configuration.location.path).ToLower(), $Path.ToLower())
                    $rootIndex = [array]::IndexOf(($Xml.configuration.location.path).ToLower(), ($Path.Split("/")[0]).ToLower())

                    if ($pathIndex -ne -1) {
                        $configNode = $Xml.configuration.location[$pathIndex]
                        $nodePath = $configNode.Path
                        $ep = $configNode.'system.webServer'.security.authentication.windowsAuthentication.extendedProtection.tokenChecking
                        $ipRestrictions = $configNode.'system.webServer'.security.ipSecurity

                        if (-not ([string]::IsNullOrEmpty($ep))) {
                            Write-Verbose "Found tokenChecking: $ep"
                            $extendedProtection = $ep
                        } else {
                            Write-Verbose "Failed to find tokenChecking. Using default value of None."
                        }

                        [string]$sslSettings = $configNode.'system.webServer'.security.access.sslFlags

                        if ([string]::IsNullOrEmpty($sslSettings)) {
                            Write-Verbose "Failed to find SSL settings for the path. Falling back to the root."

                            if ($rootIndex -ne -1) {
                                Write-Verbose "Found root path."
                                $rootConfigNode = $Xml.configuration.location[$rootIndex]
                                [string]$sslSettings = $rootConfigNode.'system.webServer'.security.access.sslFlags
                            }
                        }

                        if (-not([string]::IsNullOrEmpty($ipRestrictions))) {
                            Write-Verbose "IP-filtered restrictions detected"
                            foreach ($restriction in $ipRestrictions.add) {
                                $ipRestrictionsHashTable.Add($restriction.ipAddress, $restriction.allowed)
                            }
                        }

                        Write-Verbose "SSLSettings: $sslSettings"

                        if ($null -ne $sslSettings) {
                            [array]$sslFlags = ($sslSettings.Split(",").ToLower()).Trim()
                        } else {
                            $sslFlags = $null
                        }

                        # SSL flags: https://docs.microsoft.com/iis/configuration/system.webserver/security/access#attributes
                        $requireSsl = $false
                        $ssl128Bit = $false
                        $clientCertificate = "Unknown"

                        if ($null -eq $sslFlags) {
                            Write-Verbose "Failed to find SSLFlags"
                        } elseif ($sslFlags.Contains("none")) {
                            $clientCertificate = "Ignore"
                        } else {
                            if ($sslFlags.Contains("ssl")) { $requireSsl = $true }
                            if ($sslFlags.Contains("ssl128")) { $ssl128Bit = $true }
                            if ($sslFlags.Contains("sslNegotiateCert".ToLower())) {
                                $clientCertificate = "Accept"
                            } elseif ($sslFlags.Contains("sslRequireCert".ToLower())) {
                                $clientCertificate = "Require"
                            } else {
                                $clientCertificate = "Ignore"
                            }
                        }
                    }
                } catch {
                    Write-Verbose "Ran into some error trying to parse the application host config for $Path."
                    Invoke-CatchActionError $CatchActionFunction
                }
            } end {
                return [PSCustomObject]@{
                    ExtendedProtection = $extendedProtection
                    ValidPath          = ($pathIndex -ne -1)
                    NodePath           = $nodePath
                    SslSettings        = [PSCustomObject]@{
                        RequireSsl        = $requireSsl
                        Ssl128Bit         = $ssl128Bit
                        ClientCertificate = $clientCertificate
                        Value             = $sslSettings
                    }
                    MitigationSettings = [PScustomObject]@{
                        AllowUnlisted = $ipRestrictions.allowUnlisted
                        Restrictions  = $ipRestrictionsHashTable
                    }
                }
            }
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $computerResult = Invoke-ScriptBlockHandler -ComputerName $ComputerName -ScriptBlock { return $env:COMPUTERNAME }
        $serverConnected = $null -ne $computerResult

        if ($null -eq $computerResult) {
            Write-Verbose "Failed to connect to server $ComputerName"
            return
        }

        if ($null -eq $ExSetupVersion) {
            [System.Version]$ExSetupVersion = Invoke-ScriptBlockHandler -ComputerName $ComputerName -ScriptBlock {
                (Get-Command ExSetup.exe |
                    ForEach-Object { $_.FileVersionInfo } |
                    Select-Object -First 1).FileVersion
            }

            if ($null -eq $ExSetupVersion) {
                throw "Failed to determine Exchange build number"
            }
        } else {
            # Hopefully the caller knows what they are doing, best be from the correct server!!
            Write-Verbose "Caller passed the ExSetupVersion information"
        }

        if ($null -eq $ApplicationHostConfig) {
            Write-Verbose "Trying to load the application host config from $ComputerName"
            $params = @{
                ComputerName        = $ComputerName
                ScriptBlock         = ${Function:GetApplicationHostConfig}
                CatchActionFunction = $CatchActionFunction
            }

            $ApplicationHostConfig = Invoke-ScriptBlockHandler @params

            if ($null -eq $ApplicationHostConfig) {
                throw "Failed to load application host config from $ComputerName"
            }
        } else {
            # Hopefully the caller knows what they are doing, best be from the correct server!!
            Write-Verbose "Caller passed the application host config."
        }

        $default = "Default Web Site"
        $backend = "Exchange Back End"
        $Script:IsExchange2013 = $ExSetupVersion.Major -eq 15 -and $ExSetupVersion.Minor -eq 0
        try {
            $VirtualDirectoryMatchEntries = @(
                (NewVirtualDirMatchingEntry "API" -WebSite $default, $backend -ExtendedProtection "Require", "Require")
                (NewVirtualDirMatchingEntry "Autodiscover" -WebSite $default, $backend -ExtendedProtection "None", "None")
                (NewVirtualDirMatchingEntry "ECP" -WebSite $default, $backend -ExtendedProtection "Require", "Require")
                (NewVirtualDirMatchingEntry "EWS" -WebSite $default, $backend -ExtendedProtection "Allow", "Require")
                (NewVirtualDirMatchingEntry "Microsoft-Server-ActiveSync" -WebSite $default, $backend -ExtendedProtection "Allow", "Require")
                (NewVirtualDirMatchingEntry "OAB" -WebSite $default, $backend -ExtendedProtection "Require", "Require")
                (NewVirtualDirMatchingEntry "Powershell" -WebSite $default, $backend -ExtendedProtection "Require", "Require" -SslFlags "SslNegotiateCert", "Ssl,Ssl128,SslNegotiateCert")
                (NewVirtualDirMatchingEntry "OWA" -WebSite $default, $backend -ExtendedProtection "Require", "Require")
                (NewVirtualDirMatchingEntry "RPC" -WebSite $default, $backend -ExtendedProtection "Require", "Require")
                (NewVirtualDirMatchingEntry "MAPI" -WebSite $default -ExtendedProtection "Require")
                (NewVirtualDirMatchingEntry "PushNotifications" -WebSite $backend -ExtendedProtection "Require")
                (NewVirtualDirMatchingEntry "RPCWithCert" -WebSite $backend -ExtendedProtection "Require")
                (NewVirtualDirMatchingEntry "MAPI/emsmdb" -WebSite $backend -ExtendedProtection "Require")
                (NewVirtualDirMatchingEntry "MAPI/nspi" -WebSite $backend -ExtendedProtection "Require")
            )
        } catch {
            # Don't handle with Catch Error as this is a bug in the script.
            throw "Failed to create NewVirtualDirMatchingEntry. Inner Exception $_"
        }

        # Is Supported build of Exchange to have the configuration set.
        # Edge Server is not accounted for. It is the caller's job to not try to collect this info on Edge.
        $supportedVersion = $false
        $extendedProtectionList = New-Object 'System.Collections.Generic.List[object]'

        if ($ExSetupVersion.Major -eq 15) {
            if ($ExSetupVersion.Minor -eq 2) {
                $supportedVersion = $ExSetupVersion.Build -gt 1118 -or
                ($ExSetupVersion.Build -eq 1118 -and $ExSetupVersion.Revision -ge 11) -or
                ($ExSetupVersion.Build -eq 986 -and $ExSetupVersion.Revision -ge 28)
            } elseif ($ExSetupVersion.Minor -eq 1) {
                $supportedVersion = $ExSetupVersion.Build -gt 2507 -or
                ($ExSetupVersion.Build -eq 2507 -and $ExSetupVersion.Revision -ge 11) -or
                ($ExSetupVersion.Build -eq 2375 -and $ExSetupVersion.Revision -ge 30)
            } elseif ($ExSetupVersion.Minor -eq 0) {
                $supportedVersion = $ExSetupVersion.Build -gt 1497 -or
                ($ExSetupVersion.Build -eq 1497 -and $ExSetupVersion.Revision -ge 38)
            }
            Write-Verbose "Build $ExSetupVersion is supported: $supportedVersion"
        } else {
            Write-Verbose "Not on Exchange Version 15"
        }

        # Add all vDirs for which the IP filtering mitigation is supported
        $mitigationSupportedVDirs = $MyInvocation.MyCommand.Parameters["SiteVDirLocations"].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
            ForEach-Object { return $_.ValidValues.ToLower() }
        Write-Verbose "Supported mitigated virtual directories: $([string]::Join(",", $mitigationSupportedVDirs))"
    }
    process {
        try {
            foreach ($matchEntry in $VirtualDirectoryMatchEntries) {
                try {
                    Write-Verbose "Verify extended protection setting for $($matchEntry.VirtualDirectory) on web site $($matchEntry.WebSite)"

                    $extendedConfiguration = GetExtendedProtectionConfiguration -Xml $applicationHostConfig -Path "$($matchEntry.WebSite)/$($matchEntry.VirtualDirectory)"

                    # Extended Protection is a windows security feature which blocks MiTM attacks.
                    # Supported server roles are: Mailbox and ClientAccess
                    # Possible configuration settings are:
                    # <None>: This value specifies that IIS will not perform channel-binding token checking.
                    # <Allow>: This value specifies that channel-binding token checking is enabled, but not required.
                    # <Require>: This value specifies that channel-binding token checking is required.
                    # https://docs.microsoft.com/iis/configuration/system.webserver/security/authentication/windowsauthentication/extendedprotection/

                    if ($extendedConfiguration.ValidPath) {
                        Write-Verbose "Configuration was successfully returned: $($extendedConfiguration.ExtendedProtection)"
                    } else {
                        Write-Verbose "Extended protection setting was not queried because it wasn't found on the system."
                    }

                    $sslFlagsToSet = $extendedConfiguration.SslSettings.Value
                    $currentSetFlags = $sslFlagsToSet.Split(",").Trim()
                    foreach ($sslFlag in $matchEntry.SslFlags.Split(",").Trim()) {
                        if (-not($currentSetFlags.Contains($sslFlag))) {
                            Write-Verbose "Failed to find SSL Flag $sslFlag"
                            # We do not want to include None in the flags as that takes priority over the other options.
                            if ($sslFlagsToSet -eq "None") {
                                $sslFlagsToSet = "$sslFlag"
                            } else {
                                $sslFlagsToSet += ",$sslFlag"
                            }
                            Write-Verbose "Updated SSL Flags Value: $sslFlagsToSet"
                        } else {
                            Write-Verbose "SSL Flag $sslFlag set."
                        }
                    }

                    $expectedExtendedConfiguration = if ($supportedVersion) { $matchEntry.ExtendedProtection } else { "None" }
                    $virtualDirectoryName = "$($matchEntry.WebSite)/$($matchEntry.VirtualDirectory)"

                    # Properly Secured Configuration is only a concern if Required is the Expected value
                    # If the Expected value is None or Allow, you can have it configured however you would like and from a security standpoint, it shouldn't be a concern.
                    # For a mitigation scenario, like EWS BE, Required is the Expected value. Therefore, on those directories, we need to verify that IP filtering is set if not set to Require.
                    if ($expectedExtendedConfiguration -eq "Require") {
                        $properlySecuredConfiguration = $expectedExtendedConfiguration -eq $extendedConfiguration.ExtendedProtection

                        if ($properlySecuredConfiguration -eq $false) {
                            # Only care about virtual directories that we allow mitigation for
                            $properlySecuredConfiguration = $mitigationSupportedVDirs.Contains($virtualDirectoryName.ToLower()) -and
                            $extendedConfiguration.MitigationSettings.AllowUnlisted -eq "false"
                        }
                    } else {
                        $properlySecuredConfiguration = $true
                    }

                    $extendedProtectionList.Add([PSCustomObject]@{
                            VirtualDirectoryName          = $virtualDirectoryName
                            Configuration                 = $extendedConfiguration
                            ExtendedProtection            = $extendedConfiguration.ExtendedProtection
                            SupportedExtendedProtection   = $expectedExtendedConfiguration -eq $extendedConfiguration.ExtendedProtection
                            ExpectedExtendedConfiguration = $expectedExtendedConfiguration
                            MitigationEnabled             = ($extendedConfiguration.MitigationSettings.AllowUnlisted -eq "false")
                            MitigationSupported           = $mitigationSupportedVDirs.Contains($virtualDirectoryName.ToLower())
                            ProperlySecuredConfiguration  = $properlySecuredConfiguration
                            ExpectedSslFlags              = $matchEntry.SslFlags
                            SslFlagsSetCorrectly          = $sslFlagsToSet.Split(",").Count -eq $currentSetFlags.Count
                            SslFlagsToSet                 = $sslFlagsToSet
                        })
                } catch {
                    Write-Verbose "Failed to get extended protection match entry."
                    Invoke-CatchActionError $CatchActionFunction
                }
            }
        } catch {
            Write-Verbose "Failed to get get extended protection."
            Invoke-CatchActionError $CatchActionFunction
        }
    }
    end {
        return [PSCustomObject]@{
            ComputerName                          = $ComputerName
            ServerConnected                       = $serverConnected
            SupportedVersionForExtendedProtection = $supportedVersion
            ApplicationHostConfig                 = $ApplicationHostConfig
            ExtendedProtectionConfiguration       = $extendedProtectionList
            ExtendedProtectionConfigured          = $null -ne ($extendedProtectionList.ExtendedProtection | Where-Object { $_ -ne "None" })
        }
    }
}

function Invoke-ConfigureExtendedProtection {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [object[]]$ExtendedProtectionConfigurations
    )

    begin {
        $failedServers = New-Object 'System.Collections.Generic.List[string]'
        $noChangesMadeServers = New-Object 'System.Collections.Generic.List[string]'
        $updatedServers = New-Object 'System.Collections.Generic.List[string]'
        $counter = 0
        $totalCount = $ExtendedProtectionConfigurations.Count
        $progressParams = @{
            Id              = 1
            Activity        = "Configuring Extended Protection"
            Status          = [string]::Empty
            PercentComplete = 0
        }
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    } process {
        foreach ($serverExtendedProtection in $ExtendedProtectionConfigurations) {
            $counter++
            # Check to make sure server is connected and valid information is provided.
            if (-not ($serverExtendedProtection.ServerConnected)) {
                $line = "$($serverExtendedProtection.ComputerName): Server not online. Cannot get Extended Protection configuration settings."
                Write-Verbose $line
                Write-Warning $line
                $failedServers.Add($serverExtendedProtection.ComputerName)
                continue
            }

            if ($serverExtendedProtection.ExtendedProtectionConfiguration.Count -eq 0) {
                $line = "$($serverExtendedProtection.ComputerName): Server wasn't able to collect Extended Protection configuration."
                Write-Verbose $line
                Write-Warning $line
                continue
            }

            # set the extended protection (TokenChecking) configuration to the expected and supported configuration if different
            # only Set SSLFlags option if we are not setting extended protection to None
            $commandParameters = [PSCustomObject]@{
                TokenChecking = @{}
                SSLFlags      = @{}
            }

            $baseStatus = "Processing: $($serverExtendedProtection.ComputerName) -"
            $progressParams.PercentComplete = ($counter / $totalCount * 100)
            $progressParams.Status = "$baseStatus Evaluating Extended Protection Settings"
            Write-Progress @progressParams

            foreach ($virtualDirectory in $serverExtendedProtection.ExtendedProtectionConfiguration) {
                Write-Verbose "$($serverExtendedProtection.ComputerName): Virtual Directory Name: $($virtualDirectory.VirtualDirectoryName) Current Set Extended Protection: $($virtualDirectory.ExtendedProtection) Expected Value $($virtualDirectory.ExpectedExtendedConfiguration)"
                Write-Verbose "$($serverExtendedProtection.ComputerName): Current Set SSL Flags: $($virtualDirectory.Configuration.SslSettings.Value) Expected SSL Flags: $($virtualDirectory.ExpectedSslFlags) Set Correctly: $($virtualDirectory.SslFlagsSetCorrectly)"
                if ($virtualDirectory.ExtendedProtection -ne $virtualDirectory.ExpectedExtendedConfiguration) {
                    $commandParameters.TokenChecking.Add($virtualDirectory.VirtualDirectoryName, $virtualDirectory.ExpectedExtendedConfiguration)

                    if ($virtualDirectory.ExpectedExtendedConfiguration -ne "None" -and
                        $virtualDirectory.SslFlagsSetCorrectly -eq $false) {
                        $commandParameters.SSLFlags.Add($virtualDirectory.VirtualDirectoryName, $virtualDirectory.SslFlagsToSet)
                    }
                }
            }

            if ($commandParameters.TokenChecking.Count -gt 0) {
                $progressParams.Status = "$baseStatus Executing Actions on Server"
                Write-Progress @progressParams
                Write-Host "$($serverExtendedProtection.ComputerName): Backing up applicationHost.config."
                # provide what we are changing outside of the script block for remote servers.
                $commandParameters.TokenChecking.Keys | ForEach-Object { Write-Verbose "$($serverExtendedProtection.ComputerName): Setting the $_ with the tokenChecking value of $($commandParameters.TokenChecking[$_])" }
                $commandParameters.SSLFlags.Keys | ForEach-Object { Write-Verbose "$($serverExtendedProtection.ComputerName): Setting the $_ with the SSLFlags value of $($commandParameters.SSLFlags[$_])" }
                $results = Invoke-ScriptBlockHandler -ComputerName $serverExtendedProtection.ComputerName -ScriptBlock {
                    param(
                        [object]$Commands,
                        [bool]$PassedWhatIf
                    )
                    $saveToPath = "$($env:WINDIR)\System32\inetSrv\config\applicationHost.config"
                    $backupLocation = $saveToPath.Replace(".config", ".cep.$([DateTime]::Now.ToString("yyyyMMddHHMMss")).bak")
                    $internalTotalCommands = $Commands.TokenChecking.Count + $Commands.SSLFlags.Count
                    $internalCounter = 0
                    $internalProgressParams = @{
                        ParentId        = 1
                        Activity        = "Executing Actions on $env:ComputerName"
                        Status          = "Backing Up ApplicationHost.Config"
                        PercentComplete = 0
                    }
                    Write-Progress @internalProgressParams
                    try {
                        $backupSuccessful = $false
                        Copy-Item -Path $saveToPath -Destination $backupLocation -ErrorAction Stop -WhatIf:$PassedWhatIf
                        $backupSuccessful = $true
                        $errorContext = New-Object 'System.Collections.Generic.List[object]'
                        $setAllTokenChecking = $true
                        $setAllSslFlags = $true
                        Write-Host "$($env:COMPUTERNAME): Successful backup to $backupLocation"
                        foreach ($siteKey in $Commands.TokenChecking.Keys) {
                            $internalCounter++
                            $internalProgressParams.Status = "Setting TokenChecking for $siteKey"
                            $internalProgressParams.PercentComplete = ($internalCounter / $internalTotalCommands * 100)
                            Write-Progress @internalProgressParams
                            try {
                                $params = @{
                                    Filter      = "system.WebServer/security/authentication/windowsAuthentication"
                                    Name        = "extendedProtection.tokenChecking"
                                    Value       = $Commands.TokenChecking[$siteKey]
                                    Location    = $siteKey
                                    PSPath      = "IIS:\"
                                    ErrorAction = "Stop"
                                    WhatIf      = $PassedWhatIf
                                }
                                Set-WebConfigurationProperty @params
                            } catch {
                                Write-Host "$($env:COMPUTERNAME): Failed to set tokenChecking for $siteKey with the value $($Commands.TokenChecking[$siteKey]). Inner Exception $_"
                                $setAllTokenChecking = $false
                                $errorContext.Add($_)
                            }
                        }
                        foreach ($siteKey in $Commands.SSLFlags.Keys) {
                            try {
                                $internalCounter++
                                $internalProgressParams.Status = "Setting SSLFlags for $siteKey"
                                $internalProgressParams.PercentComplete = ($internalCounter / $internalTotalCommands * 100)
                                Write-Progress @internalProgressParams
                                $params = @{
                                    Filter      = "system.WebServer/security/access"
                                    Name        = "sslFlags"
                                    Value       = $Commands.SSLFlags[$siteKey]
                                    Location    = $siteKey
                                    PSPath      = "IIS:\"
                                    ErrorAction = "Stop"
                                    WhatIf      = $PassedWhatIf
                                }
                                Set-WebConfigurationProperty @params
                            } catch {
                                Write-Host "$($env:COMPUTERNAME): Failed to set sslFlags for $siteKey with the value $($Commands.SSLFlags[$siteKey]). Inner Exception $_"
                                $setAllSslFlags = $false
                                $errorContext.Add($_)
                            }
                        }
                        # Save out our changes
                        Copy-Item -Path $saveToPath -Destination $backupLocation.Replace(".cep.", ".cepChanges") -ErrorAction Stop -WhatIf:$PassedWhatIf
                    } catch {
                        Write-Host "$($env:COMPUTERNAME): Failed to backup applicationHost.config. Inner Exception $_"
                    }
                    Write-Progress @internalProgressParams -Completed
                    return [PSCustomObject]@{
                        BackupSuccess       = $backupSuccessful
                        BackupLocation      = $backupLocation
                        SetAllTokenChecking = $setAllTokenChecking
                        SetAllSslFlags      = $setAllSslFlags
                        ErrorContext        = $errorContext
                    }
                } -ArgumentList $commandParameters, $WhatIfPreference

                Write-Verbose "$($serverExtendedProtection.ComputerName): Backup Success: $($results.BackupSuccess) SetAllTokenChecking: $($results.SetAllTokenChecking) SetAllSslFlags: $($results.SetAllSslFlags)"

                if ($results.BackupSuccess -and ($results.SetAllTokenChecking -and $results.SetAllSslFlags)) {
                    Write-Verbose "$($serverExtendedProtection.ComputerName): Backed up the file to $($results.BackupLocation)"
                    Write-Host "$($serverExtendedProtection.ComputerName): Successfully updated applicationHost.config."
                    $updatedServers.Add($serverExtendedProtection.ComputerName)
                    continue
                } elseif ($results.BackupSuccess -eq $false) {
                    $line = "$($serverExtendedProtection.ComputerName): Failed to backup the applicationHost.config. No settings were applied."
                    Write-Verbose $line
                    Write-Warning $line
                } else {
                    $line = "$($serverExtendedProtection.ComputerName): Failed to set the values required for Extended Protection."
                    Write-Verbose $line
                    Write-Warning $line
                }
                $failedServers.Add($serverExtendedProtection.ComputerName)
                $results.ErrorContext | ForEach-Object { Write-HostErrorInformation "$($serverExtendedProtection.ComputerName): $_" }
                Write-Host ""
            } else {
                Write-Host "$($serverExtendedProtection.ComputerName): No changes made. Exchange build supports Extended Protection? $($serverExtendedProtection.SupportedVersionForExtendedProtection)"
                $noChangesMadeServers.Add($serverExtendedProtection.ComputerName)
            }
        }
    } end {
        Write-Progress @progressParams -Completed
        Write-Host ""
        if ($failedServers.Count -gt 0) {
            $line = "Failed to enable Extended Protection: $([string]::Join(", " ,$failedServers))"
            Write-Verbose $line
            Write-Warning $line
        }

        if ($noChangesMadeServers.Count -gt 0) {
            Write-Host "No changes made: $([string]::Join(", " ,$noChangesMadeServers))"
        }

        if ($updatedServers.Count -gt 0 ) {
            Write-Host "Successfully enabled Extended Protection: $([string]::Join(", " ,$updatedServers))"
        }
    }
}


function Invoke-RollbackExtendedProtection {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string[]]$ExchangeServers
    )
    begin {
        $failedServers = New-Object 'System.Collections.Generic.List[string]'
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    } process {
        foreach ($server in $ExchangeServers) {
            Write-Host "Attempting to rollback on $server"
            $results = Invoke-ScriptBlockHandler -ComputerName $server -ScriptBlock {
                param(
                    [bool]$PassedWhatIf
                )
                try {
                    $saveToPath = "$($env:WINDIR)\System32\inetSrv\config\applicationHost.config"
                    $backupLocation = $saveToPath.Replace(".config", ".revert.cep.$([DateTime]::Now.ToString("yyyyMMddHHMMss")).bak")
                    $restoreFile = (Get-ChildItem "$($env:WINDIR)\System32\inetSrv\config\" -Filter "*applicationHost.cep.*.bak" | Sort-Object CreationTime | Select-Object -First 1).FullName
                    $successRestore = $false
                    $successBackupCurrent = $false

                    if ($null -eq $restoreFile) {
                        throw "Failed to find applicationHost.cep.*.bak file."
                    }

                    Copy-Item -Path $saveToPath -Destination $backupLocation -ErrorAction Stop -WhatIf:$PassedWhatIf
                    $successBackupCurrent = $true
                    Copy-Item -Path $restoreFile -Destination $saveToPath -Force -ErrorAction Stop -WhatIf:$PassedWhatIf
                    $successRestore = $true
                } catch {
                    Write-Host "Failed to restore application host file on server $env:COMPUTERNAME. Inner Exception $_"
                }
                return [PSCustomObject]@{
                    RestoreFile          = $restoreFile
                    SuccessRestore       = $successRestore
                    SuccessBackupCurrent = $successBackupCurrent
                    ErrorContext         = $Error[0]
                }
            } -ArgumentList $WhatIfPreference

            if ($results.SuccessRestore -and $results.SuccessBackupCurrent) {
                Write-Host "Successful restored $($results.RestoreFile) on server $server"
                continue
            } elseif ($results.SuccessBackupCurrent -eq $false) {
                $line = "Failed to backup the current configuration on server $server"
                Write-Verbose $line
                Write-Warning $line
            } elseif ($null -eq $results) {
                $line = "Failed to restore application host config file on server $server, because we weren't able to reach it."
                Write-Verbose $line
                Write-Warning $line
                # need to add to list and continue because there is no error context
                $failedServers.Add($server)
                continue
            } else {
                $line = "Failed to restore $($results.RestoreFile) to be the active application host config file on server $server"
                Write-Verbose $line
                Write-Warning $line
            }
            $failedServers.Add($server)
            Start-Sleep 1
            Write-HostErrorInformation $results.ErrorContext
            Write-Host ""
        }
    } end {
        if ($failedServers.Count -gt 0) {
            $line = "These are the servers that failed to rollback: $([string]::Join(", " ,$failedServers))"
            Write-Verbose $line
            Write-Warning $line
        }
    }
}


function Get-WmiObjectHandler {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '', Justification = 'This is what this function is for')]
    [CmdletBinding()]
    param(
        [string]
        $ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $true)]
        [string]
        $Class,

        [string]
        $Filter,

        [string]
        $Namespace,

        [ScriptBlock]
        $CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Passed - ComputerName: '$ComputerName' | Class: '$Class' | Filter: '$Filter' | Namespace: '$Namespace'"

        $execute = @{
            ComputerName = $ComputerName
            Class        = $Class
        }

        if (-not ([string]::IsNullOrEmpty($Filter))) {
            $execute.Add("Filter", $Filter)
        }

        if (-not ([string]::IsNullOrEmpty($Namespace))) {
            $execute.Add("Namespace", $Namespace)
        }
    }
    process {
        try {
            $wmi = Get-WmiObject @execute -ErrorAction Stop
            return $wmi
        } catch {
            Write-Verbose "Failed to run Get-WmiObject on class '$class'"

            if ($null -ne $CatchActionFunction) {
                & $CatchActionFunction
            }
        }
    }
}

function Get-RemoteRegistrySubKey {
    [CmdletBinding()]
    param(
        [string]$RegistryHive = "LocalMachine",
        [string]$MachineName,
        [string]$SubKey,
        [ScriptBlock]$CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Attempting to open the Base Key $RegistryHive on Machine $MachineName"
        $regKey = $null
    }
    process {

        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegistryHive, $MachineName)
            Write-Verbose "Attempting to open the Sub Key '$SubKey'"
            $regKey = $reg.OpenSubKey($SubKey)
            Write-Verbose "Opened Sub Key"
        } catch {
            Write-Verbose "Failed to open the registry"

            if ($null -ne $CatchActionFunction) {
                & $CatchActionFunction
            }
        }
    }
    end {
        return $regKey
    }
}


function Get-RemoteRegistryValue {
    [CmdletBinding()]
    param(
        [string]$RegistryHive = "LocalMachine",
        [string]$MachineName,
        [string]$SubKey,
        [string]$GetValue,
        [string]$ValueType,
        [ScriptBlock]$CatchActionFunction
    )

    <#
    Valid ValueType return values (case-sensitive)
    (https://docs.microsoft.com/en-us/dotnet/api/microsoft.win32.registryvaluekind?view=net-5.0)
    Binary = REG_BINARY
    DWord = REG_DWORD
    ExpandString = REG_EXPAND_SZ
    MultiString = REG_MULTI_SZ
    None = No data type
    QWord = REG_QWORD
    String = REG_SZ
    Unknown = An unsupported registry data type
    #>

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $registryGetValue = $null
    }
    process {

        try {

            $regSubKey = Get-RemoteRegistrySubKey -RegistryHive $RegistryHive `
                -MachineName $MachineName `
                -SubKey $SubKey

            if (-not ([System.String]::IsNullOrWhiteSpace($regSubKey))) {
                Write-Verbose "Attempting to get the value $GetValue"
                $registryGetValue = $regSubKey.GetValue($GetValue)
                Write-Verbose "Finished running GetValue()"

                if ($null -ne $registryGetValue -and
                    (-not ([System.String]::IsNullOrWhiteSpace($ValueType)))) {
                    Write-Verbose "Validating ValueType $ValueType"
                    $registryValueType = $regSubKey.GetValueKind($GetValue)
                    Write-Verbose "Finished running GetValueKind()"

                    if ($ValueType -ne $registryValueType) {
                        Write-Verbose "ValueType: $ValueType is different to the returned ValueType: $registryValueType"
                        $registryGetValue = $null
                    } else {
                        Write-Verbose "ValueType matches: $ValueType"
                    }
                }
            }
        } catch {
            Write-Verbose "Failed to get the value on the registry"

            if ($null -ne $CatchActionFunction) {
                & $CatchActionFunction
            }
        }
    }
    end {
        if ($registryGetValue.Length -le 100) {
            Write-Verbose "$($MyInvocation.MyCommand) Return Value: '$registryGetValue'"
        } else {
            Write-Verbose "$($MyInvocation.MyCommand) Return Value is too long to log"
        }
        return $registryGetValue
    }
}

function Invoke-CatchActionErrorLoop {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [int]$CurrentErrors,
        [Parameter(Mandatory = $false, Position = 1)]
        [ScriptBlock]$CatchActionFunction
    )
    process {
        if ($null -ne $CatchActionFunction -and
            $Error.Count -ne $CurrentErrors) {
            $i = 0
            while ($i -lt ($Error.Count - $currentErrors)) {
                & $CatchActionFunction $Error[$i]
                $i++
            }
        }
    }
}
function Get-AllNicInformation {
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [string]$ComputerFQDN,
        [ScriptBlock]$CatchActionFunction
    )
    begin {

        # Extract for Pester Testing - Start
        function Get-NicPnpCapabilitiesSetting {
            [CmdletBinding()]
            param(
                [ValidateNotNullOrEmpty()]
                [string]$NicAdapterComponentId
            )
            begin {
                $nicAdapterBasicPath = "SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}"
                [int]$i = 0
                Write-Verbose "Probing started to detect NIC adapter registry path"
            }
            process {
                $registrySubKey = Get-RemoteRegistrySubKey -MachineName $ComputerName -SubKey $nicAdapterBasicPath
                if ($null -ne $registrySubKey) {
                    $optionalKeys = $registrySubKey.GetSubKeyNames() | Where-Object { $_ -like "0*" }
                    do {
                        $nicAdapterPnPCapabilitiesProbingKey = "$nicAdapterBasicPath\$($optionalKeys[$i])"
                        $netCfgRemoteRegistryParams = @{
                            MachineName         = $ComputerName
                            SubKey              = $nicAdapterPnPCapabilitiesProbingKey
                            GetValue            = "NetCfgInstanceId"
                            CatchActionFunction = $CatchActionFunction
                        }
                        $netCfgInstanceId = Get-RemoteRegistryValue @netCfgRemoteRegistryParams

                        if ($netCfgInstanceId -eq $NicAdapterComponentId) {
                            Write-Verbose "Matching ComponentId found - now checking for PnPCapabilitiesValue"
                            $pnpRemoteRegistryParams = @{
                                MachineName         = $ComputerName
                                SubKey              = $nicAdapterPnPCapabilitiesProbingKey
                                GetValue            = "PnPCapabilities"
                                CatchActionFunction = $CatchActionFunction
                            }
                            $nicAdapterPnPCapabilitiesValue = Get-RemoteRegistryValue @pnpRemoteRegistryParams
                            break
                        } else {
                            Write-Verbose "No matching ComponentId found"
                            $i++
                        }
                    } while ($i -lt $optionalKeys.Count)
                }
            }
            end {
                return [PSCustomObject]@{
                    PnPCapabilities   = $nicAdapterPnPCapabilitiesValue
                    SleepyNicDisabled = ($nicAdapterPnPCapabilitiesValue -eq 24 -or $nicAdapterPnPCapabilitiesValue -eq 280)
                }
            }
        }

        # Extract for Pester Testing - End

        function Get-NetworkConfiguration {
            [CmdletBinding()]
            param(
                [string]$ComputerName
            )
            begin {
                $currentErrors = $Error.Count
                $params = @{
                    ErrorAction = "Stop"
                }
            }
            process {
                try {
                    if (($ComputerName).Split(".")[0] -ne $env:COMPUTERNAME) {
                        $cimSession = New-CimSession -ComputerName $ComputerName -ErrorAction Stop
                        $params.Add("CimSession", $cimSession)
                    }
                    $networkIpConfiguration = Get-NetIPConfiguration @params | Where-Object { $_.NetAdapter.MediaConnectionState -eq "Connected" }
                    Invoke-CatchActionErrorLoop -CurrentErrors $currentErrors -CatchActionFunction $CatchActionFunction
                    return $networkIpConfiguration
                } catch {
                    Write-Verbose "Failed to run Get-NetIPConfiguration. Error $($_.Exception)"
                    #just rethrow as caller will handle the catch
                    throw
                }
            }
        }

        function Get-NicInformation {
            [CmdletBinding()]
            param(
                [array]$NetworkConfiguration,
                [bool]$WmiObject
            )
            begin {

                function Get-IpvAddresses {
                    return [PSCustomObject]@{
                        Address        = ([string]::Empty)
                        Subnet         = ([string]::Empty)
                        DefaultGateway = ([string]::Empty)
                    }
                }

                if ($null -eq $NetworkConfiguration) {
                    Write-Verbose "NetworkConfiguration are null in New-NicInformation. Returning a null object."
                    return $null
                }

                $nicObjects = New-Object 'System.Collections.Generic.List[object]'
            }
            process {
                if ($WmiObject) {
                    $networkAdapterConfigurationsParams = @{
                        ComputerName        = $ComputerName
                        Class               = "Win32_NetworkAdapterConfiguration"
                        Filter              = "IPEnabled = True"
                        CatchActionFunction = $CatchActionFunction
                    }
                    $networkAdapterConfigurations = Get-WmiObjectHandler @networkAdapterConfigurationsParams
                }

                foreach ($networkConfig in $NetworkConfiguration) {
                    $dnsClient = $null
                    $rssEnabledValue = 2
                    $netAdapterRss = $null
                    $mtuSize = 0
                    $driverDate = [DateTime]::MaxValue
                    $driverVersion = [string]::Empty
                    $description = [string]::Empty
                    $ipv4Address = @()
                    $ipv6Address = @()
                    $ipv6Enabled = $false

                    if (-not ($WmiObject)) {
                        Write-Verbose "Working on NIC: $($networkConfig.InterfaceDescription)"
                        $adapter = $networkConfig.NetAdapter

                        if ($adapter.DriverFileName -ne "NdIsImPlatform.sys") {
                            $nicPnpCapabilitiesSetting = Get-NicPnpCapabilitiesSetting -NicAdapterComponentId $adapter.DeviceID
                        } else {
                            Write-Verbose "Multiplexor adapter detected. Going to skip PnpCapabilities check"
                            $nicPnpCapabilitiesSetting = [PSCustomObject]@{
                                PnPCapabilities = "MultiplexorNoPnP"
                            }
                        }

                        try {
                            $dnsClient = $adapter | Get-DnsClient -ErrorAction Stop
                            $isRegisteredInDns = $dnsClient.RegisterThisConnectionsAddress
                            Write-Verbose "Got DNS Client information"
                        } catch {
                            Write-Verbose "Failed to get the DNS client information"
                            Invoke-CatchActionError $CatchActionFunction
                        }

                        try {
                            $netAdapterRss = $adapter | Get-NetAdapterRss -ErrorAction Stop
                            Write-Verbose "Got Net Adapter RSS Information"

                            if ($null -ne $netAdapterRss) {
                                [int]$rssEnabledValue = $netAdapterRss.Enabled
                            }
                        } catch {
                            Write-Verbose "Failed to get RSS Information"
                            Invoke-CatchActionError $CatchActionFunction
                        }

                        foreach ($ipAddress in $networkConfig.AllIPAddresses.IPAddress) {
                            if ($ipAddress.Contains(":")) {
                                $ipv6Enabled = $true
                            }
                        }

                        for ($i = 0; $i -lt $networkConfig.IPv4Address.Count; $i++) {
                            $newIpvAddress = Get-IpvAddresses

                            if ($null -ne $networkConfig.IPv4Address -and
                                $i -lt $networkConfig.IPv4Address.Count) {
                                $newIpvAddress.Address = $networkConfig.IPv4Address[$i].IPAddress
                                $newIpvAddress.Subnet = $networkConfig.IPv4Address[$i].PrefixLength
                            }

                            if ($null -ne $networkConfig.IPv4DefaultGateway -and
                                $i -lt $networkConfig.IPv4Address.Count) {
                                $newIpvAddress.DefaultGateway = $networkConfig.IPv4DefaultGateway[$i].NextHop
                            }
                            $ipv4Address += $newIpvAddress
                        }

                        for ($i = 0; $i -lt $networkConfig.IPv6Address.Count; $i++) {
                            $newIpvAddress = Get-IpvAddresses

                            if ($null -ne $networkConfig.IPv6Address -and
                                $i -lt $networkConfig.IPv6Address.Count) {
                                $newIpvAddress.Address = $networkConfig.IPv6Address[$i].IPAddress
                                $newIpvAddress.Subnet = $networkConfig.IPv6Address[$i].PrefixLength
                            }

                            if ($null -ne $networkConfig.IPv6DefaultGateway -and
                                $i -lt $networkConfig.IPv6DefaultGateway.Count) {
                                $newIpvAddress.DefaultGateway = $networkConfig.IPv6DefaultGateway[$i].NextHop
                            }
                            $ipv6Address += $newIpvAddress
                        }

                        $mtuSize = $adapter.MTUSize
                        $driverDate = $adapter.DriverDate
                        $driverVersion = $adapter.DriverVersionString
                        $description = $adapter.InterfaceDescription
                        $dnsServerToBeUsed = $networkConfig.DNSServer.ServerAddresses
                    } else {
                        Write-Verbose "Working on NIC: $($networkConfig.Description)"
                        $adapter = $networkConfig
                        $description = $adapter.Description

                        if ($adapter.ServiceName -ne "NdIsImPlatformMp") {
                            $nicPnpCapabilitiesSetting = Get-NicPnpCapabilitiesSetting -NicAdapterComponentId $adapter.Guid
                        } else {
                            Write-Verbose "Multiplexor adapter detected. Going to skip PnpCapabilities check"
                            $nicPnpCapabilitiesSetting = [PSCustomObject]@{
                                PnPCapabilities = "MultiplexorNoPnP"
                            }
                        }

                        #set the correct $adapterConfiguration to link to the correct $networkConfig that we are on
                        $adapterConfiguration = $networkAdapterConfigurations |
                            Where-Object { $_.SettingID -eq $networkConfig.GUID -or
                                $_.SettingID -eq $networkConfig.InterfaceGuid }

                        if ($null -eq $adapterConfiguration) {
                            Write-Verbose "Failed to find correct adapterConfiguration for this networkConfig."
                            Write-Verbose "GUID: $($networkConfig.GUID) | InterfaceGuid: $($networkConfig.InterfaceGuid)"
                        }

                        $ipv6Enabled = ($adapterConfiguration.IPAddress | Where-Object { $_.Contains(":") }).Count -ge 1

                        if ($null -ne $adapterConfiguration.DefaultIPGateway) {
                            $ipv4Gateway = $adapterConfiguration.DefaultIPGateway | Where-Object { $_.Contains(".") }
                            $ipv6Gateway = $adapterConfiguration.DefaultIPGateway | Where-Object { $_.Contains(":") }
                        } else {
                            $ipv4Gateway = "No default IPv4 gateway set"
                            $ipv6Gateway = "No default IPv6 gateway set"
                        }

                        for ($i = 0; $i -lt $adapterConfiguration.IPAddress.Count; $i++) {

                            if ($adapterConfiguration.IPAddress[$i].Contains(":")) {
                                $newIpv6Address = Get-IpvAddresses
                                if ($i -lt $adapterConfiguration.IPAddress.Count) {
                                    $newIpv6Address.Address = $adapterConfiguration.IPAddress[$i]
                                    $newIpv6Address.Subnet = $adapterConfiguration.IPSubnet[$i]
                                }

                                $newIpv6Address.DefaultGateway = $ipv6Gateway
                                $ipv6Address += $newIpv6Address
                            } else {
                                $newIpv4Address = Get-IpvAddresses
                                if ($i -lt $adapterConfiguration.IPAddress.Count) {
                                    $newIpv4Address.Address = $adapterConfiguration.IPAddress[$i]
                                    $newIpv4Address.Subnet = $adapterConfiguration.IPSubnet[$i]
                                }

                                $newIpv4Address.DefaultGateway = $ipv4Gateway
                                $ipv4Address += $newIpv4Address
                            }
                        }

                        $isRegisteredInDns = $adapterConfiguration.FullDNSRegistrationEnabled
                        $dnsServerToBeUsed = $adapterConfiguration.DNSServerSearchOrder
                    }

                    $nicObjects.Add([PSCustomObject]@{
                            WmiObject         = $WmiObject
                            Name              = $adapter.Name
                            LinkSpeed         = ((($adapter.Speed) / 1000000).ToString() + " Mbps")
                            DriverDate        = $driverDate
                            NetAdapterRss     = $netAdapterRss
                            RssEnabledValue   = $rssEnabledValue
                            IPv6Enabled       = $ipv6Enabled
                            Description       = $description
                            DriverVersion     = $driverVersion
                            MTUSize           = $mtuSize
                            PnPCapabilities   = $nicPnpCapabilitiesSetting.PnpCapabilities
                            SleepyNicDisabled = $nicPnpCapabilitiesSetting.SleepyNicDisabled
                            IPv4Addresses     = $ipv4Address
                            IPv6Addresses     = $ipv6Address
                            RegisteredInDns   = $isRegisteredInDns
                            DnsServer         = $dnsServerToBeUsed
                            DnsClient         = $dnsClient
                        })
                }
            }
            end {
                Write-Verbose "Found $($nicObjects.Count) active adapters on the computer."
                Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
                return $nicObjects
            }
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Passed - ComputerName: '$ComputerName' | ComputerFQDN: '$ComputerFQDN'"
    }
    process {
        try {
            try {
                $networkConfiguration = Get-NetworkConfiguration -ComputerName $ComputerName
            } catch {
                Invoke-CatchActionError $CatchActionFunction

                try {
                    if (-not ([string]::IsNullOrEmpty($ComputerFQDN))) {
                        $networkConfiguration = Get-NetworkConfiguration -ComputerName $ComputerFQDN
                    } else {
                        $bypassCatchActions = $true
                        Write-Verbose "No FQDN was passed, going to rethrow error."
                        throw
                    }
                } catch {
                    #Just throw again
                    throw
                }
            }

            if ([String]::IsNullOrEmpty($networkConfiguration)) {
                # Throw if nothing was returned by previous calls.
                # Can be caused when executed on Server 2008 R2 where CIM namespace ROOT/StandardCiMv2 is invalid.
                Write-Verbose "No value was returned by 'Get-NetworkConfiguration'. Fallback to WMI."
                throw
            }

            return (Get-NicInformation -NetworkConfiguration $networkConfiguration)
        } catch {
            if (-not $bypassCatchActions) {
                Invoke-CatchActionError $CatchActionFunction
            }

            $wmiNetworkCardsParams = @{
                ComputerName        = $ComputerName
                Class               = "Win32_NetworkAdapter"
                Filter              = "NetConnectionStatus ='2'"
                CatchActionFunction = $CatchActionFunction
            }
            $wmiNetworkCards = Get-WmiObjectHandler @wmiNetworkCardsParams

            return (Get-NicInformation -NetworkConfiguration $wmiNetworkCards -WmiObject $true)
        }
    }
}

# This function is used to get a list of all the IP in use by the Exchange Servers across the topology
function Get-ExchangeServerIPs {
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputFilePath,
        [Parameter(Mandatory = $false)]
        [object[]]$ExchangeServers
    )

    begin {
        $IPs           = New-Object 'System.Collections.Generic.List[string]'
        $FailedServers = New-Object 'System.Collections.Generic.List[string]'

        $progressParams = @{
            Activity        = "Getting List of IPs in use by Exchange Servers"
            Status          = [string]::Empty
            PercentComplete = 0
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    }
    process {
        $counter = 0
        $totalCount = $ExchangeServers.Count

        foreach ($Server in $ExchangeServers) {
            $baseStatus = "Processing: $($Server.Name) -"
            $progressParams.PercentComplete = ($counter / $totalCount * 100)
            $progressParams.Status = "$baseStatus Getting IPs"
            Write-Progress @progressParams

            $IpsFound = $false
            $HostNetworkInfo = Get-AllNicInformation -ComputerName $Server.Name -ComputerFQDN $Server.FQDN
            if ($null -ne $HostNetworkInfo) {
                if ($null -ne $HostNetworkInfo.IPv4Addresses) {
                    foreach ($address in $HostNetworkInfo.IPv4Addresses) {
                        $IPs += $address.Address
                        $IpsFound = $true
                    }
                }
                if ($null -ne $HostNetworkInfo.IPv6Addresses) {
                    foreach ($address in $HostNetworkInfo.IPv6Addresses) {
                        $IPs += $address.Address
                        $IpsFound = $true
                    }
                }
            }

            if (-not $IpsFound) {
                $FailedServers += $Server.Name
                Write-Verbose "IP of $($Server.Name) cannot be found and will not be added to IP allow list."
            }

            $counter++
        }

        Write-Progress @progressParams -Completed
    }
    end {
        if ($FailedServers -gt 0) {
            Write-Host ("Unable to get IPs from the following servers: {0}" -f [string]::Join(", ", $FailedServers)) -ForegroundColor Red
        }

        try {
            $IPs | Out-File $OutputFilePath
            Write-Host ("Please find the collected IPs at {0}" -f $OutputFilePath)
        } catch {
            Write-Host "Unable to write to file. Please check the path provided. Inner Exception:" -ForegroundColor Red
            Write-HostErrorInformation $_
        }
    }
}


# This function is used to get a list of all the IP in use by the Exchange Servers across the topology
function Get-IPRangeAllowListFromFile {
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    begin {
        $results = @{
            ipRangeAllowListRules = New-Object 'System.Collections.Generic.List[object]'
            IsError               = $true
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    }
    process {
        try {
            $SubnetStrings = (Get-Content -Path $FilePath -ErrorAction Stop) | Where-Object { $_.trim() -ne "" }
        } catch {
            Write-Host "Unable to read the content of file provided for IPRange. Inner Exception" -ForegroundColor Red
            Write-HostErrorInformation $_
            return
        }

        if ($null -eq $SubnetStrings -or $SubnetStrings.Length -eq 0) {
            Write-Host "The IP range file provided is empty. Please provide a valid file." -ForegroundColor Red
            return
        } else {
            $ipRangesString  = [string]::Join(", ", $SubnetStrings)
        }

        # Log all the IPs present in the txt file supplied by user
        Write-Verbose ("Read the contents of the file Successfully. List of IP ranges received from user: {0}" -f $ipRangesString)

        Write-Verbose "Validating the IP ranges specified in the file"
        try {
            foreach ($SubnetString in $SubnetStrings) {
                $SubnetString = $SubnetString.Trim()

                $IpAddressString = $SubnetString.Split("/")[0]
                $SubnetMaskString = $SubnetString.Split("/")[1]

                # Check the type of IP address (IPv4/IPv6)
                $IpAddress = $IpAddressString -as [IPAddress]
                $baseError = "Input file provided for IPRange doesn't have correct syntax of IPs or IP subnets."
                if ($null -eq $IpAddress -or $null -eq $IpAddress.AddressFamily) {
                    # Invalid IP address found
                    Write-Host ("$baseError Re-execute the command with proper input file for IPRange parameter. Invalid IP address detected: {0}." -f $IpAddressString) -ForegroundColor Red
                    return
                }

                $IsIPv6 = $IpAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6

                if ($SubnetMaskString) {
                    # Check if the subnet value is valid (IPv4 <= 32, IPv6 <= 128 or empty)
                    $SubnetMask = $SubnetMaskString -as [int]

                    $InvalidSubnetMaskString = "$baseError Invalid Subnet Mask found: The Subnet Mask $SubnetMaskString is not in valid range.Note: Subnet Mask must be either empty or a non-negative integer.  For IPv4 the value must be <= 32 and for IPv6 the value must be <= 128. Re-execute the command with proper input file for IPRange parameter."
                    if ($null -eq $SubnetMask) {
                        Write-Host ($InvalidSubnetMaskString) -ForegroundColor Red
                        return
                    } elseif (($SubnetMask -gt 32 -and -not $IsIPv6) -or $SubnetMask -gt 128 -or $SubnetMask -lt 0) {
                        Write-Host ($InvalidSubnetMaskString) -ForegroundColor Red
                        return
                    }

                    if ($null -eq ($results.ipRangeAllowListRules | Where-Object { $_.Type -eq "Subnet" -and $_.IP -eq $IpAddressString -and $_.SubnetMask -eq $SubnetMaskString })) {
                        $results.ipRangeAllowListRules.Add(@{Type = "Subnet"; IP=$IpAddressString; SubnetMask=$SubnetMaskString; Allowed=$true })
                    } else {
                        Write-Verbose ("Not adding $IpAddressString/$SubnetMaskString to the list as it is a duplicate entry in the file provided.")
                    }
                } else {
                    if ($null -eq ($results.ipRangeAllowListRules | Where-Object { $_.Type -eq "Single IP" -and $_.IP -eq $IpAddressString })) {
                        $results.ipRangeAllowListRules.Add(@{Type = "Single IP"; IP=$IpAddressString; Allowed=$true })
                    } else {
                        Write-Verbose ("Not adding $IpAddressString to the list as it is a duplicate entry in the file provided.")
                    }
                }
            }

            if ($results.ipRangeAllowListRules.count -gt 500) {
                Write-Host ("Too many IP filtering rules. Please reduce the specified entries by providing appropriate subnets." -f $SubnetMaskString) -ForegroundColor Red
                return
            }
        } catch {
            Write-Host ("Unable to create IP allow rules. Inner Exception") -ForegroundColor Red
            Write-HostErrorInformation $_
            return
        }

        $results.IsError = $false
    }
    end {
        return $results
    }
}



function Get-AllTlsSettingsFromRegistry {
    [CmdletBinding()]
    param(
        [string]$MachineName = $env:COMPUTERNAME,
        [ScriptBlock]$CatchActionFunction
    )
    begin {

        function Get-TLSMemberValue {
            param(
                [Parameter(Mandatory = $true)]
                [string]
                $GetKeyType,

                [Parameter(Mandatory = $false)]
                [object]
                $KeyValue,

                [Parameter( Mandatory = $false)]
                [bool]
                $NullIsEnabled
            )
            Write-Verbose "KeyValue is null: '$($null -eq $KeyValue)' | KeyValue: '$KeyValue' | GetKeyType: $GetKeyType | NullIsEnabled: $NullIsEnabled"
            switch ($GetKeyType) {
                "Enabled" {
                    return ($null -eq $KeyValue -and $NullIsEnabled) -or $KeyValue -eq 1
                }
                "DisabledByDefault" {
                    return $null -ne $KeyValue -and $KeyValue -eq 1
                }
            }
        }

        function Get-NETDefaultTLSValue {
            param(
                [Parameter(Mandatory = $false)]
                [object]
                $KeyValue,

                [Parameter(Mandatory = $true)]
                [string]
                $NetVersion,

                [Parameter(Mandatory = $true)]
                [string]
                $KeyName
            )
            Write-Verbose "KeyValue is null: '$($null -eq $KeyValue)' | KeyValue: '$KeyValue' | NetVersion: '$NetVersion' | KeyName: '$KeyName'"
            return $null -ne $KeyValue -and $KeyValue -eq 1
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Passed - MachineName: '$MachineName'"
        $registryBase = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS {0}\{1}"
        $tlsVersions = @("1.0", "1.1", "1.2", "1.3")
        $enabledKey = "Enabled"
        $disabledKey = "DisabledByDefault"
        $netVersions = @("v2.0.50727", "v4.0.30319")
        $netRegistryBase = "SOFTWARE\{0}\.NETFramework\{1}"
        $allTlsObjects = [PSCustomObject]@{
            "TLS" = @{}
            "NET" = @{}
        }
    }
    process {
        foreach ($tlsVersion in $tlsVersions) {
            $registryServer = $registryBase -f $tlsVersion, "Server"
            $registryClient = $registryBase -f $tlsVersion, "Client"

            # Get the Enabled and DisabledByDefault values
            $serverEnabledValue = Get-RemoteRegistryValue `
                -MachineName $MachineName `
                -SubKey $registryServer `
                -GetValue $enabledKey `
                -CatchActionFunction $CatchActionFunction
            $serverDisabledByDefaultValue = Get-RemoteRegistryValue `
                -MachineName $MachineName `
                -SubKey $registryServer `
                -GetValue $disabledKey `
                -CatchActionFunction $CatchActionFunction
            $clientEnabledValue = Get-RemoteRegistryValue `
                -MachineName $MachineName `
                -SubKey $registryClient `
                -GetValue $enabledKey `
                -CatchActionFunction $CatchActionFunction
            $clientDisabledByDefaultValue = Get-RemoteRegistryValue `
                -MachineName $MachineName `
                -SubKey $registryClient `
                -GetValue $disabledKey `
                -CatchActionFunction $CatchActionFunction

            $serverEnabled = (Get-TLSMemberValue -GetKeyType $enabledKey -KeyValue $serverEnabledValue -NullIsEnabled ($tlsVersion -ne "1.3"))
            $serverDisabledByDefault = (Get-TLSMemberValue -GetKeyType $disabledKey -KeyValue $serverDisabledByDefaultValue)
            $clientEnabled = (Get-TLSMemberValue -GetKeyType $enabledKey -KeyValue $clientEnabledValue -NullIsEnabled ($tlsVersion -ne "1.3"))
            $clientDisabledByDefault = (Get-TLSMemberValue -GetKeyType $disabledKey -KeyValue $clientDisabledByDefaultValue)
            $disabled = $serverEnabled -eq $false -and ($serverDisabledByDefault -or $null -eq $serverDisabledByDefaultValue) -and
            $clientEnabled -eq $false -and ($clientDisabledByDefault -or $null -eq $clientDisabledByDefaultValue)
            $misconfigured = $serverEnabled -ne $clientEnabled -or $serverDisabledByDefault -ne $clientDisabledByDefault
            # only need to test server settings here, because $misconfigured will be set and will be the official status.
            # want to check for if Server is Disabled and Disabled By Default is not set or the reverse. This would be only part disabled
            # and not what we recommend on the blog post.
            $halfDisabled = ($serverEnabled -eq $false -and $serverDisabledByDefault -eq $false -and $null -ne $serverDisabledByDefaultValue) -or
                ($serverEnabled -and $serverDisabledByDefault)
            $configuration = "Enabled"

            if ($disabled) {
                Write-Verbose "TLS is Disabled"
                $configuration = "Disabled"
            }

            if ($halfDisabled) {
                Write-Verbose "TLS is only half disabled"
                $configuration = "Half Disabled"
            }

            if ($misconfigured) {
                Write-Verbose "TLS is misconfigured"
                $configuration = "Misconfigured"
            }

            $currentTLSObject = [PSCustomObject]@{
                TLSVersion                 = $tlsVersion
                "Server$enabledKey"        = $serverEnabled
                "Server$enabledKey`Value"  = $serverEnabledValue
                "Server$disabledKey"       = $serverDisabledByDefault
                "Server$disabledKey`Value" = $serverDisabledByDefaultValue
                "ServerRegistryPath"       = $registryServer
                "Client$enabledKey"        = $clientEnabled
                "Client$enabledKey`Value"  = $clientEnabledValue
                "Client$disabledKey"       = $clientDisabledByDefault
                "Client$disabledKey`Value" = $clientDisabledByDefaultValue
                "ClientRegistryPath"       = $registryClient
                "TLSVersionDisabled"       = $disabled
                "TLSMisconfigured"         = $misconfigured
                "TLSHalfDisabled"          = $halfDisabled
                "TLSConfiguration"         = $configuration
            }
            $allTlsObjects.TLS.Add($TlsVersion, $currentTLSObject)
        }

        foreach ($netVersion in $netVersions) {

            $msRegistryKey = $netRegistryBase -f "Microsoft", $netVersion
            $wowMsRegistryKey = $netRegistryBase -f "Wow6432Node\Microsoft", $netVersion

            $systemDefaultTlsVersionsValue = Get-RemoteRegistryValue `
                -MachineName $MachineName `
                -SubKey $msRegistryKey `
                -GetValue "SystemDefaultTlsVersions" `
                -CatchActionFunction $CatchActionFunction
            $schUseStrongCryptoValue = Get-RemoteRegistryValue `
                -MachineName $MachineName `
                -SubKey $msRegistryKey `
                -GetValue "SchUseStrongCrypto" `
                -CatchActionFunction $CatchActionFunction
            $wowSystemDefaultTlsVersionsValue = Get-RemoteRegistryValue `
                -MachineName $MachineName `
                -SubKey $wowMsRegistryKey `
                -GetValue "SystemDefaultTlsVersions" `
                -CatchActionFunction $CatchActionFunction
            $wowSchUseStrongCryptoValue = Get-RemoteRegistryValue `
                -MachineName $MachineName `
                -SubKey $wowMsRegistryKey `
                -GetValue "SchUseStrongCrypto" `
                -CatchActionFunction $CatchActionFunction

            $systemDefaultTlsVersions = (Get-NETDefaultTLSValue -KeyValue $SystemDefaultTlsVersionsValue -NetVersion $netVersion -KeyName "SystemDefaultTlsVersions")
            $wowSystemDefaultTlsVersions = (Get-NETDefaultTLSValue -KeyValue $wowSystemDefaultTlsVersionsValue -NetVersion $netVersion -KeyName "WowSystemDefaultTlsVersions")

            $currentNetTlsDefaultVersionObject = [PSCustomObject]@{
                NetVersion                       = $netVersion
                SystemDefaultTlsVersions         = $systemDefaultTlsVersions
                SystemDefaultTlsVersionsValue    = $systemDefaultTlsVersionsValue
                SchUseStrongCrypto               = (Get-NETDefaultTLSValue -KeyValue $schUseStrongCryptoValue -NetVersion $netVersion -KeyName "SchUseStrongCrypto")
                SchUseStrongCryptoValue          = $schUseStrongCryptoValue
                MicrosoftRegistryLocation        = $msRegistryKey
                WowSystemDefaultTlsVersions      = $wowSystemDefaultTlsVersions
                WowSystemDefaultTlsVersionsValue = $wowSystemDefaultTlsVersionsValue
                WowSchUseStrongCrypto            = (Get-NETDefaultTLSValue -KeyValue $wowSchUseStrongCryptoValue -NetVersion $netVersion -KeyName "WowSchUseStrongCrypto")
                WowSchUseStrongCryptoValue       = $wowSchUseStrongCryptoValue
                WowRegistryLocation              = $wowMsRegistryKey
                SDtvConfiguredCorrectly          = $systemDefaultTlsVersions -eq $wowSystemDefaultTlsVersions
                SDtvEnabled                      = $systemDefaultTlsVersions -and $wowSystemDefaultTlsVersions
            }

            $hashKeyName = "NET{0}" -f ($netVersion.Split(".")[0])
            $allTlsObjects.NET.Add($hashKeyName, $currentNetTlsDefaultVersionObject)
        }
        return $allTlsObjects
    }
}


function Get-TlsCipherSuiteInformation {
    [OutputType("System.Object")]
    param(
        [string]$MachineName = $env:COMPUTERNAME,
        [ScriptBlock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $tlsCipherReturnObject = New-Object 'System.Collections.Generic.List[object]'
    }
    process {
        # 'Get-TlsCipherSuite' takes account of the cipher suites which are configured by the help of GPO.
        # No need to query the ciphers defined via GPO if this call is successful.
        Write-Verbose "Trying to query TlsCipherSuites via 'Get-TlsCipherSuite'"
        $getTlsCipherSuiteParams = @{
            ComputerName        = $MachineName
            ScriptBlock         = { Get-TlsCipherSuite }
            CatchActionFunction = $CatchActionFunction
        }
        $tlsCipherSuites = Invoke-ScriptBlockHandler @getTlsCipherSuiteParams

        if ($null -eq $tlsCipherSuites) {
            # If we can't get the ciphers via cmdlet, we need to query them via registry call and need to check
            # if ciphers suites are defined via GPO as well. If there are some, these take precedence over what
            # is in the default location.
            Write-Verbose "Failed to query TlsCipherSuites via 'Get-TlsCipherSuite' fallback to registry"

            $policyTlsRegistryParams = @{
                MachineName         = $MachineName
                SubKey              = "SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
                GetValue            = "Functions"
                ValueType           = "String"
                CatchActionFunction = $CatchActionFunction
            }

            Write-Verbose "Trying to query cipher suites configured via GPO from registry"
            $policyDefinedCiphers = Get-RemoteRegistryValue @policyTlsRegistryParams

            if ($null -ne $policyDefinedCiphers) {
                Write-Verbose "Ciphers specified via GPO found - these take precedence over what is in the default location"
                $tlsCipherSuites = $policyDefinedCiphers.Split(",")
            } else {
                Write-Verbose "No cipher suites configured via GPO found - going to query the local TLS cipher suites"
                $tlsRegistryParams = @{
                    MachineName         = $MachineName
                    SubKey              = "SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"
                    GetValue            = "Functions"
                    ValueType           = "MultiString"
                    CatchActionFunction = $CatchActionFunction
                }

                $tlsCipherSuites = Get-RemoteRegistryValue @tlsRegistryParams
            }
        }

        if ($null -ne $tlsCipherSuites) {
            foreach ($cipher in $tlsCipherSuites) {
                $tlsCipherReturnObject.Add([PSCustomObject]@{
                        Name        = if ($null -eq $cipher.Name) { $cipher } else { $cipher.Name }
                        CipherSuite = if ($null -eq $cipher.CipherSuite) { "N/A" } else { $cipher.CipherSuite }
                        Cipher      = if ($null -eq $cipher.Cipher) { "N/A" } else { $cipher.Cipher }
                        Certificate = if ($null -eq $cipher.Certificate) { "N/A" } else { $cipher.Certificate }
                    })
            }
        }
    }
    end {
        return $tlsCipherReturnObject
    }
}

# Gets all related TLS Settings, from registry or other factors
function Get-AllTlsSettings {
    [CmdletBinding()]
    param(
        [string]$MachineName = $env:COMPUTERNAME,
        [ScriptBlock]$CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    }
    process {
        return [PSCustomObject]@{
            Registry         = (Get-AllTlsSettingsFromRegistry -MachineName $MachineName -CatchActionFunction $CatchActionFunction)
            SecurityProtocol = (Invoke-ScriptBlockHandler -ComputerName $MachineName -ScriptBlock { ([System.Net.ServicePointManager]::SecurityProtocol).ToString() } -CatchActionFunction $CatchActionFunction)
            TlsCipherSuite   = (Get-TlsCipherSuiteInformation -MachineName $MachineName -CatchActionFunction $CatchActionFunction)
        }
    }
}

# This function is used to collect the required information needed to determine if a server is ready for Extended Protection
function Get-ExtendedProtectionPrerequisitesCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$ExchangeServers,

        [Parameter(Mandatory = $false)]
        [string[]]$SiteVDirLocations,

        [Parameter(Mandatory = $false)]
        [bool]$SkipEWS
    )
    begin {
        $results = New-Object 'System.Collections.Generic.List[object]'
        $counter = 0
        $totalCount = $ExchangeServers.Count
        $progressParams = @{
            Activity        = "Prerequisites Check"
            Status          = [string]::Empty
            PercentComplete = 0
        }
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    } process {
        foreach ($server in $ExchangeServers) {

            $counter++
            $baseStatus = "Processing: $server -"
            $progressParams.PercentComplete = ($counter / $totalCount * 100)
            $progressParams.Status = "$baseStatus Extended Protection Configuration"
            Write-Progress @progressParams
            $tlsSettings = $null
            Write-Verbose "$($progressParams.Status)"

            $params = @{
                ComputerName         = $server.ToString()
                IsClientAccessServer = $server.IsClientAccessServer
                IsMailboxServer      = $server.IsMailboxServer
                ExcludeEWS           = $SkipEWS
            }

            if ($null -ne $SiteVDirLocations) {
                $params.Add("SiteVDirLocations", $SiteVDirLocations)
            }
            $extendedProtectionConfiguration = Get-ExtendedProtectionConfiguration @params

            if ($extendedProtectionConfiguration.ServerConnected) {
                Write-Verbose "Server appears to be up going to get the TLS settings as well"
                $progressParams.Status = "$baseStatus TLS Settings"
                Write-Progress @progressParams
                Write-Verbose "$($progressParams.Status)"
                $tlsSettings = Get-AllTlsSettings -MachineName $server
            } else {
                Write-Verbose "Server doesn't appear to be online. Skipped over trying to get the TLS settings"
            }

            $results.Add([PSCustomObject]@{
                    ComputerName                    = $server.ToString()
                    ExtendedProtectionConfiguration = $extendedProtectionConfiguration
                    TlsSettings                     = [PSCustomObject]@{
                        ComputerName = $server.ToString()
                        Settings     = $tlsSettings
                    }
                    ServerOnline                    = $extendedProtectionConfiguration.ServerConnected
                })
        }
        Write-Progress @progressParams -Completed
    } end {
        return $results
    }
}

# Used to test the TLS Configuration
function Invoke-ExtendedProtectionTlsPrerequisitesCheck {
    [CmdletBinding()]
    [OutputType("System.Object")]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$TlsConfiguration
    )

    begin {
        function NewActionObject {
            param(
                [string]$Name,
                [array]$List,
                [string]$Action
            )

            return [PSCustomObject]@{
                Name   = $Name
                List   = $List
                Action = $Action
            }
        }

        function GroupTlsServerSettings {
            [CmdletBinding()]
            param(
                [System.Collections.Generic.List[object]]$TlsSettingsList
            )

            $groupedResults = New-Object 'System.Collections.Generic.List[object]'

            # loop through the least amount of times to compare the TLS settings
            # if the values are different add them to the list
            $tlsKeys = @("1.0", "1.1", "1.2")
            $netKeys = @("NETv4") # Only think we care about v4

            foreach ($serverTls in $TlsSettingsList) {
                $currentServer = $serverTls.ComputerName
                $tlsSettings = $serverTls.Settings
                # Removing TLS 1.3 here to avoid it being displayed
                $tlsSettings.Registry.TLS.Remove("1.3")
                $tlsRegistry = $tlsSettings.Registry.TLS
                $netRegistry = $tlsSettings.Registry.NET
                $listIndex = 0
                $addNewGroupList = $true
                Write-Verbose "Working on Server $currentServer"

                # only need to compare against the current groupedResults List
                # if this is the first time, we don't compare we just add
                while ($listIndex -lt $groupedResults.Count) {
                    $referenceTlsSettings = $groupedResults[$listIndex].TlsSettings
                    $nextServer = $false
                    Write-Verbose "Working on TLS Setting index $listIndex"

                    foreach ($key in $tlsKeys) {
                        $props = $tlsRegistry[$key].PSObject.Properties.Name
                        $result = Compare-Object -ReferenceObject $referenceTlsSettings.Registry.TLS[$key] -DifferenceObject $tlsRegistry[$key] -Property $props
                        if ($null -ne $result) {
                            Write-Verbose "Found difference in TLS for $key"
                            $nextServer = $true
                            break;
                        }
                    }

                    if ($nextServer) { $listIndex++; continue; }

                    foreach ($key in $netKeys) {
                        $props = $netRegistry[$key].PSObject.Properties.Name
                        $result = Compare-Object -ReferenceObject $referenceTlsSettings.Registry.NET[$key] -DifferenceObject $netRegistry[$key] -Property $props
                        if ($null -ne $result) {
                            Write-Verbose "Found difference in NET for $key"
                            $nextServer = $true
                            break
                        }
                    }

                    if ($nextServer) { $listIndex++; continue; }
                    Write-Verbose "This server's Security Protocol is set to $($tlsSettings.SecurityProtocol)"

                    # we must match so add to the current groupResults and break
                    Write-Verbose "Server appears to match current reference TLS Object"
                    $groupedResults[$listIndex].MatchedServer.Add($currentServer)
                    Write-Verbose "Now $($groupedResults[$listIndex].MatchedServer.Count) servers match this reference"
                    $addNewGroupList = $false
                    break
                }

                if ($addNewGroupList) {
                    Write-Verbose "Added new grouped result because of server $currentServer"
                    $obj = [PSCustomObject]@{
                        TlsSettings   = $tlsSettings
                        MatchedServer = New-Object 'System.Collections.Generic.List[string]'
                    }
                    $obj.MatchedServer.Add($currentServer)
                    $groupedResults.Add($obj)
                }
            }
            return $groupedResults
        }

        $actionsRequiredList = New-Object 'System.Collections.Generic.List[object]'
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    } process {

        $tlsGroupedResults = @(GroupTlsServerSettings -TlsSettingsList $TlsConfiguration)

        if ($null -ne $tlsGroupedResults -and
            $tlsGroupedResults.Count -gt 0) {

            foreach ($tlsResults in $tlsGroupedResults) {
                # Check for actions to take against
                $netKeys = @("NETv4")
                $netRegistry = $tlsResults.TlsSettings.Registry.NET
                foreach ($key in $netKeys) {
                    if ($netRegistry[$key].SchUseStrongCrypto -eq $false -or
                        $netRegistry[$key].WowSchUseStrongCrypto -eq $false -or
                        $null -eq $netRegistry[$key].SchUseStrongCryptoValue -or
                        $null -eq $netRegistry[$key].WowSchUseStrongCryptoValue) {
                        $params = @{
                            Name   = "SchUseStrongCrypto is not configured as expected"
                            List   = $tlsResults.MatchedServer
                            Action = "Configure SchUseStrongCrypto for $key as described here: https://aka.ms/ExchangeEPDoc"
                        }
                        $actionsRequiredList.Add((NewActionObject @params))
                        Write-Verbose "SchUseStrongCrypto doesn't match the expected configuration"
                    }

                    if ($netRegistry[$key].SystemDefaultTlsVersions -eq $false -or
                        $netRegistry[$key].WowSystemDefaultTlsVersions -eq $false -or
                        $null -eq $netRegistry[$key].SystemDefaultTlsVersionsValue -or
                        $null -eq $netRegistry[$key].WowSystemDefaultTlsVersionsValue) {
                        $params = @{
                            Name   = "SystemDefaultTlsVersions is not configured as expected"
                            List   = $tlsResults.MatchedServer
                            Action = "Configure SystemDefaultTlsVersions for $key as described here: https://aka.ms/ExchangeEPDoc"
                        }
                        $actionsRequiredList.Add((NewActionObject @params))
                        Write-Verbose "SystemDefaultTlsVersions doesn't match the expected configuration"
                    }
                }
            }

            if ($tlsGroupedResults.Count -gt 1) {
                $params = @{
                    Name   = "Multiple TLS differences have been detected"
                    Action = "Please ensure that all servers are running the same TLS configuration"
                }
                $action = NewActionObject @params
                $actionsRequiredList.Add($action)
            }
        }
    } end {
        return [PSCustomObject]@{
            CheckPassed     = ($actionsRequiredList.Count -eq 0)
            TlsSettings     = $tlsGroupedResults
            ActionsRequired = $actionsRequiredList
        }
    }
}

function Write-Host {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Proper handling of write host with colors')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [object]$Object,
        [switch]$NoNewLine,
        [string]$ForegroundColor
    )
    process {
        $consoleHost = $host.Name -eq "ConsoleHost"

        if ($null -ne $Script:WriteHostManipulateObjectAction) {
            $Object = & $Script:WriteHostManipulateObjectAction $Object
        }

        $params = @{
            Object    = $Object
            NoNewLine = $NoNewLine
        }

        if ([string]::IsNullOrEmpty($ForegroundColor)) {
            if ($null -ne $host.UI.RawUI.ForegroundColor -and
                $consoleHost) {
                $params.Add("ForegroundColor", $host.UI.RawUI.ForegroundColor)
            }
        } elseif ($ForegroundColor -eq "Yellow" -and
            $consoleHost -and
            $null -ne $host.PrivateData.WarningForegroundColor) {
            $params.Add("ForegroundColor", $host.PrivateData.WarningForegroundColor)
        } elseif ($ForegroundColor -eq "Red" -and
            $consoleHost -and
            $null -ne $host.PrivateData.ErrorForegroundColor) {
            $params.Add("ForegroundColor", $host.PrivateData.ErrorForegroundColor)
        } else {
            $params.Add("ForegroundColor", $ForegroundColor)
        }

        Microsoft.PowerShell.Utility\Write-Host @params

        if ($null -ne $Script:WriteHostDebugAction -and
            $null -ne $Object) {
            &$Script:WriteHostDebugAction $Object
        }
    }
}

function SetProperForegroundColor {
    $Script:OriginalConsoleForegroundColor = $host.UI.RawUI.ForegroundColor

    if ($Host.UI.RawUI.ForegroundColor -eq $Host.PrivateData.WarningForegroundColor) {
        Write-Verbose "Foreground Color matches warning's color"

        if ($Host.UI.RawUI.ForegroundColor -ne "Gray") {
            $Host.UI.RawUI.ForegroundColor = "Gray"
        }
    }

    if ($Host.UI.RawUI.ForegroundColor -eq $Host.PrivateData.ErrorForegroundColor) {
        Write-Verbose "Foreground Color matches error's color"

        if ($Host.UI.RawUI.ForegroundColor -ne "Gray") {
            $Host.UI.RawUI.ForegroundColor = "Gray"
        }
    }
}

function RevertProperForegroundColor {
    $Host.UI.RawUI.ForegroundColor = $Script:OriginalConsoleForegroundColor
}

function SetWriteHostAction ($DebugAction) {
    $Script:WriteHostDebugAction = $DebugAction
}

function SetWriteHostManipulateObjectAction ($ManipulateObject) {
    $Script:WriteHostManipulateObjectAction = $ManipulateObject
}

function Write-Progress {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Warning from Shared functions')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$Activity = "",

        [switch]$Completed,

        [string]$CurrentOperation,

        [Parameter(Position = 2)]
        [int]$Id,

        [int]$ParentId = -1,

        [int]$PercentComplete,

        [int]$SecondsRemaining = -1,

        [int]$SourceId,

        [Parameter(Position = 1)]
        [string]$Status
    )

    process {
        $params = @{
            Activity         = $Activity
            Completed        = $Completed
            CurrentOperation = $CurrentOperation
            Id               = $Id
            ParentId         = $ParentId
            PercentComplete  = $PercentComplete
            SecondsRemaining = $SecondsRemaining
            SourceId         = $SourceId
        }

        if (-not([string]::IsNullOrEmpty($Status))) {
            $params.Add("Status", $Status)
        }

        Microsoft.PowerShell.Utility\Write-Progress @params

        $message = "Write-Progress Activity: '$Activity' Completed: $Completed CurrentOperation: '$CurrentOperation' Id: $Id" +
        " ParentId: $ParentId PercentComplete: $PercentComplete SecondsRemaining: $SecondsRemaining SourceId: $SourceId Status: '$Status'"

        if ($null -ne $Script:WriteProgressDebugAction) {
            & $Script:WriteProgressDebugAction $message
        }

        if ($PSSenderInfo -and
            $null -ne $Script:WriteRemoteProgressDebugAction) {
            & $Script:WriteRemoteProgressDebugAction $message
        }
    }
}

function SetWriteProgressAction ($DebugAction) {
    $Script:WriteProgressDebugAction = $DebugAction
}

function SetWriteRemoteProgressAction ($DebugAction) {
    $Script:WriteRemoteProgressDebugAction = $DebugAction
}

function Write-Verbose {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Verbose from Shared functions')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [string]$Message
    )

    process {

        if ($null -ne $Script:WriteVerboseManipulateMessageAction) {
            $Message = & $Script:WriteVerboseManipulateMessageAction $Message
        }

        Microsoft.PowerShell.Utility\Write-Verbose $Message

        if ($null -ne $Script:WriteVerboseDebugAction) {
            & $Script:WriteVerboseDebugAction $Message
        }

        # $PSSenderInfo is set when in a remote context
        if ($PSSenderInfo -and
            $null -ne $Script:WriteRemoteVerboseDebugAction) {
            & $Script:WriteRemoteVerboseDebugAction $Message
        }
    }
}

function SetWriteVerboseAction ($DebugAction) {
    $Script:WriteVerboseDebugAction = $DebugAction
}

function SetWriteRemoteVerboseAction ($DebugAction) {
    $Script:WriteRemoteVerboseDebugAction = $DebugAction
}

function SetWriteVerboseManipulateMessageAction ($DebugAction) {
    $Script:WriteVerboseManipulateMessageAction = $DebugAction
}

function Write-Warning {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Warning from Shared functions')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [string]$Message
    )
    process {

        if ($null -ne $Script:WriteWarningManipulateMessageAction) {
            $Message = & $Script:WriteWarningManipulateMessageAction $Message
        }

        Microsoft.PowerShell.Utility\Write-Warning $Message

        # Add WARNING to beginning of the message by default.
        $Message = "WARNING: $Message"

        if ($null -ne $Script:WriteWarningDebugAction) {
            & $Script:WriteWarningDebugAction $Message
        }

        # $PSSenderInfo is set when in a remote context
        if ($PSSenderInfo -and
            $null -ne $Script:WriteRemoteWarningDebugAction) {
            & $Script:WriteRemoteWarningDebugAction $Message
        }
    }
}

function SetWriteWarningAction ($DebugAction) {
    $Script:WriteWarningDebugAction = $DebugAction
}

function SetWriteRemoteWarningAction ($DebugAction) {
    $Script:WriteRemoteWarningDebugAction = $DebugAction
}

function SetWriteWarningManipulateMessageAction ($DebugAction) {
    $Script:WriteWarningManipulateMessageAction = $DebugAction
}




function Confirm-ProxyServer {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $TargetUri
    )

    try {
        $proxyObject = ([System.Net.WebRequest]::GetSystemWebProxy()).GetProxy($TargetUri)
        if ($TargetUri -ne $proxyObject.OriginalString) {
            return $true
        } else {
            return $false
        }
    } catch {
        return $false
    }
}

function Invoke-WebRequestWithProxyDetection {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "Default")]
        [string]
        $Uri,

        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [switch]
        $UseBasicParsing,

        [Parameter(Mandatory = $true, ParameterSetName = "ParametersObject")]
        [hashtable]
        $ParametersObject,

        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [string]
        $OutFile
    )

    if ([System.String]::IsNullOrEmpty($Uri)) {
        $Uri = $ParametersObject.Uri
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (Confirm-ProxyServer -TargetUri $Uri) {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "PowerShell")
        $webClient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    }

    if ($null -eq $ParametersObject) {
        $params = @{
            Uri     = $Uri
            OutFile = $OutFile
        }

        if ($UseBasicParsing) {
            $params.UseBasicParsing = $true
        }
    } else {
        $params = $ParametersObject
    }

    Invoke-WebRequest @params
}

<#
    Determines if the script has an update available.
#>
function Get-ScriptUpdateAvailable {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $false)]
        [string]
        $VersionsUrl = "https://github.com/microsoft/CSS-Exchange/releases/latest/download/ScriptVersions.csv"
    )

    $BuildVersion = "23.04.04.1055"

    $scriptName = $script:MyInvocation.MyCommand.Name
    $scriptPath = [IO.Path]::GetDirectoryName($script:MyInvocation.MyCommand.Path)
    $scriptFullName = (Join-Path $scriptPath $scriptName)

    $result = [PSCustomObject]@{
        ScriptName     = $scriptName
        CurrentVersion = $BuildVersion
        LatestVersion  = ""
        UpdateFound    = $false
        Error          = $null
    }

    if ((Get-AuthenticodeSignature -FilePath $scriptFullName).Status -eq "NotSigned") {
        Write-Warning "This script appears to be an unsigned test build. Skipping version check."
    } else {
        try {
            $versionData = [Text.Encoding]::UTF8.GetString((Invoke-WebRequestWithProxyDetection $VersionsUrl -UseBasicParsing).Content) | ConvertFrom-Csv
            $latestVersion = ($versionData | Where-Object { $_.File -eq $scriptName }).Version
            $result.LatestVersion = $latestVersion
            if ($null -ne $latestVersion -and $latestVersion -ne $BuildVersion) {
                $result.UpdateFound = $true
            }

            Write-Verbose "Current version: $($result.CurrentVersion) Latest version: $($result.LatestVersion) Update found: $($result.UpdateFound)"
        } catch {
            Write-Verbose "Unable to check for updates: $($_.Exception)"
            $result.Error = $_
        }
    }

    return $result
}


function Confirm-Signature {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $File
    )

    $IsValid = $false
    $MicrosoftSigningRoot2010 = 'CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
    $MicrosoftSigningRoot2011 = 'CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'

    try {
        $sig = Get-AuthenticodeSignature -FilePath $File

        if ($sig.Status -ne 'Valid') {
            Write-Warning "Signature is not trusted by machine as Valid, status: $($sig.Status)."
            throw
        }

        $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.VerificationFlags = "IgnoreNotTimeValid"

        if (-not $chain.Build($sig.SignerCertificate)) {
            Write-Warning "Signer certificate doesn't chain correctly."
            throw
        }

        if ($chain.ChainElements.Count -le 1) {
            Write-Warning "Certificate Chain shorter than expected."
            throw
        }

        $rootCert = $chain.ChainElements[$chain.ChainElements.Count - 1]

        if ($rootCert.Certificate.Subject -ne $rootCert.Certificate.Issuer) {
            Write-Warning "Top-level certificate in chain is not a root certificate."
            throw
        }

        if ($rootCert.Certificate.Subject -ne $MicrosoftSigningRoot2010 -and $rootCert.Certificate.Subject -ne $MicrosoftSigningRoot2011) {
            Write-Warning "Unexpected root cert. Expected $MicrosoftSigningRoot2010 or $MicrosoftSigningRoot2011, but found $($rootCert.Certificate.Subject)."
            throw
        }

        Write-Host "File signed by $($sig.SignerCertificate.Subject)"

        $IsValid = $true
    } catch {
        $IsValid = $false
    }

    $IsValid
}

<#
.SYNOPSIS
    Overwrites the current running script file with the latest version from the repository.
.NOTES
    This function always overwrites the current file with the latest file, which might be
    the same. Get-ScriptUpdateAvailable should be called first to determine if an update is
    needed.

    In many situations, updates are expected to fail, because the server running the script
    does not have internet access. This function writes out failures as warnings, because we
    expect that Get-ScriptUpdateAvailable was already called and it successfully reached out
    to the internet.
#>
function Invoke-ScriptUpdate {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([boolean])]
    param ()

    $scriptName = $script:MyInvocation.MyCommand.Name
    $scriptPath = [IO.Path]::GetDirectoryName($script:MyInvocation.MyCommand.Path)
    $scriptFullName = (Join-Path $scriptPath $scriptName)

    $oldName = [IO.Path]::GetFileNameWithoutExtension($scriptName) + ".old"
    $oldFullName = (Join-Path $scriptPath $oldName)
    $tempFullName = (Join-Path $env:TEMP $scriptName)

    if ($PSCmdlet.ShouldProcess("$scriptName", "Update script to latest version")) {
        try {
            Invoke-WebRequestWithProxyDetection "https://github.com/microsoft/CSS-Exchange/releases/latest/download/$scriptName" -OutFile $tempFullName
        } catch {
            Write-Warning "AutoUpdate: Failed to download update: $($_.Exception.Message)"
            return $false
        }

        try {
            if (Confirm-Signature -File $tempFullName) {
                Write-Host "AutoUpdate: Signature validated."
                if (Test-Path $oldFullName) {
                    Remove-Item $oldFullName -Force -Confirm:$false -ErrorAction Stop
                }
                Move-Item $scriptFullName $oldFullName
                Move-Item $tempFullName $scriptFullName
                Remove-Item $oldFullName -Force -Confirm:$false -ErrorAction Stop
                Write-Host "AutoUpdate: Succeeded."
                return $true
            } else {
                Write-Warning "AutoUpdate: Signature could not be verified: $tempFullName."
                Write-Warning "AutoUpdate: Update was not applied."
            }
        } catch {
            Write-Warning "AutoUpdate: Failed to apply update: $($_.Exception.Message)"
        }
    }

    return $false
}

<#
    Determines if the script has an update available. Use the optional
    -AutoUpdate switch to make it update itself. Pass -Confirm:$false
    to update without prompting the user. Pass -Verbose for additional
    diagnostic output.

    Returns $true if an update was downloaded, $false otherwise. The
    result will always be $false if the -AutoUpdate switch is not used.
#>
function Test-ScriptVersion {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'Need to pass through ShouldProcess settings to Invoke-ScriptUpdate')]
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $false)]
        [switch]
        $AutoUpdate,
        [Parameter(Mandatory = $false)]
        [string]
        $VersionsUrl = "https://github.com/microsoft/CSS-Exchange/releases/latest/download/ScriptVersions.csv"
    )

    $updateInfo = Get-ScriptUpdateAvailable $VersionsUrl
    if ($updateInfo.UpdateFound) {
        if ($AutoUpdate) {
            return Invoke-ScriptUpdate
        } else {
            Write-Warning "$($updateInfo.ScriptName) $BuildVersion is outdated. Please download the latest, version $($updateInfo.LatestVersion)."
        }
    }

    return $false
}

function Confirm-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )

    return $currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )
}


# Confirm that either Remote Shell or EMS is loaded from an Edge Server, Exchange Server, or a Tools box.
# It does this by also initializing the session and running Get-EventLogLevel. (Server Management RBAC right)
# All script that require Confirm-ExchangeShell should be at least using Server Management RBAC right for the user running the script.
function Confirm-ExchangeShell {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [bool]$LoadExchangeShell = $true,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Passed: LoadExchangeShell: $LoadExchangeShell"
        $currentErrors = $Error.Count
        $edgeTransportKey = 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\EdgeTransportRole'
        $setupKey = 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup'
        $remoteShell = (-not(Test-Path $setupKey))
        $toolsServer = (Test-Path $setupKey) -and
            (-not(Test-Path $edgeTransportKey)) -and
            ($null -eq (Get-ItemProperty -Path $setupKey -Name "Services" -ErrorAction SilentlyContinue))
        Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction

        function IsExchangeManagementSession {
            [OutputType("System.Boolean")]
            param(
                [ScriptBlock]$CatchActionFunction
            )

            $getEventLogLevelCallSuccessful = $false
            $isExchangeManagementShell = $false

            try {
                $currentErrors = $Error.Count
                $eventLogLevel = Get-EventLogLevel -ErrorAction Stop | Select-Object -First 1
                $getEventLogLevelCallSuccessful = $true
                foreach ($e in $eventLogLevel) {
                    Write-Verbose "Type is: $($e.GetType().Name) BaseType is: $($e.GetType().BaseType)"
                    if (($e.GetType().Name -eq "EventCategoryObject") -or
                        (($e.GetType().Name -eq "PSObject") -and
                            ($null -ne $e.SerializationData))) {
                        $isExchangeManagementShell = $true
                    }
                }
                Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction
            } catch {
                Write-Verbose "Failed to run Get-EventLogLevel"
                Invoke-CatchActionError $CatchActionFunction
            }

            return [PSCustomObject]@{
                CallWasSuccessful = $getEventLogLevelCallSuccessful
                IsManagementShell = $isExchangeManagementShell
            }
        }
    }
    process {
        $isEMS = IsExchangeManagementSession $CatchActionFunction
        if ($isEMS.CallWasSuccessful) {
            Write-Verbose "Exchange PowerShell Module already loaded."
        } else {
            if (-not ($LoadExchangeShell)) { return }

            #Test 32 bit process, as we can't see the registry if that is the case.
            if (-not ([System.Environment]::Is64BitProcess)) {
                Write-Warning "Open a 64 bit PowerShell process to continue"
                return
            }

            if (Test-Path "$setupKey") {
                Write-Verbose "We are on Exchange 2013 or newer"

                try {
                    $currentErrors = $Error.Count
                    if (Test-Path $edgeTransportKey) {
                        Write-Verbose "We are on Exchange Edge Transport Server"
                        [xml]$PSSnapIns = Get-Content -Path "$env:ExchangeInstallPath\Bin\exShell.psc1" -ErrorAction Stop

                        foreach ($PSSnapIn in $PSSnapIns.PSConsoleFile.PSSnapIns.PSSnapIn) {
                            Write-Verbose ("Trying to add PSSnapIn: {0}" -f $PSSnapIn.Name)
                            Add-PSSnapin -Name $PSSnapIn.Name -ErrorAction Stop
                        }

                        Import-Module $env:ExchangeInstallPath\bin\Exchange.ps1 -ErrorAction Stop
                    } else {
                        Import-Module $env:ExchangeInstallPath\bin\RemoteExchange.ps1 -ErrorAction Stop
                        Connect-ExchangeServer -Auto -ClientApplication:ManagementShell
                    }
                    Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction

                    Write-Verbose "Imported Module. Trying Get-EventLogLevel Again"
                    $isEMS = IsExchangeManagementSession $CatchActionFunction
                    if (($isEMS.CallWasSuccessful) -and
                        ($isEMS.IsManagementShell)) {
                        Write-Verbose "Successfully loaded Exchange Management Shell"
                    } else {
                        Write-Warning "Something went wrong while loading the Exchange Management Shell"
                    }
                } catch {
                    Write-Warning "Failed to Load Exchange PowerShell Module..."
                    Invoke-CatchActionError $CatchActionFunction
                }
            } else {
                Write-Verbose "Not on an Exchange or Tools server"
            }
        }
    }
    end {

        $returnObject = [PSCustomObject]@{
            ShellLoaded = $isEMS.CallWasSuccessful
            Major       = ((Get-ItemProperty -Path $setupKey -Name "MsiProductMajor" -ErrorAction SilentlyContinue).MsiProductMajor)
            Minor       = ((Get-ItemProperty -Path $setupKey -Name "MsiProductMinor" -ErrorAction SilentlyContinue).MsiProductMinor)
            Build       = ((Get-ItemProperty -Path $setupKey -Name "MsiBuildMajor" -ErrorAction SilentlyContinue).MsiBuildMajor)
            Revision    = ((Get-ItemProperty -Path $setupKey -Name "MsiBuildMinor" -ErrorAction SilentlyContinue).MsiBuildMinor)
            EdgeServer  = $isEMS.CallWasSuccessful -and (Test-Path $setupKey) -and (Test-Path $edgeTransportKey)
            ToolsOnly   = $isEMS.CallWasSuccessful -and $toolsServer
            RemoteShell = $isEMS.CallWasSuccessful -and $remoteShell
            EMS         = $isEMS.IsManagementShell
        }

        return $returnObject
    }
}

function Get-NewLoggerInstance {
    [CmdletBinding()]
    param(
        [string]$LogDirectory = (Get-Location).Path,

        [ValidateNotNullOrEmpty()]
        [string]$LogName = "Script_Logging",

        [bool]$AppendDateTime = $true,

        [bool]$AppendDateTimeToFileName = $true,

        [int]$MaxFileSizeMB = 10,

        [int]$CheckSizeIntervalMinutes = 10,

        [int]$NumberOfLogsToKeep = 10
    )

    $fileName = if ($AppendDateTimeToFileName) { "{0}_{1}.txt" -f $LogName, ((Get-Date).ToString('yyyyMMddHHmmss')) } else { "$LogName.txt" }
    $fullFilePath = [System.IO.Path]::Combine($LogDirectory, $fileName)

    if (-not (Test-Path $LogDirectory)) {
        try {
            New-Item -ItemType Directory -Path $LogDirectory -ErrorAction Stop | Out-Null
        } catch {
            throw "Failed to create Log Directory: $LogDirectory"
        }
    }

    return [PSCustomObject]@{
        FullPath                 = $fullFilePath
        AppendDateTime           = $AppendDateTime
        MaxFileSizeMB            = $MaxFileSizeMB
        CheckSizeIntervalMinutes = $CheckSizeIntervalMinutes
        NumberOfLogsToKeep       = $NumberOfLogsToKeep
        BaseInstanceFileName     = $fileName.Replace(".txt", "")
        Instance                 = 1
        NextFileCheckTime        = ((Get-Date).AddMinutes($CheckSizeIntervalMinutes))
        PreventLogCleanup        = $false
        LoggerDisabled           = $false
    } | Write-LoggerInstance -Object "Starting Logger Instance $(Get-Date)"
}

function Write-LoggerInstance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$LoggerInstance,

        [Parameter(Mandatory = $true, Position = 1)]
        [object]$Object
    )
    process {
        if ($LoggerInstance.LoggerDisabled) { return }

        if ($LoggerInstance.AppendDateTime -and
            $Object.GetType().Name -eq "string") {
            $Object = "[$([System.DateTime]::Now)] : $Object"
        }

        # Doing WhatIf:$false to support -WhatIf in main scripts but still log the information
        $Object | Out-File $LoggerInstance.FullPath -Append -WhatIf:$false

        #Upkeep of the logger information
        if ($LoggerInstance.NextFileCheckTime -gt [System.DateTime]::Now) {
            return
        }

        #Set next update time to avoid issues so we can log things
        $LoggerInstance.NextFileCheckTime = ([System.DateTime]::Now).AddMinutes($LoggerInstance.CheckSizeIntervalMinutes)
        $item = Get-ChildItem $LoggerInstance.FullPath

        if (($item.Length / 1MB) -gt $LoggerInstance.MaxFileSizeMB) {
            $LoggerInstance | Write-LoggerInstance -Object "Max file size reached rolling over" | Out-Null
            $directory = [System.IO.Path]::GetDirectoryName($LoggerInstance.FullPath)
            $fileName = "$($LoggerInstance.BaseInstanceFileName)-$($LoggerInstance.Instance).txt"
            $LoggerInstance.Instance++
            $LoggerInstance.FullPath = [System.IO.Path]::Combine($directory, $fileName)

            $items = Get-ChildItem -Path ([System.IO.Path]::GetDirectoryName($LoggerInstance.FullPath)) -Filter "*$($LoggerInstance.BaseInstanceFileName)*"

            if ($items.Count -gt $LoggerInstance.NumberOfLogsToKeep) {
                $item = $items | Sort-Object LastWriteTime | Select-Object -First 1
                $LoggerInstance | Write-LoggerInstance "Removing Log File $($item.FullName)" | Out-Null
                $item | Remove-Item -Force
            }
        }
    }
    end {
        return $LoggerInstance
    }
}

function Invoke-LoggerInstanceCleanup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$LoggerInstance
    )
    process {
        if ($LoggerInstance.LoggerDisabled -or
            $LoggerInstance.PreventLogCleanup) {
            return
        }

        Get-ChildItem -Path ([System.IO.Path]::GetDirectoryName($LoggerInstance.FullPath)) -Filter "*$($LoggerInstance.BaseInstanceFileName)*" |
            Remove-Item -Force
    }
}

<#
.SYNOPSIS
    Outputs a table of objects with certain values colorized.
.EXAMPLE
    PS C:\> <example usage>
    Explanation of what the example does
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    General notes
#>
function Out-Columns {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [object[]]
        $InputObject,

        [Parameter(Mandatory = $false, Position = 0)]
        [string[]]
        $Properties,

        [Parameter(Mandatory = $false, Position = 1)]
        [ScriptBlock[]]
        $ColorizerFunctions = @(),

        [Parameter(Mandatory = $false)]
        [int]
        $IndentSpaces = 0,

        [Parameter(Mandatory = $false)]
        [int]
        $LinesBetweenObjects = 0,

        [Parameter(Mandatory = $false)]
        [ref]
        $StringOutput
    )

    begin {
        function WrapLine {
            param([string]$line, [int]$width)
            if ($line.Length -le $width -and $line.IndexOf("`n") -lt 0) {
                return $line
            }

            $lines = New-Object System.Collections.ArrayList

            $noLF = $line.Replace("`r", "")
            $lineSplit = $noLF.Split("`n")
            foreach ($l in $lineSplit) {
                if ($l.Length -le $width) {
                    [void]$lines.Add($l)
                } else {
                    $split = $l.Split(" ")
                    $sb = New-Object System.Text.StringBuilder
                    for ($i = 0; $i -lt $split.Length; $i++) {
                        if ($sb.Length -eq 0 -and $sb.Length + $split[$i].Length -lt $width) {
                            [void]$sb.Append($split[$i])
                        } elseif ($sb.Length -gt 0 -and $sb.Length + $split[$i].Length + 1 -lt $width) {
                            [void]$sb.Append(" " + $split[$i])
                        } elseif ($sb.Length -gt 0) {
                            [void]$lines.Add($sb.ToString())
                            [void]$sb.Clear()
                            $i--
                        } else {
                            if ($split[$i].Length -le $width) {
                                [void]$lines.Add($split[$i])
                            } else {
                                [void]$lines.Add($split[$i].Substring(0, $width))
                                $split[$i] = $split[$i].Substring($width)
                                $i--
                            }
                        }
                    }

                    if ($sb.Length -gt 0) {
                        [void]$lines.Add($sb.ToString())
                    }
                }
            }

            return $lines
        }

        function GetLineObjects {
            param($obj, $props, $colWidths)
            $linesNeededForThisObject = 1
            $multiLineProps = @{}
            for ($i = 0; $i -lt $props.Length; $i++) {
                $p = $props[$i]
                $val = $obj."$p"

                if ($val -isnot [array]) {
                    $val = WrapLine -line $val -width $colWidths[$i]
                } elseif ($val -is [array]) {
                    $val = $val | Where-Object { $null -ne $_ }
                    $val = $val | ForEach-Object { WrapLine -line $_ -width $colWidths[$i] }
                }

                if ($val -is [array]) {
                    $multiLineProps[$p] = $val
                    if ($val.Length -gt $linesNeededForThisObject) {
                        $linesNeededForThisObject = $val.Length
                    }
                }
            }

            if ($linesNeededForThisObject -eq 1) {
                $obj
            } else {
                for ($i = 0; $i -lt $linesNeededForThisObject; $i++) {
                    $lineProps = @{}
                    foreach ($p in $props) {
                        if ($null -ne $multiLineProps[$p] -and $multiLineProps[$p].Length -gt $i) {
                            $lineProps[$p] = $multiLineProps[$p][$i]
                        } elseif ($i -eq 0) {
                            $lineProps[$p] = $obj."$p"
                        } else {
                            $lineProps[$p] = $null
                        }
                    }

                    [PSCustomObject]$lineProps
                }
            }
        }

        function GetColumnColors {
            param($obj, $props, $functions)

            $consoleHost = (Get-Host).Name -eq "ConsoleHost"
            $colColors = New-Object string[] $props.Count
            for ($i = 0; $i -lt $props.Count; $i++) {
                if ($consoleHost) {
                    $fgColor = (Get-Host).ui.RawUi.ForegroundColor
                } else {
                    $fgColor = "White"
                }
                foreach ($func in $functions) {
                    $result = $func.Invoke($obj, $props[$i])
                    if (-not [string]::IsNullOrEmpty($result)) {
                        $fgColor = $result
                        break # The first colorizer that takes action wins
                    }
                }

                $colColors[$i] = $fgColor
            }

            $colColors
        }

        function GetColumnWidths {
            param($objects, $props)

            $colWidths = New-Object int[] $props.Count

            # Start with the widths of the property names
            for ($i = 0; $i -lt $props.Count; $i++) {
                $colWidths[$i] = $props[$i].Length
            }

            # Now check the widths of the widest values
            foreach ($thing in $objects) {
                for ($i = 0; $i -lt $props.Count; $i++) {
                    $val = $thing."$($props[$i])"
                    if ($null -ne $val) {
                        $width = 0
                        if ($val -isnot [array]) {
                            $val = $val.ToString().Split("`n")
                        }

                        $width = ($val | ForEach-Object {
                                if ($null -ne $_) { $_.ToString() } else { "" }
                            } | Sort-Object Length -Descending | Select-Object -First 1).Length

                        if ($width -gt $colWidths[$i]) {
                            $colWidths[$i] = $width
                        }
                    }
                }
            }

            # If we're within the window width, we're done
            $totalColumnWidth = $colWidths.Length * $padding + ($colWidths | Measure-Object -Sum).Sum + $IndentSpaces
            $windowWidth = (Get-Host).UI.RawUI.WindowSize.Width
            if ($windowWidth -lt 1 -or $totalColumnWidth -lt $windowWidth) {
                return $colWidths
            }

            # Take size away from one or more columns to make them fit
            while ($totalColumnWidth -ge $windowWidth) {
                $startingTotalWidth = $totalColumnWidth
                $widest = $colWidths | Sort-Object -Descending | Select-Object -First 1
                $newWidest = [Math]::Floor($widest * 0.95)
                for ($i = 0; $i -lt $colWidths.Length; $i++) {
                    if ($colWidths[$i] -eq $widest) {
                        $colWidths[$i] = $newWidest
                        break
                    }
                }

                $totalColumnWidth = $colWidths.Length * $padding + ($colWidths | Measure-Object -Sum).Sum + $IndentSpaces
                if ($totalColumnWidth -ge $startingTotalWidth) {
                    # Somehow we didn't reduce the size at all, so give up
                    break
                }
            }

            return $colWidths
        }

        $objects = New-Object System.Collections.ArrayList
        $padding = 2
        $stb = New-Object System.Text.StringBuilder
    }

    process {
        foreach ($thing in $InputObject) {
            [void]$objects.Add($thing)
        }
    }

    end {
        if ($objects.Count -gt 0) {
            $props = $null

            if ($null -ne $Properties) {
                $props = $Properties
            } else {
                $props = $objects[0].PSObject.Properties.Name
            }

            $colWidths = GetColumnWidths $objects $props

            Write-Host
            [void]$stb.Append([System.Environment]::NewLine)

            Write-Host (" " * $IndentSpaces) -NoNewline
            [void]$stb.Append(" " * $IndentSpaces)

            for ($i = 0; $i -lt $props.Count; $i++) {
                Write-Host ("{0,$(-1 * ($colWidths[$i] + $padding))}" -f $props[$i]) -NoNewline
                [void]$stb.Append("{0,$(-1 * ($colWidths[$i] + $padding))}" -f $props[$i])
            }

            Write-Host
            [void]$stb.Append([System.Environment]::NewLine)

            Write-Host (" " * $IndentSpaces) -NoNewline
            [void]$stb.Append(" " * $IndentSpaces)

            for ($i = 0; $i -lt $props.Count; $i++) {
                Write-Host ("{0,$(-1 * ($colWidths[$i] + $padding))}" -f ("-" * $props[$i].Length)) -NoNewline
                [void]$stb.Append("{0,$(-1 * ($colWidths[$i] + $padding))}" -f ("-" * $props[$i].Length))
            }

            Write-Host
            [void]$stb.Append([System.Environment]::NewLine)

            foreach ($o in $objects) {
                $colColors = GetColumnColors -obj $o -props $props -functions $ColorizerFunctions
                $lineObjects = @(GetLineObjects -obj $o -props $props -colWidths $colWidths)
                foreach ($lineObj in $lineObjects) {
                    Write-Host (" " * $IndentSpaces) -NoNewline
                    [void]$stb.Append(" " * $IndentSpaces)
                    for ($i = 0; $i -lt $props.Count; $i++) {
                        $val = $o."$($props[$i])"
                        Write-Host ("{0,$(-1 * ($colWidths[$i] + $padding))}" -f $lineObj."$($props[$i])") -NoNewline -ForegroundColor $colColors[$i]
                        [void]$stb.Append("{0,$(-1 * ($colWidths[$i] + $padding))}" -f $lineObj."$($props[$i])")
                    }

                    Write-Host
                    [void]$stb.Append([System.Environment]::NewLine)
                }

                for ($i = 0; $i -lt $LinesBetweenObjects; $i++) {
                    Write-Host
                    [void]$stb.Append([System.Environment]::NewLine)
                }
            }

            Write-Host
            [void]$stb.Append([System.Environment]::NewLine)

            if ($null -ne $StringOutput) {
                $StringOutput.Value = $stb.ToString()
            }
        }
    }
}

function Show-Disclaimer {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [ValidateNotNullOrEmpty()]
        [string]$Target,
        [ValidateNotNullOrEmpty()]
        [string]$Operation
    )

    if ($PSCmdlet.ShouldProcess($Message, $Target, $Operation) -or
        $WhatIfPreference) {
        return
    } else {
        exit
    }
}


# This function is used to determine the version of Exchange based off a build number or
# by providing the Exchange Version and CU and/or SU. This provides one location in the entire repository
# that is required to be updated for when a new release of Exchange is dropped.
function Get-ExchangeBuildVersionInformation {
    [CmdletBinding(DefaultParameterSetName = "AdminDisplayVersion")]
    param(
        [Parameter(ParameterSetName = "AdminDisplayVersion", Position = 1)]
        [object]$AdminDisplayVersion,

        [Parameter(ParameterSetName = "ExSetup")]
        [System.Version]$FileVersion,

        [Parameter(ParameterSetName = "VersionCU", Mandatory = $true)]
        [ValidateScript( { ValidateVersionParameter $_ } )]
        [string]$Version,

        [Parameter(ParameterSetName = "VersionCU", Mandatory = $true)]
        [ValidateScript( { ValidateCUParameter $_ } )]
        [string]$CU,

        [Parameter(ParameterSetName = "VersionCU", Mandatory = $false)]
        [ValidateScript( { ValidateSUParameter $_ } )]
        [string]$SU,

        [Parameter(ParameterSetName = "FindSUBuilds", Mandatory = $true)]
        [ValidateScript( { ValidateSUParameter $_ } )]
        [string]$FindBySUName,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )
    begin {

        function GetBuildVersion {
            param(
                [Parameter(Position = 1)]
                [string]$ExchangeVersion,
                [Parameter(Position = 2)]
                [string]$CU,
                [Parameter(Position = 3)]
                [string]$SU
            )
            $cuResult = $exchangeBuildDictionary[$ExchangeVersion][$CU]

            if ((-not [string]::IsNullOrEmpty($SU)) -and
                $cuResult.SU.ContainsKey($SU)) {
                return $cuResult.SU[$SU]
            } else {
                return $cuResult.CU
            }
        }

        # Dictionary of Exchange Version/CU/SU to build number
        $exchangeBuildDictionary = GetExchangeBuildDictionary

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $exchangeMajorVersion = [string]::Empty
        $exchangeVersion = $null
        $supportedBuildNumber = $false
        $latestSUBuild = $false
        $extendedSupportDate = [string]::Empty
        $cuReleaseDate = [string]::Empty
        $friendlyName = [string]::Empty
        $cuLevel = [string]::Empty
        $suName = [string]::Empty
        $orgValue = 0
        $schemaValue = 0
        $mesoValue = 0
        $ex19 = "Exchange2019"
        $ex16 = "Exchange2016"
        $ex13 = "Exchange2013"
    }
    process {
        # Convert both input types to a [System.Version]
        try {
            if ($PSCmdlet.ParameterSetName -eq "FindSUBuilds") {
                foreach ($exchangeKey in $exchangeBuildDictionary.Keys) {
                    foreach ($cuKey in $exchangeBuildDictionary[$exchangeKey].Keys) {
                        if ($null -ne $exchangeBuildDictionary[$exchangeKey][$cuKey].SU -and
                            $exchangeBuildDictionary[$exchangeKey][$cuKey].SU.ContainsKey($FindBySUName)) {
                            Get-ExchangeBuildVersionInformation -FileVersion $exchangeBuildDictionary[$exchangeKey][$cuKey].SU[$FindBySUName]
                        }
                    }
                }
                return
            } elseif ($PSCmdlet.ParameterSetName -eq "VersionCU") {
                [System.Version]$exchangeVersion = GetBuildVersion -ExchangeVersion $Version -CU $CU -SU $SU
            } elseif ($PSCmdlet.ParameterSetName -eq "AdminDisplayVersion") {
                $AdminDisplayVersion = $AdminDisplayVersion.ToString()
                Write-Verbose "Passed AdminDisplayVersion: $AdminDisplayVersion"
                $split1 = $AdminDisplayVersion.Substring(($AdminDisplayVersion.IndexOf(" ")) + 1, 4).Split(".")
                $buildStart = $AdminDisplayVersion.LastIndexOf(" ") + 1
                $split2 = $AdminDisplayVersion.Substring($buildStart, ($AdminDisplayVersion.LastIndexOf(")") - $buildStart)).Split(".")
                [System.Version]$exchangeVersion = "$($split1[0]).$($split1[1]).$($split2[0]).$($split2[1])"
            } else {
                [System.Version]$exchangeVersion = $FileVersion
            }
        } catch {
            Write-Verbose "Failed to convert to system.version"
            Invoke-CatchActionError $CatchActionFunction
        }

        <#
            Exchange Build Numbers: https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019
            Exchange 2016 & 2019 AD Changes: https://learn.microsoft.com/en-us/exchange/plan-and-deploy/prepare-ad-and-domains?view=exchserver-2019
            Exchange 2013 AD Changes: https://learn.microsoft.com/en-us/exchange/prepare-active-directory-and-domains-exchange-2013-help
        #>
        if ($exchangeVersion.Major -eq 15 -and $exchangeVersion.Minor -eq 2) {
            Write-Verbose "Exchange 2019 is detected"
            $exchangeMajorVersion = "Exchange2019"
            $extendedSupportDate = "10/14/2025"
            $friendlyName = "Exchange 2019"

            #Latest Version AD Settings
            $schemaValue = 17003
            $mesoValue = 13243
            $orgValue = 16760

            switch ($exchangeVersion) {
                { $_ -ge (GetBuildVersion $ex19 "CU12") } {
                    $cuLevel = "CU12"
                    $cuReleaseDate = "04/20/2022"
                    $supportedBuildNumber = $true
                }
                (GetBuildVersion $ex19 "CU12" -SU "Mar23SU") { $latestSUBuild = $true }
                { $_ -lt (GetBuildVersion $ex19 "CU12") } {
                    $cuLevel = "CU11"
                    $cuReleaseDate = "09/28/2021"
                    $supportedBuildNumber = $true
                    $mesoValue = 13242
                    $orgValue = 16759
                }
                (GetBuildVersion $ex19 "CU11" -SU "Mar23SU") { $latestSUBuild = $true }
                (GetBuildVersion $ex19 "CU11" -SU "May22SU") { $mesoValue = 13243 }
                { $_ -lt (GetBuildVersion $ex19 "CU11") } {
                    $cuLevel = "CU10"
                    $cuReleaseDate = "06/29/2021"
                    $mesoValue = 13241
                    $orgValue = 16758
                    $supportedBuildNumber = $false
                }
                { $_ -lt (GetBuildVersion $ex19 "CU10") } {
                    $cuLevel = "CU9"
                    $cuReleaseDate = "03/16/2021"
                    $schemaValue = 17002
                    $mesoValue = 13240
                    $orgValue = 16757
                }
                { $_ -lt (GetBuildVersion $ex19 "CU9") } {
                    $cuLevel = "CU8"
                    $cuReleaseDate = "12/15/2020"
                    $mesoValue = 13239
                    $orgValue = 16756
                }
                { $_ -lt (GetBuildVersion $ex19 "CU8") } {
                    $cuLevel = "CU7"
                    $cuReleaseDate = "09/15/2020"
                    $schemaValue = 17001
                    $mesoValue = 13238
                    $orgValue = 16755
                }
                { $_ -lt (GetBuildVersion $ex19 "CU7") } {
                    $cuLevel = "CU6"
                    $cuReleaseDate = "06/16/2020"
                    $mesoValue = 13237
                    $orgValue = 16754
                }
                { $_ -lt (GetBuildVersion $ex19 "CU6") } {
                    $cuLevel = "CU5"
                    $cuReleaseDate = "03/17/2020"
                }
                { $_ -lt (GetBuildVersion $ex19 "CU5") } {
                    $cuLevel = "CU4"
                    $cuReleaseDate = "12/17/2019"
                }
                { $_ -lt (GetBuildVersion $ex19 "CU4") } {
                    $cuLevel = "CU3"
                    $cuReleaseDate = "09/17/2019"
                }
                { $_ -lt (GetBuildVersion $ex19 "CU3") } {
                    $cuLevel = "CU2"
                    $cuReleaseDate = "06/18/2019"
                }
                { $_ -lt (GetBuildVersion $ex19 "CU2") } {
                    $cuLevel = "CU1"
                    $cuReleaseDate = "02/12/2019"
                    $schemaValue = 17000
                    $mesoValue = 13236
                    $orgValue = 16752
                }
                { $_ -lt (GetBuildVersion $ex19 "CU1") } {
                    $cuLevel = "RTM"
                    $cuReleaseDate = "10/22/2018"
                    $orgValue = 16751
                }
            }
        } elseif ($exchangeVersion.Major -eq 15 -and $exchangeVersion.Minor -eq 1) {
            Write-Verbose "Exchange 2016 is detected"
            $exchangeMajorVersion = "Exchange2016"
            $extendedSupportDate = "10/14/2025"
            $friendlyName = "Exchange 2016"

            #Latest Version AD Settings
            $schemaValue = 15334
            $mesoValue = 13243
            $orgValue = 16223

            switch ($exchangeVersion) {
                { $_ -ge (GetBuildVersion $ex16 "CU23") } {
                    $cuLevel = "CU23"
                    $cuReleaseDate = "04/20/2022"
                    $supportedBuildNumber = $true
                }
                (GetBuildVersion $ex16 "CU23" -SU "Mar23SU") { $latestSUBuild = $true }
                { $_ -lt (GetBuildVersion $ex16 "CU23") } {
                    $cuLevel = "CU22"
                    $cuReleaseDate = "09/28/2021"
                    $supportedBuildNumber = $false
                    $mesoValue = 13242
                    $orgValue = 16222
                }
                (GetBuildVersion $ex16 "CU22" -SU "May22SU") { $mesoValue = 13243 }
                { $_ -lt (GetBuildVersion $ex16 "CU22") } {
                    $cuLevel = "CU21"
                    $cuReleaseDate = "06/29/2021"
                    $mesoValue = 13241
                    $orgValue = 16221
                }
                { $_ -lt (GetBuildVersion $ex16 "CU21") } {
                    $cuLevel = "CU20"
                    $cuReleaseDate = "03/16/2021"
                    $schemaValue = 15333
                    $mesoValue = 13240
                    $orgValue = 16220
                }
                { $_ -lt (GetBuildVersion $ex16 "CU20") } {
                    $cuLevel = "CU19"
                    $cuReleaseDate = "12/15/2020"
                    $mesoValue = 13239
                    $orgValue = 16219
                }
                { $_ -lt (GetBuildVersion $ex16 "CU19") } {
                    $cuLevel = "CU18"
                    $cuReleaseDate = "09/15/2020"
                    $schemaValue = 15332
                    $mesoValue = 13238
                    $orgValue = 16218
                }
                { $_ -lt (GetBuildVersion $ex16 "CU18") } {
                    $cuLevel = "CU17"
                    $cuReleaseDate = "06/16/2020"
                    $mesoValue = 13237
                    $orgValue = 16217
                }
                { $_ -lt (GetBuildVersion $ex16 "CU17") } {
                    $cuLevel = "CU16"
                    $cuReleaseDate = "03/17/2020"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU16") } {
                    $cuLevel = "CU15"
                    $cuReleaseDate = "12/17/2019"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU15") } {
                    $cuLevel = "CU14"
                    $cuReleaseDate = "09/17/2019"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU14") } {
                    $cuLevel = "CU13"
                    $cuReleaseDate = "06/18/2019"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU13") } {
                    $cuLevel = "CU12"
                    $cuReleaseDate = "02/12/2019"
                    $mesoValue = 13236
                    $orgValue = 16215
                }
                { $_ -lt (GetBuildVersion $ex16 "CU12") } {
                    $cuLevel = "CU11"
                    $cuReleaseDate = "10/16/2018"
                    $orgValue = 16214
                }
                { $_ -lt (GetBuildVersion $ex16 "CU11") } {
                    $cuLevel = "CU10"
                    $cuReleaseDate = "06/19/2018"
                    $orgValue = 16213
                }
                { $_ -lt (GetBuildVersion $ex16 "CU10") } {
                    $cuLevel = "CU9"
                    $cuReleaseDate = "03/20/2018"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU9") } {
                    $cuLevel = "CU8"
                    $cuReleaseDate = "12/19/2017"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU8") } {
                    $cuLevel = "CU7"
                    $cuReleaseDate = "09/16/2017"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU7") } {
                    $cuLevel = "CU6"
                    $cuReleaseDate = "06/24/2017"
                    $schemaValue = 15330
                }
                { $_ -lt (GetBuildVersion $ex16 "CU6") } {
                    $cuLevel = "CU5"
                    $cuReleaseDate = "03/21/2017"
                    $schemaValue = 15326
                }
                { $_ -lt (GetBuildVersion $ex16 "CU5") } {
                    $cuLevel = "CU4"
                    $cuReleaseDate = "12/13/2016"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU4") } {
                    $cuLevel = "CU3"
                    $cuReleaseDate = "09/20/2016"
                    $orgValue = 16212
                }
                { $_ -lt (GetBuildVersion $ex16 "CU3") } {
                    $cuLevel = "CU2"
                    $cuReleaseDate = "06/21/2016"
                    $schemaValue = 15325
                }
                { $_ -lt (GetBuildVersion $ex16 "CU2") } {
                    $cuLevel = "CU1"
                    $cuReleaseDate = "03/15/2016"
                    $schemaValue = 15323
                    $orgValue = 16211
                }
            }
        } elseif ($exchangeVersion.Major -eq 15 -and $exchangeVersion.Minor -eq 0) {
            Write-Verbose "Exchange 2013 is detected"
            $exchangeMajorVersion = "Exchange2013"
            $extendedSupportDate = "04/11/2023"
            $friendlyName = "Exchange 2013"

            #Latest Version AD Settings
            $schemaValue = 15312
            $mesoValue = 13237
            $orgValue = 16133

            switch ($exchangeVersion) {
                { $_ -ge (GetBuildVersion $ex13 "CU23") } {
                    $cuLevel = "CU23"
                    $cuReleaseDate = "06/18/2019"
                    $supportedBuildNumber = $true
                }
                (GetBuildVersion $ex13 "CU23" -SU "Mar23SU") { $latestSUBuild = $true }
                (GetBuildVersion $ex13 "CU23" -SU "May22SU") { $mesoValue = 13238 }
                { $_ -lt (GetBuildVersion $ex13 "CU23") } {
                    $cuLevel = "CU22"
                    $cuReleaseDate = "02/12/2019"
                    $mesoValue = 13236
                    $orgValue = 16131
                    $supportedBuildNumber = $false
                }
                { $_ -lt (GetBuildVersion $ex13 "CU22") } {
                    $cuLevel = "CU21"
                    $cuReleaseDate = "06/19/2018"
                    $orgValue = 16130
                }
                { $_ -lt (GetBuildVersion $ex13 "CU21") } {
                    $cuLevel = "CU20"
                    $cuReleaseDate = "03/20/2018"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU20") } {
                    $cuLevel = "CU19"
                    $cuReleaseDate = "12/19/2017"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU19") } {
                    $cuLevel = "CU18"
                    $cuReleaseDate = "09/16/2017"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU18") } {
                    $cuLevel = "CU17"
                    $cuReleaseDate = "06/24/2017"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU17") } {
                    $cuLevel = "CU16"
                    $cuReleaseDate = "03/21/2017"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU16") } {
                    $cuLevel = "CU15"
                    $cuReleaseDate = "12/13/2016"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU15") } {
                    $cuLevel = "CU14"
                    $cuReleaseDate = "09/20/2016"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU14") } {
                    $cuLevel = "CU13"
                    $cuReleaseDate = "06/21/2016"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU13") } {
                    $cuLevel = "CU12"
                    $cuReleaseDate = "03/15/2016"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU12") } {
                    $cuLevel = "CU11"
                    $cuReleaseDate = "12/15/2015"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU11") } {
                    $cuLevel = "CU10"
                    $cuReleaseDate = "09/15/2015"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU10") } {
                    $cuLevel = "CU9"
                    $cuReleaseDate = "06/17/2015"
                    $orgValue = 15965
                }
                { $_ -lt (GetBuildVersion $ex13 "CU9") } {
                    $cuLevel = "CU8"
                    $cuReleaseDate = "03/17/2015"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU8") } {
                    $cuLevel = "CU7"
                    $cuReleaseDate = "12/09/2014"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU7") } {
                    $cuLevel = "CU6"
                    $cuReleaseDate = "08/26/2014"
                    $schemaValue = 15303
                }
                { $_ -lt (GetBuildVersion $ex13 "CU6") } {
                    $cuLevel = "CU5"
                    $cuReleaseDate = "05/27/2014"
                    $schemaValue = 15300
                    $orgValue = 15870
                }
                { $_ -lt (GetBuildVersion $ex13 "CU5") } {
                    $cuLevel = "CU4"
                    $cuReleaseDate = "02/25/2014"
                    $schemaValue = 15292
                    $orgValue = 15844
                }
                { $_ -lt (GetBuildVersion $ex13 "CU4") } {
                    $cuLevel = "CU3"
                    $cuReleaseDate = "11/25/2013"
                    $schemaValue = 15283
                    $orgValue = 15763
                }
                { $_ -lt (GetBuildVersion $ex13 "CU3") } {
                    $cuLevel = "CU2"
                    $cuReleaseDate = "07/09/2013"
                    $schemaValue = 15281
                    $orgValue = 15688
                }
                { $_ -lt (GetBuildVersion $ex13 "CU2") } {
                    $cuLevel = "CU1"
                    $cuReleaseDate = "04/02/2013"
                    $schemaValue = 15254
                    $orgValue = 15614
                }
            }
        } else {
            Write-Verbose "Unknown version of Exchange is detected."
        }

        # Now get the SU Name
        if ([string]::IsNullOrEmpty($exchangeMajorVersion) -or
            [string]::IsNullOrEmpty($cuLevel)) {
            Write-Verbose "Can't lookup when keys aren't set"
            return
        }

        $currentSUInfo = $exchangeBuildDictionary[$exchangeMajorVersion][$cuLevel].SU
        $compareValue = $exchangeVersion.ToString()
        if ($null -ne $currentSUInfo -and
            $currentSUInfo.ContainsValue($compareValue)) {
            foreach ($key in $currentSUInfo.Keys) {
                if ($compareValue -eq $currentSUInfo[$key]) {
                    $suName = $key
                }
            }
        }
    }
    end {

        if ($PSCmdlet.ParameterSetName -eq "FindSUBuilds") {
            Write-Verbose "Return nothing here, results were already returned on the pipeline"
            return
        }

        $friendlyName = "$friendlyName $cuLevel $suName".Trim()
        Write-Verbose "Determined Build Version $friendlyName"
        return [PSCustomObject]@{
            MajorVersion        = $exchangeMajorVersion
            FriendlyName        = $friendlyName
            BuildVersion        = $exchangeVersion
            CU                  = $cuLevel
            ReleaseDate         = if (-not([System.String]::IsNullOrEmpty($cuReleaseDate))) { ([System.Convert]::ToDateTime([DateTime]$cuReleaseDate, [System.Globalization.DateTimeFormatInfo]::InvariantInfo)) } else { $null }
            ExtendedSupportDate = if (-not([System.String]::IsNullOrEmpty($extendedSupportDate))) { ([System.Convert]::ToDateTime([DateTime]$extendedSupportDate, [System.Globalization.DateTimeFormatInfo]::InvariantInfo)) } else { $null }
            Supported           = $supportedBuildNumber
            LatestSU            = $latestSUBuild
            ADLevel             = [PSCustomObject]@{
                SchemaValue = $schemaValue
                MESOValue   = $mesoValue
                OrgValue    = $orgValue
            }
        }
    }
}

function GetExchangeBuildDictionary {

    function NewCUAndSUObject {
        param(
            [string]$CUBuildNumber,
            [Hashtable]$SUBuildNumber
        )
        return @{
            "CU" = $CUBuildNumber
            "SU" = $SUBuildNumber
        }
    }

    @{
        "Exchange2013" = @{
            "CU1"  = (NewCUAndSUObject "15.0.620.29")
            "CU2"  = (NewCUAndSUObject "15.0.712.24")
            "CU3"  = (NewCUAndSUObject "15.0.775.38")
            "CU4"  = (NewCUAndSUObject "15.0.847.32")
            "CU5"  = (NewCUAndSUObject "15.0.913.22")
            "CU6"  = (NewCUAndSUObject "15.0.995.29")
            "CU7"  = (NewCUAndSUObject "15.0.1044.25")
            "CU8"  = (NewCUAndSUObject "15.0.1076.9")
            "CU9"  = (NewCUAndSUObject "15.0.1104.5")
            "CU10" = (NewCUAndSUObject "15.0.1130.7")
            "CU11" = (NewCUAndSUObject "15.0.1156.6")
            "CU12" = (NewCUAndSUObject "15.0.1178.4")
            "CU13" = (NewCUAndSUObject "15.0.1210.3")
            "CU14" = (NewCUAndSUObject "15.0.1236.3")
            "CU15" = (NewCUAndSUObject "15.0.1263.5")
            "CU16" = (NewCUAndSUObject "15.0.1293.2")
            "CU17" = (NewCUAndSUObject "15.0.1320.4")
            "CU18" = (NewCUAndSUObject "15.0.1347.2" @{
                    "Mar18SU" = "15.0.1347.5"
                })
            "CU19" = (NewCUAndSUObject "15.0.1365.1" @{
                    "Mar18SU" = "15.0.1365.3"
                    "May18SU" = "15.0.1365.7"
                })
            "CU20" = (NewCUAndSUObject "15.0.1367.3" @{
                    "May18SU" = "15.0.1367.6"
                    "Aug18SU" = "15.0.1367.9"
                })
            "CU21" = (NewCUAndSUObject "15.0.1395.4" @{
                    "Aug18SU" = "15.0.1395.7"
                    "Oct18SU" = "15.0.1395.8"
                    "Jan19SU" = "15.0.1395.10"
                    "Mar21SU" = "15.0.1395.12"
                })
            "CU22" = (NewCUAndSUObject "15.0.1473.3" @{
                    "Feb19SU" = "15.0.1473.3"
                    "Apr19SU" = "15.0.1473.4"
                    "Jun19SU" = "15.0.1473.5"
                    "Mar21SU" = "15.0.1473.6"
                })
            "CU23" = (NewCUAndSUObject "15.0.1497.2" @{
                    "Jul19SU" = "15.0.1497.3"
                    "Nov19SU" = "15.0.1497.4"
                    "Feb20SU" = "15.0.1497.6"
                    "Oct20SU" = "15.0.1497.7"
                    "Nov20SU" = "15.0.1497.8"
                    "Dec20SU" = "15.0.1497.10"
                    "Mar21SU" = "15.0.1497.12"
                    "Apr21SU" = "15.0.1497.15"
                    "May21SU" = "15.0.1497.18"
                    "Jul21SU" = "15.0.1497.23"
                    "Oct21SU" = "15.0.1497.24"
                    "Nov21SU" = "15.0.1497.26"
                    "Jan22SU" = "15.0.1497.28"
                    "Mar22SU" = "15.0.1497.33"
                    "May22SU" = "15.0.1497.36"
                    "Aug22SU" = "15.0.1497.40"
                    "Oct22SU" = "15.0.1497.42"
                    "Nov22SU" = "15.0.1497.44"
                    "Jan23SU" = "15.0.1497.45"
                    "Feb23SU" = "15.0.1497.47"
                    "Mar23SU" = "15.0.1497.48"
                })
        }
        "Exchange2016" = @{
            "CU1"  = (NewCUAndSUObject "15.1.396.30")
            "CU2"  = (NewCUAndSUObject "15.1.466.34")
            "CU3"  = (NewCUAndSUObject "15.1.544.27")
            "CU4"  = (NewCUAndSUObject "15.1.669.32")
            "CU5"  = (NewCUAndSUObject "15.1.845.34")
            "CU6"  = (NewCUAndSUObject "15.1.1034.26")
            "CU7"  = (NewCUAndSUObject "15.1.1261.35" @{
                    "Mar18SU" = "15.1.1261.39"
                })
            "CU8"  = (NewCUAndSUObject "15.1.1415.2" @{
                    "Mar18SU" = "15.1.1415.4"
                    "May18SU" = "15.1.1415.7"
                    "Mar21SU" = "15.1.1415.8"
                })
            "CU9"  = (NewCUAndSUObject "15.1.1466.3" @{
                    "May18SU" = "15.1.1466.8"
                    "Aug18SU" = "15.1.1466.9"
                    "Mar21SU" = "15.1.1466.13"
                })
            "CU10" = (NewCUAndSUObject "15.1.1531.3" @{
                    "Aug18SU" = "15.1.1531.6"
                    "Oct18SU" = "15.1.1531.8"
                    "Jan19SU" = "15.1.1531.10"
                    "Mar21SU" = "15.1.1531.12"
                })
            "CU11" = (NewCUAndSUObject "15.1.1591.10" @{
                    "Dec18SU" = "15.1.1591.11"
                    "Jan19SU" = "15.1.1591.13"
                    "Apr19SU" = "15.1.1591.16"
                    "Jun19SU" = "15.1.1591.17"
                    "Mar21SU" = "15.1.1591.18"
                })
            "CU12" = (NewCUAndSUObject "15.1.1713.5" @{
                    "Feb19SU" = "15.1.1713.5"
                    "Apr19SU" = "15.1.1713.6"
                    "Jun19SU" = "15.1.1713.7"
                    "Jul19SU" = "15.1.1713.8"
                    "Sep19SU" = "15.1.1713.9"
                    "Mar21SU" = "15.1.1713.10"
                })
            "CU13" = (NewCUAndSUObject "15.1.1779.2" @{
                    "Jul19SU" = "15.1.1779.4"
                    "Sep19SU" = "15.1.1779.5"
                    "Nov19SU" = "15.1.1779.7"
                    "Mar21SU" = "15.1.1779.8"
                })
            "CU14" = (NewCUAndSUObject "15.1.1847.3" @{
                    "Nov19SU" = "15.1.1847.5"
                    "Feb20SU" = "15.1.1847.7"
                    "Mar20SU" = "15.1.1847.10"
                    "Mar21SU" = "15.1.1847.12"
                })
            "CU15" = (NewCUAndSUObject "15.1.1913.5" @{
                    "Feb20SU" = "15.1.1913.7"
                    "Mar20SU" = "15.1.1913.10"
                    "Mar21SU" = "15.1.1913.12"
                })
            "CU16" = (NewCUAndSUObject "15.1.1979.3" @{
                    "Sep20SU" = "15.1.1979.6"
                    "Mar21SU" = "15.1.1979.8"
                })
            "CU17" = (NewCUAndSUObject "15.1.2044.4" @{
                    "Sep20SU" = "15.1.2044.6"
                    "Oct20SU" = "15.1.2044.7"
                    "Nov20SU" = "15.1.2044.8"
                    "Dec20SU" = "15.1.2044.12"
                    "Mar21SU" = "15.1.2044.13"
                })
            "CU18" = (NewCUAndSUObject "15.1.2106.2" @{
                    "Oct20SU" = "15.1.2106.3"
                    "Nov20SU" = "15.1.2106.4"
                    "Dec20SU" = "15.1.2106.6"
                    "Feb21SU" = "15.1.2106.8"
                    "Mar21SU" = "15.1.2106.13"
                })
            "CU19" = (NewCUAndSUObject "15.1.2176.2" @{
                    "Feb21SU" = "15.1.2176.4"
                    "Mar21SU" = "15.1.2176.9"
                    "Apr21SU" = "15.1.2176.12"
                    "May21SU" = "15.1.2176.14"
                })
            "CU20" = (NewCUAndSUObject "15.1.2242.4" @{
                    "Apr21SU" = "15.1.2242.8"
                    "May21SU" = "15.1.2242.10"
                    "Jul21SU" = "15.1.2242.12"
                })
            "CU21" = (NewCUAndSUObject "15.1.2308.8" @{
                    "Jul21SU" = "15.1.2308.14"
                    "Oct21SU" = "15.1.2308.15"
                    "Nov21SU" = "15.1.2308.20"
                    "Jan22SU" = "15.1.2308.21"
                    "Mar22SU" = "15.1.2308.27"
                })
            "CU22" = (NewCUAndSUObject "15.1.2375.7" @{
                    "Oct21SU" = "15.1.2375.12"
                    "Nov21SU" = "15.1.2375.17"
                    "Jan22SU" = "15.1.2375.18"
                    "Mar22SU" = "15.1.2375.24"
                    "May22SU" = "15.1.2375.28"
                    "Aug22SU" = "15.1.2375.31"
                    "Oct22SU" = "15.1.2375.32"
                    "Nov22SU" = "15.1.2375.37"
                })
            "CU23" = (NewCUAndSUObject "15.1.2507.6" @{
                    "May22SU" = "15.1.2507.9"
                    "Aug22SU" = "15.1.2507.12"
                    "Oct22SU" = "15.1.2507.13"
                    "Nov22SU" = "15.1.2507.16"
                    "Jan23SU" = "15.1.2507.17"
                    "Feb23SU" = "15.1.2507.21"
                    "Mar23SU" = "15.1.2507.23"
                })
        }
        "Exchange2019" = @{
            "CU1"  = (NewCUAndSUObject "15.2.330.5" @{
                    "Feb19SU" = "15.2.330.5"
                    "Apr19SU" = "15.2.330.7"
                    "Jun19SU" = "15.2.330.8"
                    "Jul19SU" = "15.2.330.9"
                    "Sep19SU" = "15.2.330.10"
                    "Mar21SU" = "15.2.330.11"
                })
            "CU2"  = (NewCUAndSUObject "15.2.397.3" @{
                    "Jul19SU" = "15.2.397.5"
                    "Sep19SU" = "15.2.397.6"
                    "Nov19SU" = "15.2.397.9"
                    "Mar21SU" = "15.2.397.11"
                })
            "CU3"  = (NewCUAndSUObject "15.2.464.5" @{
                    "Nov19SU" = "15.2.464.7"
                    "Feb20SU" = "15.2.464.11"
                    "Mar20SU" = "15.2.464.14"
                    "Mar21SU" = "15.2.464.15"
                })
            "CU4"  = (NewCUAndSUObject "15.2.529.5" @{
                    "Feb20SU" = "15.2.529.8"
                    "Mar20SU" = "15.2.529.11"
                    "Mar21SU" = "15.2.529.13"
                })
            "CU5"  = (NewCUAndSUObject "15.2.595.3" @{
                    "Sep20SU" = "15.2.595.6"
                    "Mar21SU" = "15.2.595.8"
                })
            "CU6"  = (NewCUAndSUObject "15.2.659.4" @{
                    "Sep20SU" = "15.2.659.6"
                    "Oct20SU" = "15.2.659.7"
                    "Nov20SU" = "15.2.659.8"
                    "Dec20SU" = "15.2.659.11"
                    "Mar21SU" = "15.2.659.12"
                })
            "CU7"  = (NewCUAndSUObject "15.2.721.2" @{
                    "Oct20SU" = "15.2.721.3"
                    "Nov20SU" = "15.2.721.4"
                    "Dec20SU" = "15.2.721.6"
                    "Feb21SU" = "15.2.721.8"
                    "Mar21SU" = "15.2.721.13"
                })
            "CU8"  = (NewCUAndSUObject "15.2.792.3" @{
                    "Feb21SU" = "15.2.792.5"
                    "Mar21SU" = "15.2.792.10"
                    "Apr21SU" = "15.2.792.13"
                    "May21SU" = "15.2.792.15"
                })
            "CU9"  = (NewCUAndSUObject "15.2.858.5" @{
                    "Apr21SU" = "15.2.858.10"
                    "May21SU" = "15.2.858.12"
                    "Jul21SU" = "15.2.858.15"
                })
            "CU10" = (NewCUAndSUObject "15.2.922.7" @{
                    "Jul21SU" = "15.2.922.13"
                    "Oct21SU" = "15.2.922.14"
                    "Nov21SU" = "15.2.922.19"
                    "Jan22SU" = "15.2.922.20"
                    "Mar22SU" = "15.2.922.27"
                })
            "CU11" = (NewCUAndSUObject "15.2.986.5" @{
                    "Oct21SU" = "15.2.986.9"
                    "Nov21SU" = "15.2.986.14"
                    "Jan22SU" = "15.2.986.15"
                    "Mar22SU" = "15.2.986.22"
                    "May22SU" = "15.2.986.26"
                    "Aug22SU" = "15.2.986.29"
                    "Oct22SU" = "15.2.986.30"
                    "Nov22SU" = "15.2.986.36"
                    "Jan23SU" = "15.2.986.37"
                    "Feb23SU" = "15.2.986.41"
                    "Mar23SU" = "15.2.986.42"
                })
            "CU12" = (NewCUAndSUObject "15.2.1118.7" @{
                    "May22SU" = "15.2.1118.9"
                    "Aug22SU" = "15.2.1118.12"
                    "Oct22SU" = "15.2.1118.15"
                    "Nov22SU" = "15.2.1118.20"
                    "Jan23SU" = "15.2.1118.21"
                    "Feb23SU" = "15.2.1118.25"
                    "Mar23SU" = "15.2.1118.26"
                })
        }
    }
}

# Must be outside function to use it as a validate script
function GetValidatePossibleParameters {
    $exchangeBuildDictionary = GetExchangeBuildDictionary
    $suNames = New-Object 'System.Collections.Generic.HashSet[string]'
    $cuNames = New-Object 'System.Collections.Generic.HashSet[string]'
    $versionNames = New-Object 'System.Collections.Generic.HashSet[string]'

    foreach ($exchangeKey in $exchangeBuildDictionary.Keys) {
        [void]$versionNames.Add($exchangeKey)
        foreach ($cuKey in $exchangeBuildDictionary[$exchangeKey].Keys) {
            [void]$cuNames.Add($cuKey)
            if ($null -eq $exchangeBuildDictionary[$exchangeKey][$cuKey].SU) { continue }
            foreach ($suKey in $exchangeBuildDictionary[$exchangeKey][$cuKey].SU.Keys) {
                [void]$suNames.Add($suKey)
            }
        }
    }
    return [PSCustomObject]@{
        Version = $versionNames
        CU      = $cuNames
        SU      = $suNames
    }
}

function ValidateSUParameter {
    param($name)

    $possibleParameters = GetValidatePossibleParameters
    $possibleParameters.SU.Contains($Name)
}

function ValidateCUParameter {
    param($Name)

    $possibleParameters = GetValidatePossibleParameters
    $possibleParameters.CU.Contains($Name)
}

function ValidateVersionParameter {
    param($Name)

    $possibleParameters = GetValidatePossibleParameters
    $possibleParameters.Version.Contains($Name)
}

    # TODO: Move this so it isn't duplicated
    # matching restrictions
    $restrictionToSite = @{
        "APIFrontend"                         = "Default Web Site/API"
        "AutodiscoverFrontend"                = "Default Web Site/Autodiscover"
        "ECPFrontend"                         = "Default Web Site/ECP"
        "EWSFrontend"                         = "Default Web Site/EWS"
        "Microsoft-Server-ActiveSyncFrontend" = "Default Web Site/Microsoft-Server-ActiveSync"
        "OABFrontend"                         = "Default Web Site/OAB"
        "PowershellFrontend"                  = "Default Web Site/Powershell"
        "OWAFrontend"                         = "Default Web Site/OWA"
        "RPCFrontend"                         = "Default Web Site/RPC"
        "MAPIFrontend"                        = "Default Web Site/MAPI"
        "APIBackend"                          = "Exchange Back End/API"
        "AutodiscoverBackend"                 = "Exchange Back End/Autodiscover"
        "ECPBackend"                          = "Exchange Back End/ECP"
        "EWSBackend"                          = "Exchange Back End/EWS"
        "Microsoft-Server-ActiveSyncBackend"  = "Exchange Back End/Microsoft-Server-ActiveSync"
        "OABBackend"                          = "Exchange Back End/OAB"
        "PowershellBackend"                   = "Exchange Back End/Powershell"
        "OWABackend"                          = "Exchange Back End/OWA"
        "RPCBackend"                          = "Exchange Back End/RPC"
        "PushNotificationsBackend"            = "Exchange Back End/PushNotifications"
        "RPCWithCertBackend"                  = "Exchange Back End/RPCWithCert"
        "MAPI-emsmdbBackend"                  = "Exchange Back End/MAPI/emsmdb"
        "MAPI-nspiBackend"                    = "Exchange Back End/MAPI/nspi"
    }

    $Script:Logger = Get-NewLoggerInstance -LogName "ExchangeExtendedProtectionManagement-$((Get-Date).ToString("yyyyMMddhhmmss"))-Debug" `
        -AppendDateTimeToFileName $false `
        -ErrorAction SilentlyContinue

    SetWriteHostAction ${Function:Write-HostLog}
    SetWriteVerboseAction ${Function:Write-VerboseLog}
    SetWriteWarningAction ${Function:Write-HostLog}
    SetWriteProgressAction ${Function:Write-HostLog}

    # The ParameterSetName options
    $RollbackSelected = $PsCmdlet.ParameterSetName -eq "Rollback"
    $RollbackRestoreIISAppConfig = $RollbackSelected -and $RollbackType.Contains("RestoreIISAppConfig")
    $RollbackRestrictType = $RollbackSelected -and (-not $RollbackRestoreIISAppConfig)
    $ConfigureMitigationSelected = $PsCmdlet.ParameterSetName -eq "ConfigureMitigation"
    $ConfigureEPSelected = $ConfigureMitigationSelected -or
        ($PsCmdlet.ParameterSetName -eq "ConfigureEP" -and -not $ShowExtendedProtection)
    $ValidateTypeSelected = $PsCmdlet.ParameterSetName -eq "ValidateMitigation"

    $includeExchangeServerNames = New-Object 'System.Collections.Generic.List[string]'

    if ($RollbackRestoreIISAppConfig -and $RollbackType.Length -gt 1) {
        Write-Host "RestoreIISAppConfig Rollback type can only be used individually"
        exit
    }

    if ($RollbackRestrictType) {
        $RestrictType = $RollbackType.Replace("RestrictType", "")
    }

    if ($ConfigureMitigationSelected) {
        $RestrictType = $RestrictType | Get-Unique
    }

    if ($ValidateTypeSelected) {
        $RestrictType = New-Object 'System.Collections.Generic.List[string]'
        $ValidateType | Get-Unique | ForEach-Object { $RestrictType += $_.Replace("RestrictType", "") }
    }

    if (($ConfigureMitigationSelected -or $ValidateTypeSelected)) {
        # Get list of IPs in object form from the file specified
        $ipResults = Get-IPRangeAllowListFromFile -FilePath $IPRangeFilePath
        if ($ipResults.IsError) {
            exit
        }

        $ipRangeAllowListRules = $ipResults.ipRangeAllowListRules
    }

    if ($InternalOption -eq "SkipEWS") {
        Write-Verbose "SkipEWS option enabled."
        $Script:SkipEWS = $true
    } else {
        $Script:SkipEWS = $false
    }

    if ($null -ne $RestrictType -and $RestrictType.Count -gt 0) {
        $SiteVDirLocations = New-Object 'System.Collections.Generic.List[string]'
        foreach ($key in $RestrictType) {
            $SiteVDirLocations += $restrictionToSite[$key]
        }
    }
} process {
    foreach ($server in $ExchangeServerNames) {
        $includeExchangeServerNames.Add($server)
    }
} end {
    if (-not (Confirm-Administrator)) {
        Write-Warning "The script needs to be executed in elevated mode. Start the Exchange Management Shell as an Administrator."
        exit
    }

    try {
        $BuildVersion = "23.04.04.1055"
        Write-Host "Version $BuildVersion"

        $exchangeShell = Confirm-ExchangeShell
        if (-not($exchangeShell.ShellLoaded)) {
            Write-Warning "Failed to load the Exchange Management Shell. Start the script using the Exchange Management Shell."
            exit
        } elseif (-not($exchangeShell.EMS)) {
            Write-Warning "This script requires to be run inside of Exchange Management Shell. Please run on an Exchange Management Server or an Exchange Server with Exchange Management Shell."
            exit
        }

        if ($SkipAutoUpdate) {
            Write-Verbose "Skipping AutoUpdate"
        } elseif ((Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/CEP-VersionsUrl")) {
            Write-Warning "Script was updated. Please rerun the command."
            exit
        } else {
            Write-Verbose "Script is up to date."
        }

        if ($ConfigureEPSelected) {
            $params = @{
                Message   = "Display Warning about Extended Protection"
                Target    = "Extended Protection is recommended to be enabled for security reasons. " +
                "Known Issues: Following scenarios will not work when Extended Protection is enabled." +
                "`r`n    - SSL offloading or SSL termination via Layer 7 load balancing." +
                "`r`n    - Exchange Hybrid Features if using Modern Hybrid." +
                "`r`n    - Access to Public folders on Exchange 2013 Servers." +
                "`r`nYou can find more information on: https://aka.ms/ExchangeEPDoc. Do you want to proceed?"
                Operation = "Enabling Extended Protection"
            }

            Show-Disclaimer @params
        }

        Write-Verbose ("Running Get-ExchangeServer to get list of all exchange servers")
        Set-ADServerSettings -ViewEntireForest $true
        $ExchangeServers = Get-ExchangeServer | Where-Object { $_.AdminDisplayVersion -like "Version 15*" -and $_.ServerRole -ne "Edge" }

        if ($FindExchangeServerIPAddresses) {
            Get-ExchangeServerIPs -OutputFilePath $OutputFilePath -ExchangeServers $ExchangeServers
            Write-Warning ("The file generated contains all the IPv4 and IPv6 addresses of all Exchange Servers in the organization." +
                " This file should be used as a reference. Please change the file to include/remove IP addresses for the IP filtering allow list." +
                " If the number of Exchange Servers in your organization is high (>100), consider using a IPRange file with IP Range Subnets [x.x.x.x/n] instead of IP addresses which is more efficient." +
                "`r`nYou can find more information on: https://aka.ms/ExchangeEPDoc.")
            return
        }

        $ExchangeServersPrerequisitesCheckSettingsCheck = $ExchangeServers

        if ($null -ne $includeExchangeServerNames -and $includeExchangeServerNames.Count -gt 0) {
            Write-Verbose "Running only on servers: $([string]::Join(", " ,$includeExchangeServerNames))"
            $ExchangeServers = $ExchangeServers | Where-Object { ($_.Name -in $includeExchangeServerNames) -or ($_.FQDN -in $includeExchangeServerNames) }
        }

        if ($null -ne $SkipExchangeServerNames -and $SkipExchangeServerNames.Count -gt 0) {
            Write-Verbose "Skipping servers: $([string]::Join(", ", $SkipExchangeServerNames))"

            # Remove all the servers present in the SkipExchangeServerNames list
            $ExchangeServers = $ExchangeServers | Where-Object { ($_.Name -notin $SkipExchangeServerNames) -and ($_.FQDN -notin $SkipExchangeServerNames) }
        }

        if ($null -eq $ExchangeServers) {
            Write-Host "No exchange servers to process. Please specify server filters correctly"
            exit
        }

        if ($ValidateTypeSelected) {
            # Validate mitigation
            $ExchangeServers = $ExchangeServers | Where-Object { -not ((Get-ExchangeBuildVersionInformation -AdminDisplayVersion $_.AdminDisplayVersion).BuildVersion.Major -eq 15 -and (Get-ExchangeBuildVersionInformation -AdminDisplayVersion $_.AdminDisplayVersion).BuildVersion.Minor -eq 0 -and $_.IsClientAccessServer) }
            Invoke-ValidateMitigation -ExchangeServers $ExchangeServers.Name -ipRangeAllowListRules $ipRangeAllowListRules -SiteVDirLocations $SiteVDirLocations
        }

        if ($ShowExtendedProtection) {
            Write-Verbose "Showing Extended Protection Information Only"
            $extendedProtectionConfigurations = New-Object 'System.Collections.Generic.List[object]'
            foreach ($server in $ExchangeServers) {
                $params = @{
                    ComputerName         = $server.ToString()
                    IsClientAccessServer = $server.IsClientAccessServer
                    IsMailboxServer      = $server.IsMailboxServer
                    ExcludeEWS           = $SkipEWS
                }
                $extendedProtectionConfigurations.Add((Get-ExtendedProtectionConfiguration @params))
            }

            foreach ($configuration in $extendedProtectionConfigurations) {
                Write-Verbose "Working on server $($configuration.ComputerName)"
                $epFrontEndList = New-Object 'System.Collections.Generic.List[object]'
                $epBackEndList = New-Object 'System.Collections.Generic.List[object]'
                foreach ($entry in $configuration.ExtendedProtectionConfiguration) {
                    $vDirArray = $entry.VirtualDirectoryName.Split("/", 2)
                    $ssl = $entry.Configuration.SslSettings

                    $listToAdd = $epFrontEndList
                    if ($vDirArray[0] -eq "Exchange Back End") {
                        $listToAdd = $epBackEndList
                    }

                    $listToAdd.Add(([PSCustomObject]@{
                                $vDirArray[0]     = $vDirArray[1]
                                Value             = $entry.ExtendedProtection
                                SupportedValue    = if ($entry.MitigationSupported -and $entry.MitigationEnabled) { "None" } else { $entry.ExpectedExtendedConfiguration }
                                ConfigSupported   = $entry.ProperlySecuredConfiguration
                                RequireSSL        = "$($ssl.RequireSSL) $(if($ssl.Ssl128Bit) { "(128-bit)" })".Trim()
                                ClientCertificate = $ssl.ClientCertificate
                                IPFilterEnabled   = $entry.MitigationEnabled
                            }))
                }

                Write-Host "Results for Server: $($configuration.ComputerName)"
                $epFrontEndList | Format-Table | Out-String | Write-Host
                $epBackEndList | Format-Table | Out-String | Write-Host
                Write-Host ""
                Write-Host ""
            }

            return
        }

        if ($ConfigureEPSelected) {
            $prerequisitesCheck = Get-ExtendedProtectionPrerequisitesCheck -ExchangeServers $ExchangeServersPrerequisitesCheckSettingsCheck -SkipEWS $SkipEWS -SiteVDirLocations $SiteVDirLocations

            if ($null -ne $prerequisitesCheck) {
                Write-Host ""
                # Remove the down servers from $ExchangeServers list.
                $downServerName = New-Object 'System.Collections.Generic.List[string]'
                $onlineSupportedServers = New-Object 'System.Collections.Generic.List[object]'
                $unsupportedServers = New-Object 'System.Collections.Generic.List[string]'
                $unsupportedAndConfiguredServers = New-Object 'System.Collections.Generic.List[object]'
                $prerequisitesCheck | ForEach-Object {
                    if ($_.ExtendedProtectionConfiguration.ExtendedProtectionConfigured -eq $true -and
                        $_.ExtendedProtectionConfiguration.SupportedVersionForExtendedProtection -eq $false) {
                        $unsupportedAndConfiguredServers.Add($_)
                    } elseif ($_.ExtendedProtectionConfiguration.SupportedVersionForExtendedProtection -eq $false) {
                        $unsupportedServers.Add($_.ComputerName)
                    } elseif ($_.ServerOnline) {
                        $onlineSupportedServers.Add($_)
                    } else {
                        $downServerName.Add($_.ComputerName)
                    }
                }

                # We don't care about the TLS version on servers that aren't yet upgraded on
                # Therefore, we can skip over them for this check.
                # However, if there is an unsupported version of Exchange that does have EP enabled,
                # We need to prompt to the admin stating that we are going to revert the change to get back to a supported state.
                Write-Verbose ("Found the following servers configured for EP and Unsupported: " +
                    "$(if ($unsupportedAndConfiguredServers.Count -eq 0) { 'None' } else {[string]::Join(", " ,$unsupportedAndConfiguredServers.ComputerName)})")

                Write-Verbose ("Found the following servers that not supported to configure EP and not enabled: " +
                    "$(if ($unsupportedServers.Count -eq 0) { 'None' } else {[string]::Join(", " ,$unsupportedServers)})")

                if ($unsupportedAndConfiguredServers.Count -gt 0) {
                    $params = @{
                        Message   = "Display Warning about switching Extended Protection Back to None for Unsupported Build of Exchange"
                        Target    = "Found Servers that have Extended Protection Enabled, but are on an unsupported build of Exchange." +
                        "`r`nBecause of this, we will be setting them back to None for Extended Protection with the execution of this script to be in a supported state." +
                        "`r`nYou can find more information on: https://aka.ms/ExchangeEPDoc. Do you want to proceed?"
                        Operation = "Set Unsupported Version of Exchange Back to None for Extended Protection"
                    }

                    Show-Disclaimer @params
                    Write-Host ""
                }

                if ($unsupportedServers.Count -gt 0) {

                    $serversInList = @($ExchangeServers | Where-Object { $($_.Name -in $unsupportedServers) })

                    if ($serversInList.Count -gt 0) {
                        $line = "The following servers are not the minimum required version to support Extended Protection. Please update them, or re-run the script without including them in the list: $($serversInList -Join " ")"
                        Write-Verbose $line
                        Write-Warning $line
                        exit
                    }

                    Write-Verbose "The following servers are unsupported but not included in the list to configure: $([string]::Join(", " ,$unsupportedServers))"
                }

                if ($downServerName.Count -gt 0) {
                    $line = "Removing the following servers from the list to configure because we weren't able to reach them: $([string]::Join(", " ,$downServerName))"
                    Write-Verbose $line
                    Write-Warning $line
                    $ExchangeServers = $ExchangeServers | Where-Object { $($_.Name -notin $downServerName) }
                    Write-Host ""
                }

                # Only need to set the server names for the ones we are trying to configure and the ones that are up.
                # Also need to add Unsupported Configured EP servers to the list.
                $serverNames = New-Object 'System.Collections.Generic.List[string]'
                $ExchangeServers | ForEach-Object { $serverNames.Add($_.Name) }

                if ($unsupportedAndConfiguredServers.Count -gt 0) {
                    $unsupportedAndConfiguredServers |
                        Where-Object { $_.ComputerName -notin $serverNames } |
                        ForEach-Object { $serverNames.Add($_.ComputerName) }
                }

                # If there aren't any servers to check against for TLS settings, bypass this check.
                if ($null -ne $onlineSupportedServers.TlsSettings) {
                    $tlsPrerequisites = Invoke-ExtendedProtectionTlsPrerequisitesCheck -TlsConfiguration $onlineSupportedServers.TlsSettings

                    function NewDisplayObject {
                        param(
                            [string]$RegistryName,
                            [string]$Location,
                            [object]$Value
                        )
                        return [PSCustomObject]@{
                            RegistryName = $RegistryName
                            Location     = $Location
                            Value        = $Value
                        }
                    }

                    foreach ($tlsSettings in $tlsPrerequisites.TlsSettings) {
                        Write-Host "The following servers have the TLS Configuration below"
                        Write-Host "$([string]::Join(", " ,$tlsSettings.MatchedServer))"
                        $displayObject = @()
                        $tlsSettings.TlsSettings.Registry.Tls.Values |
                            ForEach-Object {
                                $displayObject += NewDisplayObject "Enabled" -Location $_.ServerRegistryPath -Value $_.ServerEnabledValue
                                $displayObject += NewDisplayObject "DisabledByDefault" -Location $_.ServerRegistryPath -Value $_.ServerDisabledByDefaultValue
                                $displayObject += NewDisplayObject "Enabled" -Location $_.ClientRegistryPath -Value $_.ClientEnabledValue
                                $displayObject += NewDisplayObject "DisabledByDefault" -Location $_.ClientRegistryPath -Value $_.ClientDisabledByDefaultValue
                            }

                        $tlsSettings.TlsSettings.Registry.Net.Values |
                            ForEach-Object {
                                $displayObject += NewDisplayObject "SystemTlsVersions" -Location $_.MicrosoftRegistryLocation -Value $_.SystemDefaultTlsVersionsValue
                                $displayObject += NewDisplayObject "SchUseStrongCrypto" -Location $_.MicrosoftRegistryLocation -Value $_.SchUseStrongCryptoValue
                                $displayObject += NewDisplayObject "SystemTlsVersions" -Location $_.WowRegistryLocation -Value $_.WowSystemDefaultTlsVersionsValue
                                $displayObject += NewDisplayObject "SchUseStrongCrypto" -Location $_.WowRegistryLocation -Value $_.WowSchUseStrongCryptoValue
                            }
                        $stringOutput = [string]::Empty
                        SetWriteHostAction $null
                        $displayObject | Sort-Object Location, RegistryName |
                            Out-Columns -StringOutput ([ref]$stringOutput)
                        Write-HostLog $stringOutput
                        SetWriteHostAction ${Function:Write-HostLog}
                    }

                    # If TLS Prerequisites Check passed, then we are good to go.
                    # If it doesn't, now we need to verify the servers we are trying to enable EP on
                    # will pass the TLS Prerequisites and all other servers that have EP enabled on.
                    if ($tlsPrerequisites.CheckPassed) {
                        Write-Host "TLS prerequisites check successfully passed!" -ForegroundColor Green
                        Write-Host ""
                    } else {
                        foreach ($entry in $tlsPrerequisites.ActionsRequired) {
                            Write-Host "Test Failed: $($entry.Name)" -ForegroundColor Red
                            if ($null -ne $entry.List) {
                                foreach ($list in $entry.List) {
                                    Write-Host "System affected: $list" -ForegroundColor Red
                                }
                            }
                            Write-Host "Action required: $($entry.Action)" -ForegroundColor Red
                            Write-Host ""
                        }
                        $checkAgainst = $onlineSupportedServers |
                            Where-Object {
                                $_.ExtendedProtectionConfiguration.ExtendedProtectionConfigured -eq $true -or
                                $_.ComputerName -in $serverNames
                            }

                        $results = Invoke-ExtendedProtectionTlsPrerequisitesCheck -TlsConfiguration $checkAgainst.TlsSettings

                        if ($results.CheckPassed) {
                            Write-Host "All servers attempting to enable Extended Protection or already enabled passed the TLS prerequisites."
                            Write-Host ""
                        } else {
                            Write-Warning "Failed to pass the TLS prerequisites. Unable to continue."
                            exit
                        }
                    }

                    # now that we passed the TLS PrerequisitesCheck, now we need to do the RPC VDir check for SSLOffloading.
                    $rpcFailedServers = New-Object 'System.Collections.Generic.List[string]'
                    $rpcNullServers = New-Object 'System.Collections.Generic.List[string]'
                    $canNotConfigure = "Therefore, we can not configure Extended Protection."
                    $counter = 0
                    $totalCount = $ExchangeServers.Count
                    $outlookAnywhereCount = 0
                    $outlookAnywhereServers = $ExchangeServersPrerequisitesCheckSettingsCheck | Where-Object { $_.IsClientAccessServer -eq $true }
                    $outlookAnywhereTotalCount = $outlookAnywhereServers.Count

                    $progressParams = @{
                        Id              = 1
                        Activity        = "Prerequisites Check"
                        Status          = "Running Get-OutlookAnywhere"
                        PercentComplete = 0
                    }

                    $outlookAnywhereProgressParams = @{
                        ParentId        = 1
                        Activity        = "Collecting Get-OutlookAnywhere Results"
                        PercentComplete = 0
                    }

                    Write-Progress @progressParams
                    Write-Progress @outlookAnywhereProgressParams
                    # Needs to be SilentlyContinue to handle down servers, we must also exclude pre Exchange 2013 servers
                    $outlookAnywhere = $outlookAnywhereServers | Get-OutlookAnywhere -ADPropertiesOnly -ErrorAction SilentlyContinue |
                        ForEach-Object {
                            $outlookAnywhereCount++
                            $outlookAnywhereProgressParams.PercentComplete = ($outlookAnywhereCount / $outlookAnywhereTotalCount * 100)
                            Write-Progress @outlookAnywhereProgressParams
                            $_
                        }

                    if ($null -eq $outlookAnywhere) {
                        Write-Warning "Failed to run Get-OutlookAnywhere. Failing out the script."
                        exit
                    }

                    foreach ($server in $ExchangeServers) {
                        $counter++
                        $progressParams.Status = "Checking RPC FE SSLOffloading - $($server.Name)"
                        $progressParams.PercentComplete = ($counter / $totalCount * 100)
                        Write-Progress @progressParams
                        if (-not ($server.IsClientAccessServer)) {
                            Write-Verbose "Server $($server.Name) is not a CAS. Skipping over the RPC FE Check."
                            continue
                        }
                        $rpcSettings = $outlookAnywhere | Where-Object { $_.ServerName -eq $server.Name }

                        if ($null -eq $rpcSettings) {
                            $line = "Failed to find '$($server.Name)\RPC (Default Web Site)' Virtual Directory to determine SSLOffloading value. $canNotConfigure"
                            Write-Verbose $line
                            Write-Warning $line
                            $rpcNullServers.Add($server.Name)
                        } elseif ($rpcSettings.SSLOffloading -eq $true) {
                            $line = "'$($server.Name)\RPC (Default Web Site)' has SSLOffloading set to true. $canNotConfigure"
                            Write-Verbose $line
                            Write-Warning $line
                            $rpcFailedServers.Add($server.Name)
                        } else {
                            Write-Verbose "Server $($server.Name) passed RPC SSLOffloading check"
                        }
                    }
                    Write-Progress @progressParams -Completed
                    if ($rpcFailedServers.Count -gt 0) {
                        Write-Warning "Please address the following server regarding RPC (Default Web Site) and SSL Offloading: $([string]::Join(", " ,$rpcFailedServers))"
                        Write-Warning "The following cmdlet should be run against each of the servers: Set-OutlookAnywhere 'SERVERNAME\RPC (Default Web Site)' -SSLOffloading `$false -InternalClientsRequireSsl `$true -ExternalClientsRequireSsl `$true"
                        exit
                    } elseif ($rpcNullServers.Count -gt 0) {
                        Write-Warning "Failed to find the following servers RPC (Default Web Site) for SSL Offloading: $([string]::Join(", " ,$rpcFailedServers))"
                        Write-Warning $canNotConfigure
                        exit
                    }
                    Write-Host "All servers that we are trying to currently configure for Extended Protection have RPC (Default Web Site) set to false for SSLOffloading."
                } else {
                    Write-Verbose "No online servers that are in a supported state. Skipping over TLS Check."
                }
            } else {
                Write-Warning "Failed to get Extended Protection Prerequisites Information to be able to continue"
                exit
            }

            # Configure Extended Protection based on given parameters
            # Prior to executing, add back any unsupported versions back into the list
            # for onlineSupportedServers, because the are online and we want to revert them.
            $unsupportedAndConfiguredServers | ForEach-Object { $onlineSupportedServers.Add($_) }
            $extendedProtectionConfigurations = ($onlineSupportedServers |
                    Where-Object { $_.ComputerName -in $serverNames }).ExtendedProtectionConfiguration

            if ($null -ne $extendedProtectionConfigurations) {
                Invoke-ConfigureExtendedProtection -ExtendedProtectionConfigurations $extendedProtectionConfigurations
            } else {
                Write-Host "No servers are online or no Exchange Servers Support Extended Protection."
            }

            if ($ConfigureMitigationSelected) {
                # Apply rules
                $ExchangeServers = $ExchangeServers | Where-Object { -not ((Get-ExchangeBuildVersionInformation -AdminDisplayVersion $_.AdminDisplayVersion).BuildVersion.Major -eq 15 -and (Get-ExchangeBuildVersionInformation -AdminDisplayVersion $_.AdminDisplayVersion).BuildVersion.Minor -eq 0 -and $_.IsClientAccessServer) }
                Invoke-ConfigureMitigation -ExchangeServers $ExchangeServers.Name -ipRangeAllowListRules $ipRangeAllowListRules -SiteVDirLocations $SiteVDirLocations
            }
        } elseif ($RollbackSelected) {
            Write-Host "Prerequisite check will be skipped due to Rollback"

            if ($RollbackRestoreIISAppConfig) {
                Invoke-RollbackExtendedProtection -ExchangeServers $ExchangeServers
            }

            if ($RollbackRestrictType) {
                $ExchangeServers = $ExchangeServers | Where-Object { -not ((Get-ExchangeBuildVersionInformation -AdminDisplayVersion $_.AdminDisplayVersion).BuildVersion.Major -eq 15 -and (Get-ExchangeBuildVersionInformation -AdminDisplayVersion $_.AdminDisplayVersion).BuildVersion.Minor -eq 0 -and $_.IsClientAccessServer) }
                Invoke-RollbackIPFiltering -ExchangeServers $ExchangeServers -SiteVDirLocations $SiteVDirLocations
            }

            return
        }
    } finally {
        Write-Host "Do you have feedback regarding the script? Please email ExToolsFeedback@microsoft.com."
    }
}

# SIG # Begin signature block
# MIIn1wYJKoZIhvcNAQcCoIInyDCCJ8QCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBzWQvKSNvSkpJx
# C2bzTISkOHOUD+SuAn79Rytfq2fMOKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
# OfsCcUI2AAAAAALLMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NTU5WhcNMjMwNTExMjA0NTU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC3sN0WcdGpGXPZIb5iNfFB0xZ8rnJvYnxD6Uf2BHXglpbTEfoe+mO//oLWkRxA
# wppditsSVOD0oglKbtnh9Wp2DARLcxbGaW4YanOWSB1LyLRpHnnQ5POlh2U5trg4
# 3gQjvlNZlQB3lL+zrPtbNvMA7E0Wkmo+Z6YFnsf7aek+KGzaGboAeFO4uKZjQXY5
# RmMzE70Bwaz7hvA05jDURdRKH0i/1yK96TDuP7JyRFLOvA3UXNWz00R9w7ppMDcN
# lXtrmbPigv3xE9FfpfmJRtiOZQKd73K72Wujmj6/Su3+DBTpOq7NgdntW2lJfX3X
# a6oe4F9Pk9xRhkwHsk7Ju9E/AgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUrg/nt/gj+BBLd1jZWYhok7v5/w4w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzQ3MDUyODAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAJL5t6pVjIRlQ8j4dAFJ
# ZnMke3rRHeQDOPFxswM47HRvgQa2E1jea2aYiMk1WmdqWnYw1bal4IzRlSVf4czf
# zx2vjOIOiaGllW2ByHkfKApngOzJmAQ8F15xSHPRvNMmvpC3PFLvKMf3y5SyPJxh
# 922TTq0q5epJv1SgZDWlUlHL/Ex1nX8kzBRhHvc6D6F5la+oAO4A3o/ZC05OOgm4
# EJxZP9MqUi5iid2dw4Jg/HvtDpCcLj1GLIhCDaebKegajCJlMhhxnDXrGFLJfX8j
# 7k7LUvrZDsQniJZ3D66K+3SZTLhvwK7dMGVFuUUJUfDifrlCTjKG9mxsPDllfyck
# 4zGnRZv8Jw9RgE1zAghnU14L0vVUNOzi/4bE7wIsiRyIcCcVoXRneBA3n/frLXvd
# jDsbb2lpGu78+s1zbO5N0bhHWq4j5WMutrspBxEhqG2PSBjC5Ypi+jhtfu3+x76N
# mBvsyKuxx9+Hm/ALnlzKxr4KyMR3/z4IRMzA1QyppNk65Ui+jB14g+w4vole33M1
# pVqVckrmSebUkmjnCshCiH12IFgHZF7gRwE4YZrJ7QjxZeoZqHaKsQLRMp653beB
# fHfeva9zJPhBSdVcCW7x9q0c2HVPLJHX9YCUU714I+qtLpDGrdbZxD9mikPqL/To
# /1lDZ0ch8FtePhME7houuoPcMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGbcwghmzAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggcYwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBj1f5fxfweXlIQ5xWpHRBqh
# g+zXYOnmWHeWsS8znCaOMFoGCisGAQQBgjcCAQwxTDBKoBqAGABDAFMAUwAgAEUA
# eABjAGgAYQBuAGcAZaEsgCpodHRwczovL2dpdGh1Yi5jb20vbWljcm9zb2Z0L0NT
# Uy1FeGNoYW5nZSAwDQYJKoZIhvcNAQEBBQAEggEAq9JpH4JpJOEdWlhhaBFMW/PS
# E1nJjKYBK6ElKBqw8gI8d3EfWLPyu9jZ+wiy3xh5LH12+z2GldE8RR80xwnSvtNe
# Csa3i3IZXdck4wYVTEBR/9Df1ubz++2RdCIyErBc4ekqKYXoBaX1QiHRcO2xkdN8
# 7/4T30/WLhoWsLh2JoPOUmjNrI6ESwN2c+nPWOew5nh91z41DvzuMV8/ZzdXgcBH
# zd2a+4lu9Jdk6CQVhULg1DoAKQGqSxrJo6hBZrHTOHfrklrSJRiS8T5QgECfj4xA
# vLkC+GQP78an5O2/fI2KMusiLRAlqfcINRsXcaT1M6mOK3SYNzrtEIAWiQXOpaGC
# FykwghclBgorBgEEAYI3AwMBMYIXFTCCFxEGCSqGSIb3DQEHAqCCFwIwghb+AgED
# MQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgEggFEMIIBQAIB
# AQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCAs83xNosOQqUMDXl2YEMAU
# izJB1gk2Qx0I1awBUnPenQIGZBsBSV2WGBMyMDIzMDQxMDIxMzMwOS43MzVaMASA
# AgH0oIHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhENDEtNEJGNy1CM0I3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIReDCCBycwggUPoAMCAQIC
# EzMAAAGz/iXOKRsbihwAAQAAAbMwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTAwHhcNMjIwOTIwMjAyMjAzWhcNMjMxMjE0MjAyMjAz
# WjCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UE
# CxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjo4RDQxLTRCRjctQjNCNzElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBALR8D7rmGICuLLBggrK9je3hJSpc9CTwbra/4Kb2eu5DZR6oCgFtCbig
# MuMcY31QlHr/3kuWhHJ05n4+t377PHondDDbz/dU+q/NfXSKr1pwU2OLylY0sw53
# 1VZ1sWAdyD2EQCEzTdLD4KJbC6wmAConiJBAqvhDyXxJ0Nuvlk74rdVEvribsDZx
# zClWEa4v62ENj/HyiCUX3MZGnY/AhDyazfpchDWoP6cJgNCSXmHV9XsJgXJ4l+AY
# AgaqAvN8N+EpN+0TErCgFOfwZV21cg7vgenOV48gmG/EMf0LvRAeirxPUu+jNB3J
# SFbW1WU8Z5xsLEoNle35icdET+G3wDNmcSXlQYs4t94IWR541+PsUTkq0kmdP4/1
# O4GD54ZsJ5eUnLaawXOxxT1fgbWb9VRg1Z4aspWpuL5gFwHa8UNMRxsKffor6qrX
# VVQ1OdJOS1JlevhpZlssSCVDodMc30I3fWezny6tNOofpfaPrtwJ0ukXcLD1yT+8
# 9u4uQB/rqUK6J7HpkNu0fR5M5xGtOch9nyncO9alorxDfiEdb6zeqtCfcbo46u+/
# rfsslcGSuJFzlwENnU+vQ+JJ6jJRUrB+mr51zWUMiWTLDVmhLd66//Da/YBjA0Bi
# 0hcYuO/WctfWk/3x87ALbtqHAbk6i1cJ8a2coieuj+9BASSjuXkBAgMBAAGjggFJ
# MIIBRTAdBgNVHQ4EFgQU0BpdwlFnUgwYizhIIf9eBdyfw40wHwYDVR0jBBgwFoAU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFt
# cCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcw
# AoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3Nv
# ZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIw
# ADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZI
# hvcNAQELBQADggIBAFqGuzfOsAm4wAJfERmJgWW0tNLLPk6VYj53+hBmUICsqGgj
# 9oXNNatgCq+jHt03EiTzVhxteKWOLoTMx39cCcUJgDOQIH+GjuyjYVVdOCa9Fx6l
# I690/OBZFlz2DDuLpUBuo//v3e4Kns412mO3A6mDQkndxeJSsdBSbkKqccB7TC/m
# uFOhzg39mfijGICc1kZziJE/6HdKCF8p9+vs1yGUR5uzkIo+68q/n5kNt33hdaQ2
# 34VEh0wPSE+dCgpKRqfxgYsBT/5tXa3e8TXyJlVoG9jwXBrKnSQb4+k19jHVB3wV
# UflnuANJRI9azWwqYFKDbZWkfQ8tpNoFfKKFRHbWomcodP1bVn7kKWUCTA8YG2Rl
# TBtvrs3CqY3mADTJUig4ckN/MG6AIr8Q+ACmKBEm4OFpOcZMX0cxasopdgxM9aSd
# BusaJfZ3Itl3vC5C3RE97uURsVB2pvC+CnjFtt/PkY71l9UTHzUCO++M4hSGSzkf
# u+yBhXMGeBZqLXl9cffgYPcnRFjQT97Gb/bg4ssLIFuNJNNAJub+IvxhomRrtWuB
# 4SN935oMfvG5cEeZ7eyYpBZ4DbkvN44ZvER0EHRakL2xb1rrsj7c8I+auEqYztUp
# Dnuq6BxpBIUAlF3UDJ0SMG5xqW/9hLMWnaJCvIerEWTFm64jthAi0BDMwnCwMIIH
# cTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCB
# iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMp
# TWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEw
# OTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIh
# C3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNx
# WuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFc
# UTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAc
# nVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUo
# veO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyzi
# YrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9
# fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdH
# GO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7X
# KHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiE
# R9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/
# eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3
# FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAd
# BgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEE
# AYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMB
# Af8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1Ud
# HwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3By
# b2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQRO
# MEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2Vy
# dHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4IC
# AQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pk
# bHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gng
# ugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3
# lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHC
# gRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6
# MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEU
# BHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvsh
# VGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+
# fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrp
# NPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHI
# qzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAtQwggI9AgEBMIIB
# AKGB2KSB1TCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEt
# MCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYw
# JAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4RDQxLTRCRjctQjNCNzElMCMGA1UEAxMc
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAcYtE
# 6JbdHhKlwkJeKoCV1JIkDmGggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOfeidowIhgPMjAyMzA0MTAyMTEyNTha
# GA8yMDIzMDQxMTIxMTI1OFowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA596J2gIB
# ADAHAgEAAgIJ+zAHAgEAAgIRaTAKAgUA59/bWgIBADA2BgorBgEEAYRZCgQCMSgw
# JjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3
# DQEBBQUAA4GBAJmjNLU/8vgFI7WGTrl7OQXDEkYLEY2C3LzxUDKi+FEC5Rz2Ipcu
# 5GAq9UnMBfPXM05P54pA9yGsqK+UYxMBCpMXSd1IydEGGLy7QY66mfWmHZwANJmi
# L6xx+j9z4FzQq+qpCau3sNF+j2QJwx72XyRtWZbZHWp7UD5b5g3//1CQMYIEDTCC
# BAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGz/iXO
# KRsbihwAAQAAAbMwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsq
# hkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgnqTvcaVJZtmbDpET8CqpwOkmj6+J
# g6BU17oqVN23XyowgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCGoTPVKhDS
# B7ZG0zJQZUM2jk/ll1zJGh6KOhn76k+/QjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFBDQSAyMDEwAhMzAAABs/4lzikbG4ocAAEAAAGzMCIEID+YmJqc982W
# uwWvpCk99OUqEeWr8uxycH2HhGkUPkDYMA0GCSqGSIb3DQEBCwUABIICADxQ8+Np
# jwMYayID3sk0rnOERI1yqzvO4qNekCC+Af8Jof5gcu1jJxSSb43oRWA63zavfFPm
# 0oJ2oZQBi2zqsovloXSX5KhLIY8m/8S9v9eR9tYv1gnO1lSJ4oVxMtZ/wcEi/xKL
# vNA6waujeuw/9ClVb/D6sMPXwTNAxx8YUhVI2OaZT7zTRq5Ewpft/azHBsnL5O46
# zu6Pg0KZKa25IcQfhSFQP4FStGhA1nIk3lRNjS044w0Qd1Lny4G8Vf6iNJUlGrkX
# R1Qn8Gk0NlFs81plQbjASXywxl9Vxr/DbA/BEoG/zjAgiP/E4mBsIJjNsj80IjB1
# YzT9DdpvTddedM2nEAwRwn/DGJru548mpW4gKMNosK0jHs4gl8eE9TtDPRyrWmAX
# GFxRnhJUQKgoNLeX/HSX4hjrZf9CWwpXiUUs2sQkqHRUno0lm5HWnwVpGku6zNu4
# 7juzliN+CQD42rFGlYFhVjpk2vSWnrXqW7qWTDjIhL+0r5yb9LCpTVxnWo/6HG85
# ay/FFmcDVQYWkf9UoR6ixcq8ZhnSC5DVqvV9/hAXIklrpb2IKLrW8MQW/5RsF6+W
# byq6EvNJKsXAvB+V4dHaDJKaKJmJB9OC3RdjIpZ5mj28c3Mzgba0uRy2Mjhymqkx
# t04dwMMnWbLnyUluGB3moO7/Hn/OBsqY3e4E
# SIG # End signature block
