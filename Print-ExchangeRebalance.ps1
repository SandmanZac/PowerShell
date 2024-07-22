<#
.SYNOPSIS
This is a proof of concept script for balancing mailboxes within an exchange environment
across databases in an effort to make the databases as equal in size as possible with
the fewest possible mailbox moves.

.DESCRIPTION
This is a proof of concept script for balancing mailboxes within an exchange environment
across databases in an effort to make the databases as equal in size as possible with
the fewest possible mailbox moves.

.NOTES
Author: Zachary Loeber

#>

# Global Parameters **Change these as you see fit**
$IGNORED_MAILBOXES = @('HealthMailbox','Discovery Search Mailbox','SystemMailbox')
$ESC_IGNORED_MAILBOXES = @($IGNORED_MAILBOXES | Foreach {[regex]::Escape($_)})

$SEARCH_DATABASES = @('DAG1-SODB1','DAG2-SODB1','DAG1-SODB2')
#$SEARCH_DATABASES = @('DB00','DB01','DB02','DB03')
$ESC_SEARCH_DATABASES = @($SEARCH_DATABASES | Foreach {[regex]::Escape($_)})

$MBSIZE_FLOOR = 1           # Ignore mailboxes below this size (in Mb). Defaulting to 1 is a good idea to reduce processing for negligable mailboxes
$MBSIZE_CEILING = 100000    # Ignore mailboxes above this size (in Mb)

$MailboxMoveRequestTemplate = 'New-MoveRequest -Identity "{0}" -TargetDatabase {1} -BatchName {1} -AllowLargeItems:$true -Confirm:$false -AcceptLargeDataLoss:$true -BadItemLimit 10000 -WarningAction:silentlycontinue'
$ResultsFile = 'Mailbox-Moves.txt'
$DataFile = 'ExchangeMailboxData.csv'

$JUMBO_MAILBOX_VARIENCE = 0     # Mailboxes will be ignored if their size is greater 
                                #  than the overall average DB size minus $JUMBO_MAILBOX_VARIENCE
#region Functions
function Get-DBDiffTable {
    # This function takes our custom array of psobject data and builds another array of all DB relationships,
    # their current difference in size, and methods to recalculate the sizes in the future.
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        $DBTable
    )
    begin {
        $DBTables = @()
        $ReturnTable = @()
        $ID = 0
    }
    process {
        $DBTables += $DBTable
    }
    end {
        for ($Start = 0; $Start -lt $DBTables.Count; $Start++) {
        	for ($index = $Start+1; $index -ne $DBTables.Count; $index++) {
                $DiffProps = @{
                    'ID' = $ID
                    'DB1' = $DBTables[$Start].Database
                    'DB2' = $DBTables[$index].Database
                    'SizeDiff' = [Math]::Abs(($DBTables[$Start].Size - $DBTables[$index].Size))
                    'BeenProcessed' = $false
                    'Order' = 0
                }
                $DiffTableElement = New-Object PSObject -Property $DiffProps
                $DiffTableElement | Add-Member -MemberType ScriptMethod -Name UpdateDiff -Value {
                    param ($DBTable)
                    $this.ValueDiff = [Math]::Abs(($DBTable[$this.DB1].Size - $DBTable[$this.DB2].Size))
                }
                $DiffTableElement | Add-Member -MemberType ScriptMethod -Name GetLargerDB -Value {
                    param ($DBTable)
                    if ($DBTable[$this.DB1].Size -eq $DBTable[$this.DB2].Size) {
                        $greater = $null
                    } 
                    elseif ($DBTable[$this.DB2].Size -gt $DBTable[$this.DB1].Size) {
                        $greater = $this.DB2
                    }
                    else {
                        $greater = $this.DB1
                    }
                    return $greater
                }
                $DiffTableElement | Add-Member -MemberType ScriptMethod -Name GetSmallerDB -Value {
                    param ($DBTable)
                    if ($DBTable[$this.DB1].Size -eq $DBTable[$this.DB2].Size) {
                        $smaller = $null
                    } 
                    elseif ($DBTable[$this.DB2].Size -lt $DBTable[$this.DB1].Size) {
                        $smaller = $this.DB2
                    }
                    else {
                        $smaller = $this.DB1
                    }
                    return $smaller
                }
                $DiffTableElement | Add-Member -MemberType ScriptMethod -Name SetHasBeenProcessed -Value {
                    param ([string]$DB)
                    if (($this.DB1 -eq $DB) -or ($this.DB2 -eq $DB)) {
                        $this.BeenProcessed = $true
                    }
                }
                
                $DiffTableElement | Add-Member -MemberType ScriptMethod -Name Reset -Value {
                    $this.BeenProcessed = $false
                    $this.Order = 0
                }
                
                $DiffTableElement | Add-Member -MemberType ScriptMethod -Name RecalcDifference -Value {
                    param ($DBTable)
                    $this.SizeDiff = [Math]::Abs(($DBTable[$this.DB1].Size - $DBTable[$this.DB2].Size))
                }
                
                $ReturnTable += $DiffTableElement
                $ID++
            }
        }
        return $ReturnTable
    }
}

function ConvertTo-HashArray {
    <#
    .SYNOPSIS
    Convert an array of objects to a hash table based on a single property of the array.     
    .DESCRIPTION
    Convert an array of objects to a hash table based on a single property of the array.
    .PARAMETER InputObject
    An array of objects to convert to a hash table array.
    .PARAMETER PivotProperty
    The property to use as the key value in the resulting hash.
    .PARAMETER OverwriteDuplicates
    If the pivotproperty is found multiple times then overwrite the current hash value. Default is to skip duplicates.
    .EXAMPLE
    $test = @()
    $test += New-Object psobject -Property @{'Server' = 'Server1'; 'IP' = '1.1.1.1'}
    $test += New-Object psobject -Property @{'Server' = 'Server2'; 'IP' = '2.2.2.2'}
    $test += New-Object psobject -Property @{'Server' = 'Server2'; 'IP' = '3.3.3.3'}
    $test | ConvertTo-HashArray -PivotProperty Server
    
    Name                           Value                                                                                                                  
    ----                           -----                                                                                                                  
    Server1                        @{Server=Server1; IP=1.1.1.1}                                                                                          
    Server2                        @{Server=Server2; IP=2.2.2.2} 
    Description
    -----------
    Convert and output a hash array based on the server property (skipping duplicate values)
    
    .NOTES
    Author: Zachary Loeber
    #>
    [CmdLetBinding(DefaultParameterSetName='AsObjectArray')]
    param(
        [Parameter(ParameterSetName='AsObjectArray', Mandatory=$True, ValueFromPipeline=$True, Position=0)]
        [AllowEmptyCollection()]
        [PSObject[]]$InputObjects,
        [Parameter(ParameterSetName='AsObject', Mandatory=$True, ValueFromPipeline=$True, Position=0)]
        [AllowEmptyCollection()]
        [PSObject]$InputObject,
        [Parameter(Mandatory=$true)]
        [string]$PivotProperty,
        [Parameter()]
        [switch]$OverwriteDuplicates,
        [Parameter(HelpMessage='Property in the psobject to be the value that the hash key points to. If not specified, all properties in the psobject are used.')]
        [string]$LookupValue = ''
    )

    begin {
        Write-Verbose "$($MyInvocation.MyCommand): Begin"
        $allObjects = @()
        $Results = @{}
    }
    process {
        $allObjects += $inputObject
        switch ($PSCmdlet.ParameterSetName) {
            'AsObjectArray' {
                $allObjects = $InputObjects
            }
            'AsObject' {
                $allObjects = @($InputObject)
            }
        }
        foreach ($object in ($allObjects | where {$_ -ne $null})) {
            try {
                if ($object.PSObject.Properties.Match($PivotProperty).Count) {
                    if ($LookupValue -eq '') {
                        if (-not $Results.ContainsKey($object.$PivotProperty) -or $OverwriteDuplicates) {
                            $Results[$object.$PivotProperty] = $object
                        }
                    }
                    else {
                        if ($object.PSObject.Properties.Match($LookupValue).Count) {
                            if (-not $Results.ContainsKey($object.$PivotProperty) -or $OverwriteDuplicates) {
                                $Results[$object.$PivotProperty] = $object.$LookupValue
                            }
                        }
                        else {
                            Write-Warning -Message "$($MyInvocation.MyCommand): LookupValue ($LookupValue) Not Found"
                        }
                    }
                }
                else {
                    Write-Warning -Message "$($MyInvocation.MyCommand): PivotProperty ($PivotProperty) Not found in object"
                }
            }
            catch {
                Write-Warning -Message "$($MyInvocation.MyCommand): Something weird happened!"
            }
        }
    }
    end {
        Write-Output -InputObject $Results
        Write-Verbose "$($MyInvocation.MyCommand): End"
    }
}
#endregion Functions

#region Gather Mailbox Info
$Mailboxes = @()

Write-Output 'Gathering mailboxes, this may take a while...'
Get-MailboxDatabase |
Where {$_.Name -match ('^(' + ($ESC_SEARCH_DATABASES -join '|') + ')$')} |
Get-MailboxStatistics | Foreach {
    $mbxprop = @{
        'Name' = $_.DisplayName
        'SourceDB' = $_.DatabaseName
        'Database' = $_.DatabaseName
        'Size' = $_.TotalItemSize.Value.ToMB()
        'Moved' = 0
        'Ignore' = $false
        'Jumbo' = $false
        'State' = $_.DisconnectReason
    }
    $Mailboxes += new-object psobject -Property $mbxprop
}

$Mailboxes | Export-Csv -NoTypeInformation $DataFile
Write-Output "$DataFile has been written to this directory."
#endregion Mailbox Info

#region DB Info
$WorkingDBTable = @()
$Databases = @{}

# First get a unique list of databases with active mailboxes
$DBSet = @($Mailboxes | Select Database -unique | Foreach {$_.Database})

# Go through each DB and get a total size
foreach ($DB in $DBSet) {
    $DBSize = 0
    
    $Mailboxes | Where {($_.Database -eq $DB) -and (-not $_.Ignore)} | Foreach {
        $DBSize += $_.Size
    }
    # Keep a hash of our databases and their size
    $Databases.Add($DB,$DBSize)
    
    # Create a custom psobject that will represent the database, its size, and stats on event state from the last actions
    $DBHash = @{
        'Database' = $DB
        'Size' = $DBSize
        'MovedFromThisTime' = $false
        'MovedFromLastTime' = $false
        'MovedToThisTime' = $false
        'MovedToLastTime' = $false
    }
    $DBElement = New-Object psobject -Property $DBHash
    Add-Member -InputObject $DBElement -MemberType ScriptMethod -Name ResetMoveState -Value {
        $this.MovedFromLastTime = $this.MovedFromThisTime
        $this.MovedFromThisTime = $false
        $this.MovedToLastTime = $this.MovedToThisTime
        $this.MovedToThisTime = $false
    }
    $WorkingDBTable += $DBElement
}

# Gather unique combinations of all size differences between the databases and store for later
$DBDiffTable = Get-DBDiffTable $WorkingDBTable
$WorkingDBTable = ConvertTo-HashArray -InputObject $WorkingDBTable -PivotProperty Database
$TotalDBSize = ($Databases.Values | Measure-Object -Sum).Sum
$AverageDBSize = [Math]::Round(($TotalDBSize/($Databases.Count)),0)
#endregion DB Info

# Any mailbox larger than our average db size, the preset ceiling, smaller than the preset floor, or
# matching ignored mailboxes are exempt from any possible move requests.
$Mailboxes | Where {-not $_.Ignore} | ForEach {
    if ($_.Size -ge ($AverageDBSize - $JUMBO_MAILBOX_VARIENCE)) {
        $_.Jumbo = $true
        $_.Ignore = $true
    }
    if (($_.Size -gt $MBSIZE_CEILING) -or 
        ($_.Size -lt $MBSIZE_FLOOR)) {
        $_.Ignore = $true
    }
}

# Only work with mailboxes we are not ignoring.
$Mailboxes = @($Mailboxes | Where {-not $_.Ignore})

# So you don't have to remember everything here is a general rundown of the main variables in play:
#   $Databases = Plain ol' hash table with database names and their starting overall size.
#   $WorkingDBTable = Array of hash tables where the keys are databases and the value is a psobject with several db properties.
#                     This will get updated numerous times as we figure out mailboxes which can be moved and will be used
#                     to update the DB difference table.
#   $DBDiffTable = Array of psobjects that not only contain all unique (non-order specific) combinations of differences between
#                  all the databases but also contains some methods for self updating several properties. This will be our primary
#                  source for deciding which bins to work on and will be updated frequently.

#region Main
# We start 'rebalancing' 
$Rebalancing = $true

while ($Rebalancing) {
    # Update the status of the most recent moves. This is used purely for weight assignment when selecting which bins to
    # move objects to/from (which is not actually implemented as of yet)
    $WorkingDBTable.Keys | Foreach { 
        $WorkingDBTable[$_].ResetMoveState()
    }
    
    # Reset the BeenProcessed and Order parameters
    $DBDiffTable | Foreach {
        $_.Reset()
    }

    $MovesPerformed = 0
    $DiffTable = $null
    $FirstRun = $true
    # if there are no tables with any differences we are done, otherwise plow forward
    while (($DiffTable -ne $null) -or ($FirstRun)) {
        $FirstRun = $false
        $DiffTable = @($DBDiffTable | Where {($_.SizeDiff -ne 0) -and ($_.BeenProcessed -eq $false)})
        
        # This will find the bin sets with the largest differences
        $DiffMaxMin = ($DiffTable | Where {$_.BeenProcessed -eq $false} | Foreach {$_.SizeDiff}) | Measure-Object -Maximum -Minimum
        $WorkingDiffTable = @($DiffTable | Where {$_.SizeDiff -eq $DiffMaxMin.Maximum})
        if ($WorkingDiffTable.Count -ge 1) {
            Write-Verbose -Message ('Processing tables: {0}' -f $WorkingDiffTable.Count)
            # If we have more than one set of bins which are top contenders then use this area to add
            # logic on which one to use. The idea is to add the ordering to the 'order' property. This
            # 'order' can also be considered a weight. For now I don't assign any weight though.
            $order = 0
            $WorkingDiffTable | Foreach {
                $_.Order = $order
                $order++
            }
            $WorkingDiffTable = @($WorkingDiffTable | Sort-Object -Property Order)
            Write-Verbose -Message ('DB Differences to process: {0}' -f $WorkingDiffTable.Count)
            for ($i = 0; $i -lt $WorkingDiffTable.Count; $i++) {
                if (-not $WorkingDiffTable[$i].BeenProcessed) {
                    # Here is the actual logic used to determine if we are moving objects from one bin to another
                    # Find the first bin object which is the closest to our size difference.
                    $SmallerDB = $WorkingDiffTable[$i].GetSmallerDB($WorkingDBTable)
                    $LargerDB = $WorkingDiffTable[$i].GetLargerDB($WorkingDBTable)
                    Write-Verbose -Message ('DB difference to process from {0} => {1}' -f $LargerDB,$SmallerDB)
                    $MoveCandidate = $Mailboxes | 
                                        Where {($_.Database -eq $LargerDB) -and `
                                               ($_.Size -le $WorkingDiffTable[$i].SizeDiff) -and `
                                               ($_.Ignore -ne $true)} |
                                        Sort-Object -Property Size -Descending |
                                        Select -First 1
                    if ($MoveCandidate) {
                        Write-Verbose -Message ('Move Candidate[{0}]: {1} => {2}' -f $MoveCandidate.Name,$LargerDB,$SmallerDB)
                        $mbxsize = $MoveCandidate.Size
                        $FutureDiff = [Math]::Abs((($WorkingDBTable[$SmallerDB].Size + $mbxsize) - ($WorkingDBTable[$LargerDB].Size - $mbxsize)))

                        # if we found a move contender then check to see if the move results in a difference between the two
                        # bins changing where the smaller bin actually becomes larger than the source bin. 
                        if (($WorkingDBTable[$SmallerDB].Size + $mbxsize) -ge ($WorkingDBTable[$LargerDB].Size - $mbxsize)) {
                            # Get a mailbox from the destination bin which is no more than the future difference between the
                            # two bins.
                            $MailboxSwapCandidate = $Mailboxes | 
                                                    Where {($_.Database -eq $SmallerDB) -and `
                                                           ($_.Size -le $FutureDiff) -and `
                                                           (-not $_.Ignore)} |
                                                    Sort-Object -Property Size -Descending |
                                                    Select -First 1
                            Write-Verbose -Message ('Swap candidate [{0}]: {1} => {2}' -f $MailboxSwapCandidate.Name,$SmallerDB,$LargerDB)
                            if ($MailboxSwapCandidate) {
                                # We have a winner so process the swap
                                $Mailboxes | Where {$_.Name -eq $MailboxSwapCandidate.Name} | Foreach {
                                    $_.Moved++
                                    $_.Ignore = $true
                                    $_.Database = $LargerDB
                                }
                                $WorkingDBTable[$SmallerDB].Size -= $MailboxSwapCandidate.Size
                                $WorkingDBTable[$LargerDB].Size += $MailboxSwapCandidate.Size
                                $MovesPerformed++
                            }
                        }
                        $Mailboxes | 
                            Where {$_.Name -eq $MoveCandidate.Name} | Foreach {
                                $_.Moved++
                                $_.Ignore = $true
                                $_.Database = $SmallerDB
                            }
                        $WorkingDBTable[$SmallerDB].Size += $MoveCandidate.Size
                        $WorkingDBTable[$LargerDB].Size -= $MoveCandidate.Size
                        $MovesPerformed++
                        
                        # Make certain that if any databases were processed that we ignore future differences that
                        # contain the same databases in this itteration.
                        $WorkingDiffTable | ForEach {
                            if ($SmallerDB -ne $null) {$_.SetHasBeenProcessed($SmallerDB)}
                            if ($LargerDB -ne $null) {$_.SetHasBeenProcessed($LargerDB)}
                        }

                        # Update our base db difference table. Also update our differences.
                        $DBDiffTable | Foreach {
                            if ($SmallerDB -ne $null) {$_.SetHasBeenProcessed($SmallerDB)}
                            if ($LargerDB -ne $null) {$_.SetHasBeenProcessed($LargerDB)}
                            $_.RecalcDifference($WorkingDBTable)
                        }
                    }
                    else {
                        # Otherwise we have finished without a move performed but we still need to 
                        # mark that we processed this set of bins
                        $DiffTable | Where {$_.ID -eq $WorkingDiffTable[$i].ID} | %{$_.BeenProcessed = $true}

                        Write-Verbose -Message ('Nothing moved from {0} to {1}' -f $LargerDB,$SmallerDB)
                    }
                }
            }
        }
        else {
            if ($MovesPerformed -eq 0) {
                $Rebalancing = $false
            }
        }
    }
}

$MoveRequests = @()
$ConsoleOutput = @()
$Mailboxes | 
    sort-object -Property Database | 
    Where {$_.SourceDB -ne $_.Database} | 
    select Name,@{n='Mailbox Size';e={$_.Size}},@{n='Source DB';e={$_.SourceDB}},@{n='Dest DB';e={$_.Database}} | 
    ForEach {
        $ConsoleOutput += $_
        $MoveRequests += $MailboxMoveRequestTemplate -f $_.Name,$_.'Dest DB'
    }
$MoveRequests | Out-File $ResultsFile

$Report = @"
Average database size: $AverageDBSize

Original database size information:
$($Databases.Keys | Select @{n='Database';e={$_}},@{n='Size';e={$Databases[$_]}} | Sort-Object Database | ft -AutoSize | Out-String)

Future database size information:
$($WorkingDBTable.Keys | Select @{n='Database';e={$_}},@{n='Size';e={$WorkingDBTable[$_].Size}} | Sort-Object Database | ft -AutoSize | Out-String)

Total Moves Required = $(($Mailboxes | sort-object -Property Database | Where {$_.SourceDB -ne $_.Database}| Measure-Object).Count)

Please review the Mailbox-Moves.txt file for use in migrating these mailboxes.

Alternatively you can run this script again after manually moving mailboxes to try and level out the database sizes.
"@

Write-Output $Report | More
#endregion Main
