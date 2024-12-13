$DNSServers = "192.168.1.2,192.168.1.3"
$Scopes = Get-DhcpServerv4Scope

foreach ($Scope in $Scopes) {
    Set-DhcpServerv4OptionValue -ScopeId 10.1.1.0 -OptionId 6 -Value $DNSServers -Force
}
