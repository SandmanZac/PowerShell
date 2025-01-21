$groups = get-distributiongroup

foreach ($group in $groups) {
    $alias = $group.Alias
    $newEmailAddress = $alias + "@guadalupetx.gov"
    Set-DistributionGroup -Identity $group.Identity -EmailAddresses @{Add=$newEmailAddress} -EmailAddressPolicyEnabled:$false -primarySmtpAddress $newEmailAddress -ErrorAction SilentlyContinue
}
