$groups = get-distributiongroup

foreach ($group in $groups) {
    $alias = $group.Alias
    $newEmailAddress = $alias + "@guadalupetx.gov"
    Set-DistributionGroup -Identity $group.Identity -EmailAddresses @{Add=$newEmailAddress} -ErrorAction SilentlyContinue
    Set-DistributionGroup -Identity $group.Identity -EmailAddressPolicyEnabled:$false -ErrorAction SilentlyContinue
    Set-DistributionGroup -Identity $group.Identity -primarySmtpAddress $newEmailAddress -ErrorAction SilentlyContinue
}
