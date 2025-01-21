$mailboxes = get-mailbox -resultsize unlimited

# Execute the changes
foreach ($mailbox in $mailboxes) {
  $alias = $mailbox.alias
  $newPrimaryAddress = $alias + "@guadalupetx.gov"
  set-mailbox $alias -EmailAddresses @{Add=$newPrimaryAddress} -ErrorAction SilentlyContinue
  set-mailbox $alias -primarysmtpaddress $newPrimaryAddress -ErrorAction SilentlyContinue
  set-mailbox $alias -EmailAddressPolicyEnabled:$false -ErrorAction SilentlyContinue
}
