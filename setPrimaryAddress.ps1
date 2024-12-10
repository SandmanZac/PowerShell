$mailboxes = get-mailbox -resultsize unlimited

# Execute the changes
foreach ($mailbox in $mailboxes) {
  $alias = $mailbox.alias
  $newPrimaryAddress = $alias + "@guadalupetx.gov"
  $cmd="Set-Mailbox " + $alias + " -PrimarySmtpAddress " + $newPrimaryAddress + " -EmailAddressPolicyEnabled:`$false -ErrorAction SilentlyContinue"
  write-host $cmd
  set-mailbox $alias -primarysmtpaddress $newPrimaryAddress -EmailAddressPolicyEnabled:$false -ErrorAction SilentlyContinue
}
