$mailboxes = get-mailbox -resultsize unlimited

# Execute the changes
foreach ($mailbox in $mailboxes) {
  $alias = $mailbox.alias
  $cmd="Set-Mailbox `"" + $mailbox.alias + "`" -EmailAddresses @{add=`"" + $alias + "@guadalupetx.gov`"} -EmailAddressPolicyEnabled:`$false -ErrorAction SilentlyContinue"
  write-host $cmd
  set-mailbox $mailbox.alias -emailaddresses @{Add=$alias + "@guadalupetx.gov"} -EmailAddressPolicyEnabled:$false -ErrorAction SilentlyContinue
}
