$mailboxes = get-mailbox -resultsize unlimited

# Show what commands we would run
foreach ($mailbox in $mailboxes) {
  $alias = $mailbox.alias
  $cmd2="Set-Mailbox `"" + $mailbox.alias + "`" -PrimarySMTPAddress `"" + $alias + "@guadalupetx.gov`" -EmailAddressPolicyEnabled:`$false -ErrorAction SilentlyContinue"
  write-host $cmd2
}
