$mailboxes = get-mailbox -resultsize unlimited

# Execute the changes
foreach ($mailbox in $mailboxes) {
  $alias = $mailbox.alias
  $cmd="Set-Mailbox `"" + $mailbox.alias + "`" -PrimarySmtpAddress `"" + $alias + "@guadalupetx.gov`" -EmailAddressPolicyEnabled:`$false -ErrorAction SilentlyContinue"
  write-host $cmd
  set-mailbox $mailbox.alias -primarysmtpaddress $alias + "@guadalupetx.gov" -EmailAddressPolicyEnabled:$false -ErrorAction SilentlyContinue
}
