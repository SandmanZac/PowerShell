$domain_name = $env:userdnsdomain;

$dns_name = $env:computername + '.' + $domain_name;
$date_now = Get-Date;
$extended_date = $date_now.AddYears(3);

$mycert=New-SelfSignedCertificate -DnsName $dns_name -CertStoreLocation cert:/LocalMachine/My -NotAfter $extended_date;

$thumbprint=($mycert.Thumbprint | Out-String).Trim();
$certStoreLoc='HKLM:/Software/Microsoft/Cryptography/Services/NTDS/SystemCertificates/My/Certificates';
if (!(Test-Path $certStoreLoc)){New-Item $certStoreLoc -Force;};
Copy-Item -Path HKLM:/Software/Microsoft/SystemCertificates/My/Certificates/$thumbprint -Destination $certStoreLoc;
