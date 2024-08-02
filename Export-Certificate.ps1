<#
.SYNOPSIS
Export a certificate to PEM and/or PFX format.

.DESCRIPTION
This script finds a specified certificate by its Common Name (CN) in the Windows Certificate Store and exports it to PEM and/or PFX format.

.PARAMETER CertificateName
The Common Name (CN) of the certificate to export. Also displayed as "Subject".

.EXAMPLE
.\Export-Certificate.ps1 -CertificateName "MyCertificate"

This command exports the certificate with the specified name to both PEM and PFX formats.

.NOTES
For PEM export, the private key of the certificate must be marked as exportable.

#>
param(
    [Parameter(Mandatory=$true)]
    [string]$CertificateName,

    [Parameter(Mandatory=$false)]
    [bool]$ExportPEM = $true,

    [Parameter(Mandatory=$false)]
    [bool]$ExportPFX = $true
)

# Function to sanitize file name
function Sanitize-FileName {
    param (
        [Parameter(Mandatory=$true)][string]$name
    )

    # Replace illegal characters with an underscore
    return $name -replace "[^\w\d]", "_"
}

# Function to find a certificate by CN
function Find-Certificate {
    param (
        [Parameter(Mandatory=$true)][string]$certName
    )

    $certPath = "Cert:\LocalMachine\My"
    $cert = Get-ChildItem -Path $certPath | Where-Object { $_.Subject -like "*CN=$certName*" }
    if ($null -eq $cert) {
        Write-Error "Certificate with CN '$certName' not found."
        return $null
    }

    return $cert
}

# Function to export certificate to PEM format
function Export-ToPEM {
    param (
        [Parameter(Mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
    )

    $sanitizedCertName = Sanitize-FileName -name $CertificateName
    $currentPath = Get-Location
    $pemOutputPath = "$currentPath\$sanitizedCertName.pem"

    # Export the certificate to PEM format
    $certBytes = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
    $certEncoded = [System.Convert]::ToBase64String($cert.Export($certBytes), [System.Base64FormattingOptions]::InsertLineBreaks)
    $certPem = "-----BEGIN CERTIFICATE-----`n$certEncoded`n-----END CERTIFICATE-----"
    # Export the private key to PEM format
    $privateKey = $cert.PrivateKey
    $privateKeyBytes = $privateKey.ExportCspBlob($true)
    $privateKeyBase64 = [System.Convert]::ToBase64String($privateKeyBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
    $privateKeyPem = "-----BEGIN CERTIFICATE-----`n$certEncoded`n-----END CERTIFICATE-----`n-----BEGIN PRIVATE KEY-----`n$privateKeyBase64`n-----END PRIVATE KEY-----"
    [System.IO.File]::WriteAllText($pemOutputPath, $privateKeyPem)
}

# Function to export certificate to PFX format
function Export-ToPFX {
    param (
        [Parameter(Mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
    )

    $sanitizedCertName = Sanitize-FileName -name $CertificateName
    $currentPath = Get-Location
    $certOutputPath = "$currentPath\$sanitizedCertName.pfx"

    # Export the certificate to PFX format
    $securePassword = Read-Host -AsSecureString "Enter password for PFX file"
    Export-PfxCertificate -Cert $cert -FilePath $certOutputPath -Password $securePassword
}

# Function to export the public key of the certificate to a .cer file
function Export-ToCER {
    param (
        [Parameter(Mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
    )

    $sanitizedCertName = Sanitize-FileName -name $CertificateName
    $currentPath = Get-Location
    $cerOutputPath = "$currentPath\$sanitizedCertName.cer"

    # Export the public key of the certificate to a .cer file
    $certBytes = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
    $certEncoded = $cert.Export($certBytes)
    [System.IO.File]::WriteAllBytes($cerOutputPath, $certEncoded)
}

# Main script execution logic
$cert = Find-Certificate -certName $CertificateName

if ($null -eq $cert) {
    return
}

# Export to PEM if selected
if ($ExportPEM) {
    Export-ToPEM -cert $cert
}

# Export to PFX if selected
if ($ExportPFX) {
    Export-ToPFX -cert $cert
}

# Export to .CER if selected
if ($ExportCER) {
    Export-ToCER -cert $cert
}

# Export to all formats if no specific format is selected
if (-not $ExportPEM -and -not $ExportPFX -and -not $ExportCER) {
    Export-ToPEM -cert $cert
    Export-ToPFX -cert $cert
    Export-ToCER -cert $cert
}

Write-Host "Certificate export completed."
