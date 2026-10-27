<#
.SYNOPSIS
    Generates cryptographic salted SHA-256 hashes for the Nexora Admin Portal.
.DESCRIPTION
    Use this script whenever you want to rotate or change your Admin Phone number
    or Admin Password. Plaintext passwords are never stored in the website source code.
.EXAMPLE
    .\generate-admin-hash.ps1 -Phone "8595581933" -Password "YourNewStrongPassword123"
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$Phone,

    [Parameter(Mandatory=$false)]
    [string]$Password,

    [Parameter(Mandatory=$false)]
    [string]$Salt = "nexora_salt_9e3b7c84f1a26d"
)

if (-not $Phone) {
    $Phone = Read-Host "Enter Admin Phone Number (digits only)"
}
$cleanPhone = $Phone -replace '[^0-9]', ''

if (-not $Password) {
    $Password = Read-Host "Enter New Admin Password" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}

$sha256 = [System.Security.Cryptography.SHA256]::Create()

# Phone Hash
$phoneBytes = [System.Text.Encoding]::UTF8.GetBytes($Salt + $cleanPhone)
$phoneHash = [System.BitConverter]::ToString($sha256.ComputeHash($phoneBytes)).Replace("-", "").ToLower()

# Password Hash
$passBytes = [System.Text.Encoding]::UTF8.GetBytes($Salt + $Password)
$passHash = [System.BitConverter]::ToString($sha256.ComputeHash($passBytes)).Replace("-", "").ToLower()

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       NEXORA ADMIN CRYPTOGRAPHIC CREDENTIALS" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Salt:        $Salt" -ForegroundColor DarkGray
Write-Host "Clean Phone: $cleanPhone" -ForegroundColor Yellow
Write-Host ""
Write-Host "Copy and paste the following block into AUTH_CONFIG in admin.html:" -ForegroundColor White
Write-Host ""
Write-Host "const AUTH_CONFIG = {" -ForegroundColor Yellow
Write-Host "  salt: '$Salt'," -ForegroundColor Yellow
Write-Host "  phoneHash: '$phoneHash'," -ForegroundColor Yellow
Write-Host "  passHash: '$passHash'," -ForegroundColor Yellow
Write-Host "  maxAttempts: 5," -ForegroundColor Yellow
Write-Host "  lockoutDurationMs: 15 * 60 * 1000," -ForegroundColor Yellow
Write-Host "  sessionDurationMs: 2 * 60 * 60 * 1000" -ForegroundColor Yellow
Write-Host "};" -ForegroundColor Yellow
Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
