$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    -not (Get-Command New-LocalUser -ErrorAction SilentlyContinue)) {
    Write-Host 'SKIP second Windows identity: runner cannot create a disposable local account'
    exit 0
}

$name = 'tdc-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$password = 'aA9!' + [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(24))
$account = $null
try {
    $account = New-LocalUser -Name $name -Password (ConvertTo-SecureString $password -AsPlainText -Force)
    $users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    if (-not (Get-LocalGroupMember -SID $users | Where-Object { $_.SID -eq $account.SID })) {
        Add-LocalGroupMember -SID $users -Member $account
    }
    $env:TDC_TEST_WINDOWS_USER = $name
    $env:TDC_TEST_WINDOWS_PASSWORD = $password
    $env:TDC_TEST_WINDOWS_SID = $account.SID.Value
    rustup run $env:TDC_RUST cargo test --release --locked --target $env:TDC_TARGET --bin tdc-vanity -- --show-output
    if ($LASTEXITCODE -ne 0) { throw "File access test failed with exit code $LASTEXITCODE" }
} finally {
    Remove-Item Env:TDC_TEST_WINDOWS_USER, Env:TDC_TEST_WINDOWS_PASSWORD, Env:TDC_TEST_WINDOWS_SID `
        -ErrorAction SilentlyContinue
    if ($null -ne $account) { Remove-LocalUser -SID $account.SID }
}
