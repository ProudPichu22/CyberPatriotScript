function Log-Action {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path "cyberpatriot.log" -Value "$timestamp - $Message"
}