# PowerShell translation of the Python script

# Utility functions
function RunAsAdmin {
    if (-not ([bool](New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
        Write-Output "Please run this script as administrator."
        exit 1
    }
}

function NextStep {
    param (
        [string]$Message
    )
    $global:Step++
    cls
    Write-Output "($global:Step/$global:TotalSteps) - $Message"
}

# Initialize variables
$global:Step = 0
$global:TotalSteps = 5
$servicesToDisable = @(
    "Telephony", "TapiSrv", "Tlntsvr", "p2pimsvc", "simptcp", "fax", "msftpsvc",
    "iprip", "ftpsvc", "RasMan", "RasAuto", "seclogon", "W3SVC", "SMTPSVC", "Dfs",
    "TrkWks", "MSDTC", "DNS", "ERSVC", "NtFrs", "helpsvc", "HTTPFilter",
    "IISADMIN", "IsmServ", "WmdmPmSN", "Spooler", "RDSessMgr", "RPCLocator",
    "ShellHWDetection", "ScardSvr", "Sacsvr", "Uploadmgr", "VDS", "VSS", "WINS",
    "WinHttpAutoProxySvc", "SZCSVC", "CscService", "hidserv", "IPBusEnum",
    "PolicyAgent", "SCPolicySvc", "SharedAccess", "SSDPSRV", "Themes",
    "upnphost", "nfssvc", "nfsclnt", "MSSQLServerADHelper"
)

$RegistryCommands = @(
    "reg add HKLM/SOFTWARE/Policies/Microsoft/Windows/WindowsUpdate/AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f",
    "reg add HKLM/SOFTWARE/Policies/Microsoft/Windows/WindowsUpdate/AU /v NoAutoUpdate /t REG_DWORD /d 0 /f",
    "reg add HKLM/SOFTWARE/Policies/Microsoft/Windows/WindowsUpdate/AU /v AUOptions /t REG_DWORD /d 4 /f",
    "reg add HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/WindowsUpdate/Auto Update/ /v AUOptions /t REG_DWORD /d 4 /f",
    "reg add HKLM/SOFTWARE/Policies/Microsoft/Windows/WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f",
    "reg add HKLM/SOFTWARE/Policies/Microsoft/Windows/WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f",
    "reg add HKCU/SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f",
    "reg add /HKLM/SYSTEM/Internet Communication Management/Internet Communication/ /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f",
    "reg add HKCU/SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f",
    "reg ADD /HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Winlogon/ /v AllocateCDRoms /t REG_DWORD /d 1 /f",
    "reg ADD /HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Winlogon/ /v AllocateFloppies /t REG_DWORD /d 1 /f",
    "reg ADD /HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Winlogon/ /v AutoAdminLogon /t REG_DWORD /d 0 /f",
    "reg ADD /HKLM/SYSTEM/CurrentControlSet/Control/Session Manager/Memory Management/ /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f",
    "reg ADD /HKLM/SYSTEM/CurrentControlSet/Control/Print/Providers/LanMan Print Services/Servers/ /v AddPrinterDrivers /t REG_DWORD /d 1 /f",
    "reg add /HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Image File Execution Options/LSASS.exe/ /v AuditLevel /t REG_DWORD /d 00000008 /f",
    "reg add HKLM/SYSTEM/CurrentControlSet/Control/Lsa /v RunAsPPL /t REG_DWORD /d 00000001 /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/Control/Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/Control/Lsa /v auditbaseobjects /t REG_DWORD /d 1 /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/Control/Lsa /v fullprivilegeauditing /t REG_DWORD /d 1 /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/Control/Lsa /v restrictanonymous /t REG_DWORD /d 1 /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/Control/Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/Control/Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/Control/Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/Control/Lsa /v UseMachineId /t REG_DWORD /d 0 /f",
    "reg ADD HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/System /v dontdisplaylastusername /t REG_DWORD /d 1 /f",
    "reg ADD HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f",
    "reg ADD HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/System /v EnableInstallerDetection /t REG_DWORD /d 1 /f",
    "reg ADD HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/System /v undockwithoutlogon /t REG_DWORD /d 0 /f",
    "reg ADD HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/System /v DisableCAD /t REG_DWORD /d 0 /f",
    "reg ADD HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/System /v EnableLUA /t REG_DWORD /d 1 /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/services/Netlogon/Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/services/Netlogon/Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/services/Netlogon/Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/services/Netlogon/Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/services/Netlogon/Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/services/Netlogon/Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/services/LanmanServer/Parameters /v autodisconnect /t REG_DWORD /d 45 /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/services/LanmanServer/Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/services/LanmanServer/Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/services/LanmanServer/Parameters /v NullSessionPipes /t REG_MULTI_SZ /d /"/" /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/services/LanmanServer/Parameters /v NullSessionShares /t REG_MULTI_SZ /d /"/" /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/services/LanmanWorkstation/Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/Control/SecurePipeServers/winreg/AllowedExactPaths /v Machine /t REG_MULTI_SZ /d /"/" /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/Control/SecurePipeServers/winreg/AllowedPaths /v Machine /t REG_MULTI_SZ /d /"/" /f",
    "reg ADD /HKCU/Software/Microsoft/Internet Explorer/PhishingFilter/ /v EnabledV8 /t REG_DWORD /d 1 /f",
    "reg ADD /HKCU/Software/Microsoft/Internet Explorer/PhishingFilter/ /v EnabledV9 /t REG_DWORD /d 1 /f",
    "reg ADD /HKCU/Software/Microsoft/Windows/CurrentVersion/Internet Settings/ /v DisablePasswordCaching /t REG_DWORD /d 1 /f",
    "reg ADD /HKCU/Software/Microsoft/Windows/CurrentVersion/Internet Settings/ /v WarnonBadCertRecving /t REG_DWORD /d 1 /f",
    "reg ADD /HKCU/Software/Microsoft/Windows/CurrentVersion/Internet Settings/ /v WarnOnPostRedirect /t REG_DWORD /d 1 /f",
    "reg ADD /HKCU/Software/Microsoft/Internet Explorer/Main/ /v DoNotTrack /t REG_DWORD /d 1 /f",
    "reg ADD /HKCU/Software/Microsoft/Internet Explorer/Download/ /v RunInvalidSignatures /t REG_DWORD /d 1 /f",
    "reg ADD /HKCU/Software/Microsoft/Internet Explorer/Main/FeatureControl/FEATURE_LOCALMACHINE_LOCKDOWN/Settings/ /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f",
    "reg ADD /HKCU/Software/Microsoft/Windows/CurrentVersion/Internet Settings/ /v WarnonZoneCrossing /t REG_DWORD /d 1 /f",
    "reg ADD HKCU/Software/Microsoft/Windows/CurrentVersion/Explorer/Advanced /v Hidden /t REG_DWORD /d 1 /f",
    "reg ADD /HKU//.DEFAULT/Control Panel/Accessibility/StickyKeys/ /v Flags /t REG_SZ /d 506 /f",
    "reg ADD HKCU/Software/Microsoft/Windows/CurrentVersion/Explorer/Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f",
    "reg ADD HKLM/SYSTEM/CurrentControlSet/Control/CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f",
    "reg ADD HKCU/SYSTEM/CurrentControlSet/Services/CDROM /v AutoRun /t REG_DWORD /d 1 /f"
)

# Ensure the script runs as administrator
RunAsAdmin

# Introductory Message
Write-Output "------- PLEASE NOTE -------"
Write-Output "This script may not be used by any other team than CyberPatriot team 17-3724 at Kent Career Technical Center."
Write-Output "Continuing with script in 10 seconds..."
Start-Sleep -Seconds 10

# Step 1: Enable Firewall
NextStep "Enabling Firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Write-Output "Firewall enabled successfully."

# Step 2: Manage Services
NextStep "Services..."

$ConfigureServices = Read-Host "Would you like to configure services? [Y/N]"
if ($ConfigureServices -eq "Y") {
    $ServiceListPath = "service_list.txt"

    # Write the initial list of services to the file
    $servicesToDisable | Out-File -FilePath $ServiceListPath -Encoding UTF8
    Write-Output "Please delete the services you don't want managed."

    # Open the file in Notepad and wait for the user to close it
    Invoke-Item -Path $ServiceListPath
    Write-Output "Waiting for Notepad to close..."
    while (Get-Process -Name "notepad" -ErrorAction SilentlyContinue) {
        Start-Sleep -Seconds 1
    }

    # Read the updated list of services from the file
    $ServicesFromFile = Get-Content -Path $ServiceListPath | ForEach-Object { $_.Trim() }

    # Identify and output removed services
    $RemovedServices = $servicesToDisable | Where-Object { $_ -notin $ServicesFromFile }
    if ($RemovedServices.Count -gt 0) {
        Write-Output "The following services will be removed:"
        $RemovedServices | ForEach-Object { Write-Output $_ }
    }
    Start-Sleep -Seconds 3
    # Stop and disable the remaining services
    foreach ($Service in $RemovedServices) {
        Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
        Set-Service -Name $Service -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Output "Stopped and disabled service $Service"
    }
}


# Step 3: Disable RDP
$DisableRDP = Read-Host "Would you like to disable RDP? [Y/N]"
if ($DisableRDP -eq "Y") {
    Stop-Service -Name TermService -Force
    Set-Service -Name TermService -StartupType Disabled
    Stop-Service -Name SessionEnv -Force
    Set-Service -Name SessionEnv -StartupType Disabled
    Stop-Service -Name UmRdpService -Force
    Set-Service -Name UmRdpService -StartupType Disabled
    Stop-Service -Name RemoteRegistry -Force
    Set-Service -Name RemoteRegistry -StartupType Disabled
    reg add "HKLM/SYSTEM/CurrentControlSet/Control/Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
    reg add "HKLM/SOFTWARE/Policies/Microsoft/Windows NT/Terminal Services" /v fDenyTSConnections /t REG_DWORD /d 1 /f
}

# Step 4: Manage Registry
NextStep "Registry..."
$ManageRegistry = Read-Host "Would you like to manage the registry? [Y/N]"
if ($ManageRegistry -eq "Y") {
    foreach ($Command in $RegistryCommands) {
        Invoke-Expression $Command
    }
}

# Step 5: User Management
NextStep "User Management..."
$DisableAccounts = Read-Host "Would you like to disable guest and admin accounts? [Y/N]"
if ($DisableAccounts -eq "Y") {
    net user administrator /active:no
    net user guest /active:no
}

Write-Output "Would you like to perform a user audit? [Y/N]"
$PerformAudit = Read-Host
if ($PerformAudit -eq "Y") {
    $AuthorizedUsersFile = "authorized_users.txt"
    New-Item -Path $AuthorizedUsersFile -ItemType File -Force
    Write-Output "Please add authorized users."
    Invoke-Item $AuthorizedUsersFile
    Write-Output "Waiting for Notepad to close..."
    while (Get-Process -Name "notepad" -ErrorAction SilentlyContinue) {
        Start-Sleep -Seconds 1
    }
    $AuthorizedUsers = Get-Content $AuthorizedUsersFile | ForEach-Object { $_.Trim() }

    $PermittedUsers = @("DefaultAccount", "Guest", "Administrator", "WDAGUtilityAccount")
    $LocalUsers = (Get-LocalUser | Select-Object -ExpandProperty Name).Where({ $_ -notin $PermittedUsers })

    $UsersToDelete = $LocalUsers | Where-Object { $_ -notin $AuthorizedUsers }
    $UsersToAdd = $AuthorizedUsers | Where-Object { $_ -notin $LocalUsers }

    $UserChangesFile = "user_changes.txt"
    Set-Content -Path $UserChangesFile -Value "Users to delete: $UsersToDelete`nUsers to add: $UsersToAdd"
    Invoke-Item $UserChangesFile

    Write-Output "Confirm Changes? [Y/N]"
    $Confirm = Read-Host
    if ($Confirm -eq "Y") {
        foreach ($User in $UsersToDelete) {
            Remove-LocalUser -Name $User -ErrorAction SilentlyContinue
        }
        foreach ($User in $UsersToAdd) {
            New-LocalUser -Name $User -Password (ConvertTo-SecureString 'abcdefghijklmnopQ1' -AsPlainText -Force)
        }
    }

    Write-Output "Please list administrator users."
    $AdminUsersFile = "admin_users.txt"
    New-Item -Path $AdminUsersFile -ItemType File -Force
    Invoke-Item $AdminUsersFile
    Write-Output "Waiting for Notepad to close..."
    while (Get-Process -Name "notepad" -ErrorAction SilentlyContinue) {
        Start-Sleep -Seconds 1
    }
    $AuthorizedAdmins = Get-Content $AdminUsersFile | ForEach-Object { $_.Trim() }

    $CurrentAdmins = (Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name).Where({ $_ -notin $PermittedUsers })

    $AdminsToAdd = $AuthorizedAdmins | Where-Object { $_ -notin $CurrentAdmins }
    $AdminsToRemove = $CurrentAdmins | Where-Object { $_ -notin $AuthorizedAdmins }

    foreach ($Admin in $AdminsToAdd) {
        Add-LocalGroupMember -Group "Administrators" -Member $Admin
    }
    foreach ($Admin in $AdminsToRemove) {
        Remove-LocalGroupMember -Group "Administrators" -Member $Admin
    }
}

Write-Host "Do you wish to change all user passwords? (Excludes current user) [Y / N]"
Write-Host "All passwords will be 'abcdefghijklmnopQ1'"

$current_user = $env:USERNAME
$users = @()
$userInput = Read-Host ">"

if ($userInput.ToUpper() -eq "Y") {
    # Retrieve local users (excluding system accounts, adjust the filter as necessary)
    $local_users = Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.Name -notin @("Administrator", "DefaultAccount", "WDAGUtilityAccount") }

    foreach ($user in $local_users) {
        if ($user.Name -ne $current_user) {
            $users += $user.Name
        }
    }

    $outputFile = "password_changes.txt"
    "Accounts passwords changed:" | Out-File -FilePath $outputFile
    $users | Out-File -FilePath $outputFile -Append

    Start-Process -FilePath "notepad" -ArgumentList $outputFile
    Write-Host "Confirm Changes? [Y / N]"
    $confirmation = Read-Host ">"

    if ($confirmation.ToUpper() -eq "Y") {
        foreach ($user in $users) {
            $password = ConvertTo-SecureString "abcdefghijklmnopQ1" -AsPlainText -Force
            Set-LocalUser -Name $user -Password $password
        }
        Write-Host "Passwords have been updated for all selected users."
    } else {
        Write-Host "Password change operation cancelled."
    }
} else {
    Write-Host "Operation cancelled."
}

Write-Host "All Finished!"
