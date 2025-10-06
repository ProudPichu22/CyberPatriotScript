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


function Log-Action {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path "cyberpatriot.log" -Value "$timestamp - $Message"
}

# Initialize variables
$global:Step = 0
$global:TotalSteps = 5
$Services = @(
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
    "AutoInstallMinorUpdates", 
    "NoAutoUpdate", 
    "AUOptions", 
    "AUOptions", 
    "DisableWindowsUpdateAccess", 
    "ElevateNonAdmins", 
    "NoWindowsUpdate", 
    "DisableWindowsUpdateAccess", 
    "DisableWindowsUpdateAccess", 
    "AllocateCDRoms", 
    "AllocateFloppies", 
    "AutoAdminLogon", 
    "ClearPageFileAtShutdown", 
    "AddPrinterDrivers", 
    "AuditLevel",
    "RunAsPPL", 
    "LimitBlankPasswordUse", 
    "auditbaseobjects", 
    "fullprivilegeauditing", 
    "restrictanonymous", 
    "restrictanonymoussam", 
    "disabledomaincreds", 
    "everyoneincludesanonymous", 
    "UseMachineId", 
    "dontdisplaylastusername", 
    "PromptOnSecureDesktop", 
    "EnableInstallerDetection", 
    "undockwithoutlogon", 
    "DisableCAD", 
    "EnableLUA", 
    "MaximumPasswordAge",
    "DisablePasswordChange", 
    "RequireStrongKey", 
    "RequireSignOrSeal", 
    "SignSecureChannel", 
    "SealSecureChannel", 
    "autodisconnect",
    "enablesecuritysignature", 
    "requiresecuritysignature", 
    "NullSessionPipes",
    "NullSessionShares",
    "EnablePlainTextPassword", 
    "EnabledV8", 
    "EnabledV9", 
    "DisablePasswordCaching", 
    "WarnonBadCertRecving", 
    "WarnOnPostRedirect", 
    "DoNotTrack", 
    "RunInvalidSignatures", 
    "LOCALMACHINE_CD_UNLOCK", 
    "WarnonZoneCrossing", 
    "Hidden", 
    "ShowSuperHidden", 
    "CrashDumpEnabled", 
    "AutoRun"
)

$neededFiles = @(
    "registry.bat"
)

# Ensure the script runs as administrator
RunAsAdmin

# Make sure all nessecary files are present

foreach($file in $neededFiles) {
    if(-not (Test-Path -Path $file)) {
        Write-Error "Important file missing: $file"
    }
}


# Introductory Message
Write-Output "Starting script in 5 seconds..."
Start-Sleep -Seconds 5
Set-Content -Path "cyberpatriot.log" -Value ""


# Step 1: Enable Firewall
NextStep "Enabling Firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Write-Output "Firewall enabled successfully."

# Step 2: Manage Services
NextStep "Services..."
$ConfigureServices = Read-Host "Would you like to configure services? [Y/n]"
if ($ConfigureServices -ne "N") {
    $ServiceListPath = "service_list.txt"
    $Services | Out-File -FilePath $ServiceListPath
    Write-Output "Please delete the services you don't want managed."
    Start-Process $ServiceListPath -Wait
    $ServicesFromFile = Get-Content -Path $ServiceListPath | ForEach-Object { $_.Trim() }

    foreach ($Service in $ServicesFromFile) {
        Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
        Set-Service -Name $Service -StartupType Disabled
        Write-Output "Stopped and disabled service $Service"
        Log-Action "Stopped and disabled service $Service"
    }
}

# Step 3: Disable RDP
$DisableRDP = Read-Host "Would you like to disable RDP? [Y/n]"
if ($DisableRDP -ne "N") {
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
    Log-Action "Stopped and disabled service: TermService"
    Log-Action "Stopped and disabled service: SessionEnv"
    Log-Action "Stopped and disabled service: UmRdpService"
    Log-Action "Stopped and disabled service: RemoteRegistry"
    Log-Action "Set registry key: fDenyTSConnections to 1"
}

# Step 4: Manage Registry
NextStep "Registry..."
$ManageRegistry = Read-Host "Would you like to manage the registry? [Y/n]"
if ($ManageRegistry -ne "N") {
    foreach ($Command in $RegistryCommands) {
        Invoke-Expression "./registry.bat"
        Log-Action "Performed registry command: $Command"
    }
}

# Step 5: User Management
NextStep "User Management..."
$DisableAccounts = Read-Host "Would you like to disable guest and admin accounts? [Y/n]"
if ($DisableAccounts -ne "N") {
    net user administrator /active:no
    net user guest /active:no
    Log-Action "Disabled account: Administrator"
    Log-Action "Disabled account: Guest"
}

Write-Output "Would you like to perform a user audit? [y/N]"
$PerformAudit = Read-Host
if ($PerformAudit -eq "Y") {
    $AuthorizedUsersFile = "authorized_users.txt"
    New-Item -Path $AuthorizedUsersFile -ItemType File -Force
    Write-Output "Please add authorized users."
    Start-Process $AuthorizedUsersFile -Wait
    $AuthorizedUsers = Get-Content $AuthorizedUsersFile | ForEach-Object { $_.Trim() }

    $PermittedUsers = @("DefaultAccount", "Guest", "Administrator", "WDAGUtilityAccount")
    $LocalUsers = (Get-LocalUser | Select-Object -ExpandProperty Name).Where({ $_ -notin $PermittedUsers })

    $UsersToDelete = $LocalUsers | Where-Object { $_ -notin $AuthorizedUsers }
    $UsersToAdd = $AuthorizedUsers | Where-Object { $_ -notin $LocalUsers }

    $UserChangesFile = "user_changes.txt"
    Set-Content -Path $UserChangesFile -Value "Users to delete: $UsersToDelete`nUsers to add: $UsersToAdd"
    Start-Process $UserChangesFile -Wait

    Write-Output "Confirm Changes? [Y/n]"
    $Confirm = Read-Host
    if ($Confirm -ne "N") {
        foreach ($User in $UsersToDelete) {
            Remove-LocalUser -Name $User -ErrorAction SilentlyContinue
            Log-Action "Removed user: $User"
        }
        foreach ($User in $UsersToAdd) {
            New-LocalUser -Name $User -Password (ConvertTo-SecureString 'Abcdefghijklmnopq1' -AsPlainText -Force)
            Log-Action "Added user: $User"
        }
    }

    Write-Output "Please list administrator users."
    $AdminUsersFile = "admin_users.txt"
    New-Item -Path $AdminUsersFile -ItemType File -Force
    Start-Process $AdminUsersFile -Wait
    $AuthorizedAdmins = Get-Content $AdminUsersFile | ForEach-Object { $_.Trim() }

    $CurrentAdmins = (Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name).Where({ $_ -notin $PermittedUsers })

    $AdminsToAdd = $AuthorizedAdmins | Where-Object { $_ -notin $CurrentAdmins }
    $AdminsToRemove = $CurrentAdmins | Where-Object { $_ -notin $AuthorizedAdmins }

    foreach ($Admin in $AdminsToAdd) {
        Add-LocalGroupMember -Group "Administrators" -Member $Admin
        Log-Action "Gave administrator to user: $Admin"
    }
    foreach ($Admin in $AdminsToRemove) {
        Remove-LocalGroupMember -Group "Administrators" -Member $Admin
        Log-Action "Removed administrator from user: $Admin"
    }
}

Write-Host "Do you wish to change all user passwords? (Excludes current user) [y/N]"
Write-Host "All passwords will be 'Abcdefghijklmnopq1'"

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
            $password = ConvertTo-SecureString "Abcdefghijklmnopq1" -AsPlainText -Force
            Set-LocalUser -Name $user -Password $password
            Log-Action "Reset password for user: $user"
        }
        Write-Host "Passwords have been updated for all selected users."
    } else {
        Write-Host "Password change operation cancelled."
    }
} else {
    Write-Host "Operation cancelled."
}

Write-Host "All Finished! Opening log..."
Start-Process -FilePath "notepad" -ArgumentList "cyberpatriot.log"