import subprocess
import os
import ctypes
from time import sleep
from sys import exit

step = 0
totalSteps = 5
services = sorted([
    "Telephony", "TapiSrv", "Tlntsvr", "tlntsvr", "p2pimsvc", "simptcp", "fax", "msftpsvc",
    "iprip", "ftpsvc", "RasMan", "RasAuto", "seclogon", "MSFTPSVC", "W3SVC", "SMTPSVC",
    "Dfs", "TrkWks", "MSDTC", "DNS", "ERSVC", "NtFrs", "MSFtpsvc", "helpsvc", "HTTPFilter",
    "IISADMIN", "IsmServ", "WmdmPmSN", "Spooler", "RDSessMgr", "RPCLocator", "RsoPProv",
    "ShellHWDetection", "ScardSvr", "Sacsvr", "Uploadmgr", "VDS", "VSS", "WINS",
    "WinHttpAutoProxySvc", "SZCSVC", "CscService", "hidserv", "IPBusEnum", "PolicyAgent",
    "SCPolicySvc", "SharedAccess", "SSDPSRV", "Themes", "upnphost", "nfssvc", "nfsclnt",
    "MSSQLServerADHelper"
])

registry_commands = [
    "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f",
    "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f",
    "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v AUOptions /t REG_DWORD /d 4 /f",
    "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\" /v AUOptions /t REG_DWORD /d 4 /f",
    "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f",
    "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f",
    "reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f",
    "reg add \"HKLM\\SYSTEM\\Internet Communication Management\\Internet Communication\" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f",
    "reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f",
    "reg ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v AllocateCDRoms /t REG_DWORD /d 1 /f",
    "reg ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v AllocateFloppies /t REG_DWORD /d 1 /f",
    "reg ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v AutoAdminLogon /t REG_DWORD /d 0 /f",
    "reg ADD \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f",
    "reg ADD \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers\" /v AddPrinterDrivers /t REG_DWORD /d 1 /f",
    "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\LSASS.exe\" /v AuditLevel /t REG_DWORD /d 00000008 /f",
    "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 00000001 /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v auditbaseobjects /t REG_DWORD /d 1 /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v fullprivilegeauditing /t REG_DWORD /d 1 /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v UseMachineId /t REG_DWORD /d 0 /f",
    "reg ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f",
    "reg ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f",
    "reg ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f",
    "reg ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v undockwithoutlogon /t REG_DWORD /d 0 /f",
    "reg ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableCAD /t REG_DWORD /d 0 /f",
    "reg ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 1 /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\services\\Netlogon\\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\services\\Netlogon\\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\services\\Netlogon\\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\services\\Netlogon\\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\services\\Netlogon\\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\services\\Netlogon\\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\services\\LanmanServer\\Parameters /v autodisconnect /t REG_DWORD /d 45 /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\services\\LanmanServer\\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\services\\LanmanServer\\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\services\\LanmanServer\\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d \"\" /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\services\\LanmanServer\\Parameters /v NullSessionShares /t REG_MULTI_SZ /d \"\" /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\services\\LanmanWorkstation\\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\winreg\\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d \"\" /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\winreg\\AllowedPaths /v Machine /t REG_MULTI_SZ /d \"\" /f",
    "reg ADD \"HKCU\\Software\\Microsoft\\Internet Explorer\\PhishingFilter\" /v EnabledV8 /t REG_DWORD /d 1 /f",
    "reg ADD \"HKCU\\Software\\Microsoft\\Internet Explorer\\PhishingFilter\" /v EnabledV9 /t REG_DWORD /d 1 /f",
    "reg ADD \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v DisablePasswordCaching /t REG_DWORD /d 1 /f",
    "reg ADD \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f",
    "reg ADD \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f",
    "reg ADD \"HKCU\\Software\\Microsoft\\Internet Explorer\\Main\" /v DoNotTrack /t REG_DWORD /d 1 /f",
    "reg ADD \"HKCU\\Software\\Microsoft\\Internet Explorer\\Download\" /v RunInvalidSignatures /t REG_DWORD /d 1 /f",
    "reg ADD \"HKCU\\Software\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_LOCALMACHINE_LOCKDOWN\\Settings\" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f",
    "reg ADD \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f",
    "reg ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /v Hidden /t REG_DWORD /d 1 /f",
    "reg ADD \"HKU\\.DEFAULT\\Control Panel\\Accessibility\\StickyKeys\" /v Flags /t REG_SZ /d 506 /f",
    "reg ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f",
    "reg ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f",
    "reg ADD HKCU\\SYSTEM\\CurrentControlSet\\Services\\CDROM /v AutoRun /t REG_DWORD /d 1 /f"
]

def powershell(*args):
    return subprocess.run(["powershell", *args], check=True, shell=True, text=True, capture_output=True)

def next_step(msg):
    global step, totalSteps
    step += 1
    os.system("cls")
    print(f"({step}/{totalSteps} - {msg}\n")

if not ctypes.windll.shell32.IsUserAnAdmin():
    print("Please run this script as administrator.")
    exit(1)

print("------- PLEASE NOTE -------")
print("This script may not be used by any other team than CyberPatriot team 17-3724 at Kent Career Technical Center.")
print("It is against rule 3011.4 of the CyberPatriot handbook to use another team's script.")
print("This script may however, be used outside of CyberPatriot activities.")
print("Continuing with script in 10 seconds...")
sleep(10)

next_step("Enabling Firewall...")
powershell("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True")
print("Firewall enabled successfully.")

next_step("Services...")
print("Would you like to configure services? [Y / N]")
user = input("> ")
if user.upper() == "Y":
    with open("service_list.txt", "w") as file:
        for service in services:
            file.write(service + "\n")
    print("Please delete the services you dont want managed.")
    powershell("Start-Process notepad service_list.txt")
    with open("service_list.txt", "r") as file:
        services_from_file = [line.strip() for line in file.readlines()]

    for service in services_from_file:
        powershell("sc stop", service)
        powershell("sc config", service, "start=disabled")
        print(f"Stopped and disabled service {service}")

print("Would you like to disable RDP? [Y / N]")
user = input("> ")
if user.upper() == "Y":
    powershell("sc stop TermService")
    powershell("sc config TermService start=disabled")
    powershell("sc stop SessionEnv")
    powershell("sc config SessionEnv start=disabled")
    powershell("sc stop UmRdpService")
    powershell("sc config UmRdpService start=disabled")
    powershell("sc stop RemoteRegistry")
    powershell("sc config RemoteRegistry start=disabled")
    powershell("reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server /v fDenyTSConnections /t REG_DWORD /d 1 /f")
    powershell("reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\Terminal Services /v fDenyTSConnections /t REG_DWORD /d 1 /f")

next_step("Registry...")
print("Would you like to manage the registry? [Y / N]")
user = input("> ")
if user.upper() == "Y":
    for item in registry_commands:
        powershell(item)

next_step("Group Policy...")
print("Would you like to import the Group Policy? [Y / N]")
user = input("> ")
if user.upper() == "Y":
    powershell(".\LGPO.exe /g .\Policies /v")

next_step("User Management...")
print("Would you like to disable guest and admin accounts? [Y / N]")
user = input("> ")
if user.upper() == "Y":
    powershell("net user administrator /active:no")
    powershell("net user guest /active:no")

print("Would you like to perform a user audit? [Y / N]")
user = input("> ")
if user.upper() == "Y":
    with open("authorized_users.txt", "w") as file:
        file.write("")
    print("Please add authorized users.")
    powershell("Start-Process", "notepad authorized_users.txt", "-Wait")
    with open("authorized_users.txt", "r") as file:
        auth_users = [line.strip() for line in file.readlines()]

    permitted_users = ["DefaultAccount", "Guest", "Administrator", "WDAGUtilityAccount"]

    local_users = powershell("Get-LocalUser | Select-Object 'Name'").stdout.splitlines()
    tmp = []
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    for user in local_users:
        if user[0].lower() in alphabet:
            tmp.append(user)
    local_users = tmp

    del_users = []
    add_users = []

    for local in local_users:
        if local not in auth_users and local not in permitted_users:
            del_users.append(local)
    for auth in auth_users:
        if auth not in local_users and auth not in permitted_users:
            add_users.append(auth)

    with open("user_changes.txt", "w") as file:
        file.write(f"Users to delete:\n{del_users}\n\nUsers to add:\n{add_users}")
    powershell("Start-Process notepad user_changes.txt")
    print("Confirm Changes? [Y / N]")
    user = input("> ")
    if user.upper() == "Y":
        for user in del_users:
            powershell("Remove-LocalUser -Name", user)
        for user in add_users:
            powershell("New-LocalUser -Name", user, "-Password (ConvertTo-SecureString 'abcdefghijklmnopQ1' -AsPlainText -Force)")

    print("Please put administrator users.")
    with open("admin_users.txt", "w") as file:
        file.write("")
    powershell("Start-Process", "notepad admin_users.txt", "-Wait")
    with open("admin_users.txt", "r") as file:
        auth_admin_users = [line.strip() for line in file.readlines()]

    admin_users = powershell("Get-LocalGroupMember -Group 'Administrators' | Select-Object Name").stdout.splitlines()
    tmp = []
    for user in admin_users:
        if user[0].lower() in alphabet:
            tmp.append(user)
    admin_users = tmp

    user_accounts = []
    adm_accounts = []

    for usr in local_users:
        if usr in admin_users:
            adm_accounts.append(usr)
        else:
            user_accounts.append(usr)
    with open("admin_changes.txt", "w") as file:
        file.write(f"Users to change to admin:\n{adm_accounts}\n\nUsers to change to user:\n{user_accounts}")
    powershell("Start-Process notepad admin_changes.txt")
    print("Confirm Changes? [Y / N]")
    user = input("> ")
    if user.upper() == "Y":
        for user in adm_accounts:
            powershell("Add-LocalGroupMember -Group 'Administrators' -Member", user)
        for user in user_accounts:
            powershell("Remove-LocalGroupMember -Group 'Administrators' -Member", user)
            powershell("Add-LocalGroupMember -Group 'Users' -Member", user)

    print("Do you wish to change all user passwords? (Excludes current user) [Y / N]")
    print("All passwords will be 'abcdefghijklmnopQ1'")
    current_user = powershell("$env:USERNAME").stdout.strip("\n")
    users = []
    user = input("> ")
    if user.upper() == "Y":
        for user in local_users:
            if user not in permitted_users and user != current_user:
                users.append(user)
        with open("password_changes.txt", "w") as file:
            file.write(f"Accounts passwords changed:\n{users}")
        powershell("Start-Process notepad password_changes.txt")
        print("Confirm Changes? [Y / N]")
        user = input("> ")
        if user.upper() == "Y":
            for item in users:
                powershell("Set-LocalUser -Name", item, "-Password (ConvertTo-SecureString 'abcdefghijklmnopQ1' -AsPlainText -Force)")

print("All Finished!")
