# CIS Benchmark Check Tool v 2.0 
# Developed by Astra 2.0
# PowerShell script to check compliance with security policies based on user-selected environment
# Exports results to HTML in the same directory as the script
# Requires administrative privileges and PowerShell 5.1 or later

# Display Banner
if ($Host.UI -ne $null -and $Host.UI.RawUI -ne $null) {
    Write-Host @"
=======================================================================
   CIS BENCHMARK CHECK 4 WINDOWS OS v 2.0
=======================================================================
                                      Developed by ASTRA 2.0 (3tternp)
=======================================================================
"@ -ForegroundColor Green
    Start-Sleep -Milliseconds 500  # Brief pause to ensure visibility
}

# Get the directory of the script
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Function to check if running as Administrator
function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Validate PowerShell version and language mode
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "This script requires PowerShell 5.1 or later. Current version: $($PSVersionTable.PSVersion)"
    exit
}
if ($ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage") {
    Write-Error "This script cannot run in Constrained Language Mode. Please run in Full Language Mode."
    exit
}

if (-not (Test-Administrator)) {
    Write-Error "This script requires administrative privileges. Please run as Administrator."
    exit
}

# Prompt user for environment
Write-Host "Select the environment for compliance checking:"
Write-Host "1. Windows OS (Local)"
Write-Host "2. Server Environment (Non-DC)"
Write-Host "3. Active Directory Environment (DC)"
$envChoice = Read-Host "Enter choice (1, 2, or 3)"

$envType = switch ($envChoice) {
    "1" { "WindowsOS" }
    "2" { "Server" }
    "3" { "ActiveDirectory" }
    default { Write-Error "Invalid choice. Exiting."; exit }
}

# Initialize global results array
$global:results = @()

# Function to add result to array
function Add-Result {
    param ($PolicyID, $PolicyName, $Status, $Details, $RiskRating, $Remediation)
    $global:results += [PSCustomObject]@{
        PolicyID    = $PolicyID
        PolicyName  = $PolicyName
        Status      = $Status
        Details     = $Details
        RiskRating  = $RiskRating
        Remediation = $Remediation
    }
}

# Temporary file for secedit
$seceditFile = "$env:TEMP\secpol_$([guid]::NewGuid()).cfg"
if (Test-Path $seceditFile) { Remove-Item $seceditFile -Force }

# 1. Account Policies
Write-Host "Checking Password Policy..."
try {
    secedit /export /cfg $seceditFile /quiet
    $secContent = Get-Content $seceditFile -ErrorAction Stop

    # Extract and convert to integer, ensuring a single value
    $passwordHistory = ($secContent | Where-Object { $_ -match "PasswordHistorySize\s*=\s*(\d+)" } | Select-Object -First 1) -replace ".*=\s*(\d+)", '$1'
    $status = if ([int]$passwordHistory -ge 24) { "Pass" } else { "Fail" }
    $riskRating = "High"
    $remediation = "Run: 'secedit /configure /cfg <template.inf> /db <database.sdb> /areas SECURITYPOLICY' with a template setting PasswordHistorySize to 24 or greater."
    Add-Result "1.1.1" "Enforce password history" $status "Expected: 24 or more passwords, Found: $passwordHistory" $riskRating $remediation

    $maxPwAge = ($secContent | Where-Object { $_ -match "MaximumPasswordAge\s*=\s*(\d+)" } | Select-Object -First 1) -replace ".*=\s*(\d+)", '$1'
    $status = if ([int]$maxPwAge -le 60 -and [int]$maxPwAge -ne 0) { "Pass" } else { "Fail" }
    $riskRating = "High"
    $remediation = "Run: 'secedit /configure /cfg <template.inf> /db <database.sdb> /areas SECURITYPOLICY' with a template setting MaximumPasswordAge to 60 or fewer days, not 0."
    Add-Result "1.1.2" "Maximum password age" $status "Expected: 60 or fewer days, not 0, Found: $maxPwAge days" $riskRating $remediation

    $minPwAge = ($secContent | Where-Object { $_ -match "MinimumPasswordAge\s*=\s*(\d+)" } | Select-Object -First 1) -replace ".*=\s*(\d+)", '$1'
    $status = if ([int]$minPwAge -ge 1) { "Pass" } else { "Fail" }
    $riskRating = "Medium"
    $remediation = "Run: 'secedit /configure /cfg <template.inf> /db <database.sdb> /areas SECURITYPOLICY' with a template setting MinimumPasswordAge to 1 or more days."
    Add-Result "1.1.3" "Minimum password age" $status "Expected: 1 or more days, Found: $minPwAge days" $riskRating $remediation

    $minPwLen = ($secContent | Where-Object { $_ -match "MinimumPasswordLength\s*=\s*(\d+)" } | Select-Object -First 1) -replace ".*=\s*(\d+)", '$1'
    $status = if ([int]$minPwLen -ge 14) { "Pass" } else { "Fail" }
    $riskRating = "Critical"
    $remediation = "Run: 'secedit /configure /cfg <template.inf> /db <database.sdb> /areas SECURITYPOLICY' with a template setting MinimumPasswordLength to 14 or more characters."
    Add-Result "1.1.4" "Minimum password length" $status "Expected: 14 or more characters, Found: $minPwLen characters" $riskRating $remediation

    $pwComplexity = ($secContent | Where-Object { $_ -match "PasswordComplexity\s*=\s*(\d+)" } | Select-Object -First 1) -replace ".*=\s*(\d+)", '$1'
    $status = if ([int]$pwComplexity -eq 1) { "Pass" } else { "Fail" }
    $riskRating = "High"
    $remediation = "Run: 'secedit /configure /cfg <template.inf> /db <database.sdb> /areas SECURITYPOLICY' with a template setting PasswordComplexity to 1 (Enabled)."
    Add-Result "1.1.5" "Password must meet complexity requirements" $status "Expected: Enabled (1), Found: $pwComplexity" $riskRating $remediation

    $reversibleEnc = ($secContent | Where-Object { $_ -match "ClearTextPassword\s*=\s*(\d+)" } | Select-Object -First 1) -replace ".*=\s*(\d+)", '$1'
    $status = if ([int]$reversibleEnc -eq 0) { "Pass" } else { "Fail" }
    $riskRating = "Critical"
    $remediation = "Run: 'secedit /configure /cfg <template.inf> /db <database.sdb> /areas SECURITYPOLICY' with a template setting ClearTextPassword to 0 (Disabled)."
    Add-Result "1.1.6" "Store passwords using reversible encryption" $status "Expected: Disabled (0), Found: $reversibleEnc" $riskRating $remediation
}
catch {
    Add-Result "1.1" "Account Policies" "Error" "Failed to check password policies: $($_.Exception.Message)" "N/A" "N/A"
}

Write-Host "Checking Account Lockout Policy..."
try {
    $lockoutInfo = net accounts
    $lockoutDuration = ($lockoutInfo | Where-Object { $_ -match "Lockout duration \(minutes\):\s*(\d+)" }) -replace ".*:\s*(\d+)", '$1'
    $status = if ([int]$lockoutDuration -ge 15) { "Pass" } else { "Fail" }
    $riskRating = "Medium"
    $remediation = "Run: 'net accounts /lockoutduration:15' to set lockout duration to 15 minutes or more."
    Add-Result "1.2.1" "Account lockout duration" $status "Expected: 15 or more minutes, Found: $lockoutDuration minutes" $riskRating $remediation

    $lockoutThreshold = ($lockoutInfo | Where-Object { $_ -match "Lockout threshold:\s*(\d+)" }) -replace ".*:\s*(\d+)", '$1'
    $status = if ([int]$lockoutThreshold -le 3 -and [int]$lockoutThreshold -ne 0) { "Pass" } else { "Fail" }
    $riskRating = "High"
    $remediation = "Run: 'net accounts /lockoutthreshold:3' to set lockout threshold to 3 or fewer attempts, not 0."
    Add-Result "1.2.2" "Account lockout threshold" $status "Expected: 3 or fewer attempts, not 0, Found: $lockoutThreshold attempts" $riskRating $remediation

    $lockoutWindow = ($lockoutInfo | Where-Object { $_ -match "Lockout observation window \(minutes\):\s*(\d+)" }) -replace ".*:\s*(\d+)", '$1'
    $status = if ([int]$lockoutWindow -ge 15) { "Pass" } else { "Fail" }
    $riskRating = "Medium"
    $remediation = "Run: 'net accounts /lockoutwindow:15' to set lockout window to 15 or more minutes."
    Add-Result "1.2.3" "Reset account lockout counter after" $status "Expected: 15 or more minutes, Found: $lockoutWindow minutes" $riskRating $remediation
}
catch {
    Add-Result "1.2" "Account Lockout Policy" "Error" "Failed to check account lockout policies: $($_.Exception.Message)" "N/A" "N/A"
}

# Kerberos Policy (Active Directory only)
if ($envType -eq "ActiveDirectory") {
    Add-Result "1.3.1" "Enforce user logon restrictions (DC only)" "Manual" "Requires manual verification on Domain Controller: Ensure set to Enabled." "N/A" "N/A"
    Add-Result "1.3.2" "Maximum lifetime for service ticket (DC only)" "Manual" "Requires manual verification on Domain Controller: Ensure set to 600 or fewer minutes, not 0." "N/A" "N/A"
    Add-Result "1.3.3" "Maximum lifetime for user ticket (DC only)" "Manual" "Requires manual verification on Domain Controller: Ensure set to 10 or fewer hours, not 0." "N/A" "N/A"
    Add-Result "1.3.4" "Maximum lifetime for user ticket renewal (DC only)" "Manual" "Requires manual verification on Domain Controller: Ensure set to 7 or fewer days." "N/A" "N/A"
    Add-Result "1.3.5" "Maximum tolerance for computer clock synchronization (DC only)" "Manual" "Requires manual verification on Domain Controller: Ensure set to 5 or fewer minutes." "N/A" "N/A"
}

# 2.2 User Rights Assignment
Write-Host "Checking User Rights Assignment..."
try {
    secedit /export /cfg $seceditFile /areas USER_RIGHTS /quiet
    $secContent = Get-Content $seceditFile -ErrorAction Stop

    function Check-UserRight {
        param ($policy, $expected, $policyID, $policyName, $appliesTo)
        if ($appliesTo -eq "All" -or ($appliesTo -eq "DC" -and $envType -eq "ActiveDirectory") -or ($appliesTo -eq "MS" -and $envType -in @("WindowsOS", "Server"))) {
            try {
                $value = ($secContent | Where-Object { $_ -match "$policy\s*=\s*(.*)" }) -replace ".*=\s*(.*)", '$1'
                $status = if ($value -eq $expected -or ($value -eq "" -and $expected -eq "")) { "Pass" } else { "Fail" }
                $riskRating = "High"
                $remediation = "Run: 'secedit /configure /cfg <template.inf> /db <database.sdb> /areas USER_RIGHTS' with a template setting $policy to '$expected'."
                Add-Result $policyID $policyName $status "Expected: $expected, Found: $value" $riskRating $remediation
            }
            catch {
                Add-Result $policyID $policyName "Error" "Failed to check user right: $($_.Exception.Message)" "N/A" "N/A"
            }
        }
    }

    Check-UserRight "SeTrustedCredManAccessPrivilege" "" "2.2.1" "Access Credential Manager as a trusted caller" "All"
    Check-UserRight "SeNetworkLogonRight" "Administrators,Authenticated Users,ENTERPRISE DOMAIN CONTROLLERS" "2.2.2" "Access this computer from the network (DC)" "DC"
    Check-UserRight "SeNetworkLogonRight" "Administrators,Authenticated Users" "2.2.3" "Access this computer from the network (MS)" "MS"
    Check-UserRight "SeTcbPrivilege" "" "2.2.4" "Act as part of the operating system" "All"
    Check-UserRight "SeMachineAccountPrivilege" "Administrators" "2.2.5" "Add workstations to domain (DC)" "DC"
    Check-UserRight "SeIncreaseQuotaPrivilege" "Administrators,LOCAL SERVICE,NETWORK SERVICE" "2.2.6" "Adjust memory quotas for a process" "All"
    Check-UserRight "SeInteractiveLogonRight" "Administrators" "2.2.7" "Allow log on locally" "All"
    Check-UserRight "SeRemoteInteractiveLogonRight" "Administrators" "2.2.8" "Allow log on through Remote Desktop Services (DC)" "DC"
    Check-UserRight "SeRemoteInteractiveLogonRight" "Administrators,Remote Desktop Users" "2.2.9" "Allow log on through Remote Desktop Services (MS)" "MS"
    Check-UserRight "SeBackupPrivilege" "Administrators" "2.2.10" "Back up files and directories" "All"
    Check-UserRight "SeSystemtimePrivilege" "Administrators,LOCAL SERVICE" "2.2.11" "Change the system time" "All"
    Check-UserRight "SeTimeZonePrivilege" "Administrators,LOCAL SERVICE" "2.2.12" "Change the time zone" "All"
    Check-UserRight "SeCreatePagefilePrivilege" "Administrators" "2.2.13" "Create a pagefile" "All"
    Check-UserRight "SeCreateTokenPrivilege" "" "2.2.14" "Create a token object" "All"
    Check-UserRight "SeCreateGlobalPrivilege" "Administrators,LOCAL SERVICE,NETWORK SERVICE,SERVICE" "2.2.15" "Create global objects" "All"
    Check-UserRight "SeCreatePermanentPrivilege" "" "2.2.16" "Create permanent shared objects" "All"
    Check-UserRight "SeCreateSymbolicLinkPrivilege" "Administrators" "2.2.17" "Create symbolic links (DC)" "DC"
    Check-UserRight "SeCreateSymbolicLinkPrivilege" "Administrators,NT VIRTUAL MACHINE\Virtual Machines" "2.2.18" "Create symbolic links (MS)" "MS"
    Check-UserRight "SeDebugPrivilege" "Administrators" "2.2.20" "Debug programs" "All"
    Check-UserRight "SeDenyNetworkLogonRight" "Guests" "2.2.21" "Deny access to this computer from the network (DC)" "DC"
    Check-UserRight "SeDenyNetworkLogonRight" "Guests,Local account and member of Administrators group" "2.2.22" "Deny access to this computer from the network (MS)" "MS"
    Check-UserRight "SeDenyBatchLogonRight" "Guests" "2.2.24" "Deny log on as a batch job" "All"
    Check-UserRight "SeDenyServiceLogonRight" "Guests" "2.2.27" "Deny log on as a service" "All"
    Check-UserRight "SeDenyInteractiveLogonRight" "Guests" "2.2.30" "Deny log on locally" "All"
    Check-UserRight "SeDenyRemoteInteractiveLogonRight" "Guests" "2.2.33" "Deny log on through Remote Desktop Services (DC)" "DC"
    Check-UserRight "SeDenyRemoteInteractiveLogonRight" "Guests,Local account" "2.2.34" "Deny log on through Remote Desktop Services (MS)" "MS"
    Check-UserRight "SeEnableDelegationPrivilege" "Administrators" "2.2.36" "Enable computer and user accounts to be trusted for delegation (DC)" "DC"
    Check-UserRight "SeEnableDelegationPrivilege" "" "2.2.37" "Enable computer and user accounts to be trusted for delegation (MS)" "MS"
    Check-UserRight "SeRemoteShutdownPrivilege" "Administrators" "2.2.38" "Force shutdown from a remote system" "All"
    Check-UserRight "SeAuditPrivilege" "LOCAL SERVICE,NETWORK SERVICE" "2.2.39" "Generate security audits" "All"
    Check-UserRight "SeImpersonatePrivilege" "Administrators,LOCAL SERVICE,NETWORK SERVICE,SERVICE" "2.2.40" "Impersonate a client after authentication (DC)" "DC"
    Check-UserRight "SeIncreaseBasePriorityPrivilege" "Administrators,Window Manager\Window Manager Group" "2.2.43" "Increase scheduling priority" "All"
    Check-UserRight "SeLoadDriverPrivilege" "Administrators" "2.2.45" "Load and unload device drivers" "All"
    Check-UserRight "SeLockMemoryPrivilege" "" "2.2.46" "Lock pages in memory" "All"
    Check-UserRight "SeBatchLogonRight" "Administrators" "2.2.47" "Log on as a batch job (DC)" "DC"
    Check-UserRight "SeSecurityPrivilege" "Administrators" "2.2.48" "Manage auditing and security log (DC)" "DC"
    Check-UserRight "SeSecurityPrivilege" "Administrators" "2.2.50" "Manage auditing and security log (MS)" "MS"
    Check-UserRight "SeRelabelPrivilege" "" "2.2.51" "Modify an object label" "All"
    Check-UserRight "SeSystemEnvironmentPrivilege" "Administrators" "2.2.52" "Modify firmware environment values" "All"
    Check-UserRight "SeManageVolumePrivilege" "Administrators" "2.2.53" "Perform volume maintenance tasks" "All"
    Check-UserRight "SeProfileSingleProcessPrivilege" "Administrators" "2.2.54" "Profile single process" "All"
    Check-UserRight "SeSystemProfilePrivilege" "Administrators,NT SERVICE\WdiServiceHost" "2.2.55" "Profile system performance" "All"
    Check-UserRight "SeAssignPrimaryTokenPrivilege" "LOCAL SERVICE,NETWORK SERVICE" "2.2.56" "Replace a process level token" "All"
    Check-UserRight "SeRestorePrivilege" "Administrators" "2.2.57" "Restore files and directories" "All"
    Check-UserRight "SeShutdownPrivilege" "Administrators" "2.2.58" "Shut down the system" "All"
    Check-UserRight "SeSyncAgentPrivilege" "" "2.2.59" "Synchronize directory service data (DC)" "DC"
    Check-UserRight "SeTakeOwnershipPrivilege" "Administrators" "2.2.60" "Take ownership of files or other objects" "All"
}
catch {
    Add-Result "2.2" "User Rights Assignment" "Error" "Failed to check user rights: $($_.Exception.Message)" "N/A" "N/A"
}

# 2.3 Security Options
Write-Host "Checking Security Options..."
function Check-RegistryValue {
    param ($path, $name, $expected, $policyID, $policyName, $appliesTo)
    if ($appliesTo -eq "All" -or ($appliesTo -eq "DC" -and $envType -eq "ActiveDirectory") -or ($appliesTo -eq "MS" -and $envType -in @("WindowsOS", "Server"))) {
        try {
            $value = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name
            $status = if ($null -eq $value) { "Fail" } elseif ($value -eq $expected) { "Pass" } else { "Fail" }
            $riskRating = "High"
            $remediation = "Run: 'Set-ItemProperty -Path $path -Name $name -Value $expected -Type DWORD -Force' to set the registry value."
            Add-Result $policyID $policyName $status "Expected: $expected, Found: $value" $riskRating $remediation
        }
        catch {
            Add-Result $policyID $policyName "Error" "Failed to check registry value: $($_.Exception.Message)" "N/A" "N/A"
        }
    }
}

Check-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "DisableDomainCreds" 1 "2.3.1.2" "Block Microsoft accounts" "All"
Check-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse" 1 "2.3.1.5" "Limit local account use of blank passwords" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "NoConnectedUser" 3 "2.3.1.2" "Block Microsoft accounts" "All"
Check-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoNameReleaseOnDemand" 1 "2.3.10.1" "Allow anonymous SID/Name translation" "All"
Check-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous" 0 "2.3.10.7" "Let Everyone permissions apply to anonymous users" "All"
Check-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous" 1 "2.3.10.3" "Do not allow anonymous enumeration of SAM accounts" "All"
Check-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM" 1 "2.3.10.2" "Do not allow anonymous enumeration of SAM accounts (MS)" "MS"
Check-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionShares" "" "2.3.10.14" "Shares that can be accessed anonymously" "All"
Check-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictRemoteSAM" "O:BAG:BAD:(A;;RC;;;BA)" "2.3.10.13" "Restrict clients allowed to make remote calls to SAM" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" 2 "2.3.17.3" "UAC: Behavior of elevation prompt for admins" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorUser" 0 "2.3.17.5" "UAC: Behavior of elevation prompt for standard users" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableInstallerDetection" 1 "2.3.17.6" "UAC: Detect application installations" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableSecureUIAPaths" 1 "2.3.17.7" "UAC: Only elevate UIAccess applications in secure locations" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" 1 "2.3.17.8" "UAC: Run all administrators in Admin Approval Mode" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" 1 "2.3.17.9" "UAC: Switch to secure desktop for elevation" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableVirtualization" 1 "2.3.17.10" "UAC: Virtualize file and registry write failures" "All"
Check-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "AutoDisconnect" 15 "2.3.9.1" "Microsoft network server: Amount of idle time" "Server"
Check-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature" 1 "2.3.9.2" "Microsoft network server: Digitally sign communications (always)" "Server"
Check-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableSecuritySignature" 1 "2.3.9.3" "Microsoft network server: Digitally sign communications (if client agrees)" "Server"
Check-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" 1 "2.3.8.1" "Microsoft network client: Digitally sign communications (always)" "All"
Check-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnableSecuritySignature" 1 "2.3.8.2" "Microsoft network client: Digitally sign communications (if server agrees)" "All"
Check-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "ProtectionMode" 1 "2.3.15.2" "System objects: Strengthen default permissions" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ShutdownWithoutLogon" 0 "2.3.13.1" "Shutdown: Allow system to be shut down without logon" "All"
Check-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "FIPSAlgorithmPolicy" 1 "2.3.14.1" "System cryptography: Use FIPS compliant algorithms" "All"
Check-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "ForceGuest" 0 "2.3.10.15" "Network access: Sharing and security model for local accounts" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs" 900 "2.3.7.3" "Interactive logon: Machine inactivity limit" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName" 1 "2.3.7.2" "Interactive logon: Don't display last signed-in" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentControlSet\Services\Netlogon\Parameters" "MaximumPasswordAge" 30 "2.3.6.5" "Domain member: Maximum machine account password age" "DC"
Check-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoLMHash" 1 "2.3.11.5" "Network security: Do not store LAN Manager hash value" "All"
Check-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" 5 "2.3.11.7" "Network security: LAN Manager authentication level" "All"

# 5. System Services
Write-Host "Checking System Services..."
$services = @("FTPSVC", "PNRPsvc", "simptcp", "TlntSvr")
if ($envType -in @("Server", "ActiveDirectory")) {
    foreach ($service in $services) {
        try {
            $status = if (Get-Service -Name $service -ErrorAction SilentlyContinue) { "Fail" } else { "Pass" }
            $riskRating = "Medium"
            $remediation = "Run: 'Disable-WindowsOptionalFeature -Online -FeatureName $service -Remove' to uninstall the service."
            Add-Result "5.$($services.IndexOf($service)+1)" "Service: $service not installed" $status "Expected: Not Installed, Found: $(if($status -eq 'Pass'){'Not Installed'}else{'Installed'})" $riskRating $remediation
        }
        catch {
            Add-Result "5.$($services.IndexOf($service)+1)" "Service: $service not installed" "Error" "Failed to check service: $($_.Exception.Message)" "N/A" "N/A"
        }
    }
}

# 9. Windows Firewall with Advanced Security
Write-Host "Checking Windows Firewall..."
function Check-FirewallProfile {
    param ($profile, $policyIDBase)
    try {
        $fwProfile = Get-NetFirewallProfile -Name $profile -ErrorAction Stop
        if ($fwProfile) {
            $status = if ($fwProfile.Enabled) { "Pass" } else { "Fail" }
            $riskRating = "Critical"
            $remediation = "Run: 'Set-NetFirewallProfile -Name $profile -Enabled True' to enable the firewall."
            Add-Result "$policyIDBase.1" "Windows Firewall: ${profile}: Firewall state" $status "Expected: On, Found: $($fwProfile.Enabled)" $riskRating $remediation

            $status = if ($fwProfile.DefaultInboundAction -eq "Block") { "Pass" } else { "Fail" }
            $riskRating = "High"
            $remediation = "Run: 'Set-NetFirewallProfile -Name $profile -DefaultInboundAction Block' to block inbound connections."
            Add-Result "$policyIDBase.2" "Windows Firewall: ${profile}: Inbound connections" $status "Expected: Block, Found: $($fwProfile.DefaultInboundAction)" $riskRating $remediation

            $status = if ($fwProfile.DefaultOutboundAction -eq "Allow") { "Pass" } else { "Fail" }
            $riskRating = "Medium"
            $remediation = "Run: 'Set-NetFirewallProfile -Name $profile -DefaultOutboundAction Allow' to allow outbound connections."
            Add-Result "$policyIDBase.3" "Windows Firewall: ${profile}: Outbound connections" $status "Expected: Allow, Found: $($fwProfile.DefaultOutboundAction)" $riskRating $remediation

            $status = if (-not $fwProfile.NotifyOnListen) { "Pass" } else { "Fail" }
            $riskRating = "Low"
            $remediation = "Run: 'Set-NetFirewallProfile -Name $profile -NotifyOnListen False' to disable notifications."
            Add-Result "$policyIDBase.4" "Windows Firewall: ${profile}: Display a notification" $status "Expected: No, Found: $($fwProfile.NotifyOnListen)" $riskRating $remediation

            $status = if ($fwProfile.LogFileName -eq "%SystemRoot%\System32\logfiles\firewall\$($profile.ToLower())fw.log") { "Pass" } else { "Fail" }
            $riskRating = "Low"
            $remediation = "Run: 'Set-NetFirewallProfile -Name $profile -LogFileName ""%SystemRoot%\System32\logfiles\firewall\$($profile.ToLower())fw.log""' to set the log file name."
            Add-Result "$policyIDBase.5" "Windows Firewall: ${profile}: Logging: Name" $status "Expected: %SystemRoot%\System32\logfiles\firewall\$($profile.ToLower())fw.log, Found: $($fwProfile.LogFileName)" $riskRating $remediation

            $status = if ($fwProfile.LogMaxSizeKilobytes -ge 16384) { "Pass" } else { "Fail" }
            $riskRating = "Low"
            $remediation = "Run: 'Set-NetFirewallProfile -Name $profile -LogMaxSizeKilobytes 16384' to set the log size to 16384 KB or greater."
            Add-Result "$policyIDBase.6" "Windows Firewall: ${profile}: Logging: Size limit" $status "Expected: 16384 KB or greater, Found: $($fwProfile.LogMaxSizeKilobytes)" $riskRating $remediation

            $status = if ($fwProfile.LogDroppedPackets) { "Pass" } else { "Fail" }
            $riskRating = "Medium"
            $remediation = "Run: 'Set-NetFirewallProfile -Name $profile -LogDroppedPackets True' to log dropped packets."
            Add-Result "$policyIDBase.7" "Windows Firewall: ${profile}: Log dropped packets" $status "Expected: Yes, Found: $($fwProfile.LogDroppedPackets)" $riskRating $remediation

            $status = if ($fwProfile.LogAllowedConnections) { "Pass" } else { "Fail" }
            $riskRating = "Medium"
            $remediation = "Run: 'Set-NetFirewallProfile -Name $profile -LogAllowedConnections True' to log allowed connections."
            Add-Result "$policyIDBase.8" "Windows Firewall: ${profile}: Log successful connections" $status "Expected: Yes, Found: $($fwProfile.LogAllowedConnections)" $riskRating $remediation
        }
    }
    catch {
        Add-Result "$policyIDBase" "Windows Firewall: ${profile}" "Error" "Failed to check firewall profile: $($_.Exception.Message)" "N/A" "N/A"
    }
}

Check-FirewallProfile "Domain" "9.1"
Check-FirewallProfile "Private" "9.2"
Check-FirewallProfile "Public" "9.3"
try {
    $publicProfile = Get-NetFirewallProfile -Name Public -ErrorAction Stop
    if ($publicProfile) {
        $status = if (-not $publicProfile.AllowLocalPolicyMerge) { "Pass" } else { "Fail" }
        $riskRating = "Medium"
        $remediation = "Run: 'Set-NetFirewallProfile -Name Public -AllowLocalPolicyMerge False' to prevent local policy merge."
        Add-Result "9.3.5" "Windows Firewall: Public: Apply local firewall rules" $status "Expected: No, Found: $($publicProfile.AllowLocalPolicyMerge)" $riskRating $remediation

        $status = if (-not $publicProfile.AllowLocalIPsecPolicyMerge) { "Pass" } else { "Fail" }
        $riskRating = "Medium"
        $remediation = "Run: 'Set-NetFirewallProfile -Name Public -AllowLocalIPsecPolicyMerge False' to prevent local IPsec policy merge."
        Add-Result "9.3.6" "Windows Firewall: Public: Apply local connection security rules" $status "Expected: No, Found: $($publicProfile.AllowLocalIPsecPolicyMerge)" $riskRating $remediation
    }
}
catch {
    Add-Result "9.3" "Windows Firewall: Public" "Error" "Failed to check public firewall profile: $($_.Exception.Message)" "N/A" "N/A"
}

# 17. Advanced Audit Policy Configuration
Write-Host "Checking Audit Policies..."
function Check-AuditPolicy {
    param ($subcategory, $success, $failure, $policyID, $policyName, $appliesTo)
    if ($appliesTo -eq "All" -or ($appliesTo -eq "DC" -and $envType -eq "ActiveDirectory") -or ($appliesTo -eq "MS" -and $envType -in @("WindowsOS", "Server"))) {
        try {
            $audit = auditpol /get /subcategory:"$subcategory" | Out-String
            $successEnabled = $audit -match "Success\s*enabled"
            $failureEnabled = $audit -match "Failure\s*enabled"
            $status = if ($success -eq $successEnabled -and $failure -eq $failureEnabled) { "Pass" } else { "Fail" }
            $riskRating = "High"
            $remediation = "Run: 'auditpol /set /subcategory:""$subcategory"" /success:$success /failure:$failure' to configure audit policy."
            Add-Result $policyID $policyName $status "Expected: Success=$success, Failure=$failure, Found: Success=$successEnabled, Failure=$failureEnabled" $riskRating $remediation
        }
        catch {
            Add-Result $policyID $policyName "Error" "Failed to check audit policy: $($_.Exception.Message)" "N/A" "N/A"
        }
    }
}

Check-AuditPolicy "Credential Validation" $true $true "17.1.1" "Audit Credential Validation" "All"
Check-AuditPolicy "Application Group Management" $true $true "17.2.1" "Audit Application Group Management" "DC"
Check-AuditPolicy "Security Group Management" $true $false "17.2.5" "Audit Security Group Management" "DC"
Check-AuditPolicy "User Account Management" $true $true "17.2.6" "Audit User Account Management" "All"
Check-AuditPolicy "Plug and Play Events" $true $false "17.3.1" "Audit PNP Activity" "All"
Check-AuditPolicy "Process Creation" $true $false "17.3.2" "Audit Process Creation" "All"
Check-AuditPolicy "Account Lockout" $false $true "17.5.1" "Audit Account Lockout" "All"
Check-AuditPolicy "Group Membership" $true $false "17.5.3" "Audit Group Membership" "All"
Check-AuditPolicy "Logoff" $true $false "17.5.4" "Audit Logoff" "All"
Check-AuditPolicy "Logon" $true $true "17.5.5" "Audit Logon" "All"
Check-AuditPolicy "Other Logon/Logoff Events" $true $true "17.5.6" "Audit Other Logon/Logoff Events" "All"
Check-AuditPolicy "Special Logon" $true $false "17.5.7" "Audit Special Logon" "All"
Check-AuditPolicy "Detailed File Share" $false $true "17.6.1" "Audit Detailed File Share" "Server"
Check-AuditPolicy "File Share" $true $true "17.6.2" "Audit File Share" "Server"
Check-AuditPolicy "Other Object Access Events" $true $true "17.6.3" "Audit Other Object Access Events" "Server"
Check-AuditPolicy "Removable Storage" $true $true "17.6.4" "Audit Removable Storage" "All"
Check-AuditPolicy "Audit Policy Change" $true $true "17.7.1" "Audit Audit Policy Change" "All"
Check-AuditPolicy "Authentication Policy Change" $true $false "17.7.3" "Audit Authentication Policy Change" "DC"
Check-AuditPolicy "Authorization Policy Change" $true $false "17.7.4" "Audit Authorization Policy Change" "DC"
Check-AuditPolicy "MPSSVC Rule-Level Policy Change" $true $true "17.7.5" "Audit MPSSVC Rule-Level Policy Change" "All"
Check-AuditPolicy "Other Policy Change Events" $false $true "17.7.6" "Audit Other Policy Change Events" "All"
Check-AuditPolicy "Sensitive Privilege Use" $true $true "17.8.1" "Audit Sensitive Privilege Use" "All"
Check-AuditPolicy "IPsec Driver" $true $true "17.9.1" "Audit IPsec Driver" "All"
Check-AuditPolicy "Other System Events" $true $true "17.9.2" "Audit Other System Events" "All"
Check-AuditPolicy "Security State Change" $true $false "17.9.3" "Audit Security State Change" "All"
Check-AuditPolicy "Security System Extension" $true $false "17.9.4" "Audit Security System Extension" "All"
Check-AuditPolicy "System Integrity" $true $true "17.9.5" "Audit System Integrity" "All"

# 18. Administrative Templates (Computer)
Write-Host "Checking Administrative Templates (Computer)..."
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera" 1 "18.1.1.1" "Prevent enabling lock screen camera" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow" 1 "18.1.1.2" "Prevent enabling lock screen slide show" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Speech" "AllowSpeechModelUpdate" 0 "18.1.2.2" "Allow users to enable online speech recognition services" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\Personalization" "AllowOnlineTips" 0 "18.1.3" "Allow Online Tips" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network\DNSClient" "EnableMulticast" 0 "18.5.4.1" "Turn off multicast name resolution" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Fonts" "EnableFontProviders" 0 "18.5.5.1" "Enable Font Providers" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network\LanmanWorkstation" "EnableInsecureGuestLogons" 0 "18.5.8.1" "Enable insecure guest logons" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network\LLTDIO" "EnableLLTDIO" 0 "18.5.9.1" "Turn on Mapper I/O (LLTDIO) driver" "Server"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network\RSPNDR" "EnableRSPNDR" 0 "18.5.9.2" "Turn on Responder (RSPNDR) driver" "Server"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network\P2P-pnrp" "Enabled" 0 "18.5.10.2" "Turn off Microsoft Peer-to-Peer Networking Services" "Server"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network\NetworkConnections" "NC_AllowNetBridge_NLA" 0 "18.5.11.2" "Prohibit installation of Network Bridge" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network\NetworkConnections" "NC_StdDomainUserSetLocation" 1 "18.5.11.4" "Require domain users to elevate for network location" "DC"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy" "NoBackgroundPolicy" 0 "18.8.21.2" "Configure registry policy processing: No background processing" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy" "ProcessEvenIfNotChanged" 1 "18.8.21.3" "Configure registry policy processing: Process even if unchanged" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowCrossDeviceClipboard" 0 "18.8.31.1" "Allow Clipboard synchronization across devices" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" 0 "18.8.31.2" "Allow upload of User Activities" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power Management" "AllowNetworkConnectivityStandbyDC" 0 "18.8.34.6.1" "Allow network connectivity during connected-standby (DC)" "DC"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power Management" "AllowNetworkConnectivityStandbyAC" 0 "18.8.34.6.2" "Allow network connectivity during connected-standby (AC)" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power Management" "PromptPasswordOnResumeDC" 1 "18.8.34.6.3" "Require password when computer wakes (DC)" "DC"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power Management" "PromptPasswordOnResumeAC" 1 "18.8.34.6.4" "Require password when computer wakes (AC)" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteAssistance" "fAllowToGetHelp" 0 "18.8.36.1" "Configure Offer Remote Assistance" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteAssistance" "fAllowFullControl" 0 "18.8.36.2" "Configure Solicited Remote Assistance" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowBasic" 0 "18.9.97.1.1" "WinRM Client: Allow Basic authentication" "Server"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowUnencrypted" 0 "18.9.97.1.2" "WinRM Client: Allow unencrypted traffic" "Server"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowDigest" 0 "18.9.97.1.3" "WinRM Client: Disallow Digest authentication" "Server"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowBasic" 0 "18.9.97.2.1" "WinRM Service: Allow Basic authentication" "Server"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowRemoteAccess" 0 "18.9.97.2.2" "WinRM Service: Allow remote server management" "Server"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowUnencrypted" 0 "18.9.97.2.3" "WinRM Service: Allow unencrypted traffic" "Server"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "DisableRunAs" 1 "18.9.97.2.4" "WinRM Service: Disallow RunAs credentials" "Server"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRS" "AllowRemoteShellAccess" 0 "18.9.98.1" "Allow Remote Shell Access" "Server"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "EnableVirtualizationBasedSecurity" 1 "18.8.5.1" "Turn On Virtualization Based Security" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "RequirePlatformSecurityFeatures" 3 "18.8.5.2" "Turn On Virtualization Based Security: Platform Security Level" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "HypervisorEnforcedCodeIntegrity" 1 "18.8.5.3" "Turn On Virtualization Based Security: Code Integrity" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "HVCIMATRequired" 1 "18.8.5.4" "Turn On Virtualization Based Security: UEFI Memory Attributes" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "LsaCfgFlags" 0 "18.8.5.6" "Turn On Virtualization Based Security: Credential Guard (DC)" "DC"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "SecureLaunch" 1 "18.8.5.7" "Turn On Virtualization Based Security: Secure Launch" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "BootDriverPolicy" 3 "18.8.14.1" "Boot-Start Driver Initialization Policy" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DisableAutoAdminLogon" 1 "18.4.1" "MSS: Enable Automatic Logon" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Network\Tcpip\Parameters" "DisableIPSourceRouting" 2 "18.4.3" "MSS: IP source routing protection (IPv4)" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Network\Tcpip6\Parameters" "DisableIPSourceRouting" 2 "18.4.2" "MSS: IP source routing protection (IPv6)" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Network\Tcpip\Parameters" "EnableICMPRedirect" 0 "18.4.4" "MSS: Allow ICMP redirects" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Network\Tcpip\Parameters" "KeepAliveTime" 300000 "18.4.5" "MSS: KeepAliveTime" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Network\Tcpip\Parameters" "PerformRouterDiscovery" 0 "18.4.7" "MSS: PerformRouterDiscovery" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\System\CurrentControlSet\Control\Session Manager" "ScreenSaverGracePeriod" 5 "18.4.9" "MSS: ScreenSaverGracePeriod" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Network\Tcpip\Parameters" "TcpMaxDataRetransmissions" 3 "18.4.11" "MSS: TcpMaxDataRetransmissions (IPv4)" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Network\Tcpip6\Parameters" "TcpMaxDataRetransmissions" 3 "18.4.10" "MSS: TcpMaxDataRetransmissions (IPv6)" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\System\CurrentControlSet\Services\EventLog\Security" "WarningLevel" 90 "18.4.12" "MSS: WarningLevel for security event log" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Camera" "AllowCamera" 0 "18.9.12.1" "Allow Use of Camera" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1 "18.9.13.2" "Turn off Microsoft consumer experiences" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" "RequirePinForPairing" 1 "18.9.14.1" "Require pin for pairing" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Credentials" "DisablePasswordReveal" 1 "18.9.15.1" "Do not display the password reveal button" "All"
Check-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\Credentials" "EnumerateAdministrators" 0 "18.9.15.2" "Enumerate administrator accounts on elevation" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0 "18.9.16.1" "Allow Telemetry" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DisableEnterpriseAuthProxy" 1 "18.9.16.2" "Configure Authenticated Proxy usage" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications" 1 "18.9.16.3" "Do not show feedback notifications" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DisableInsiderBuilds" 1 "18.9.16.4" "Toggle user control over Insider builds" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AutoPlay" "DisallowAutoplayForNonVolume" 1 "18.9.8.1" "Disallow Autoplay for non-volume devices" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AutoPlay" "AutoRun" 0 "18.9.8.2" "Set default behavior for AutoRun" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AutoPlay" "NoDriveTypeAutoRun" 255 "18.9.8.3" "Turn off Autoplay" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Biometrics" "EnhancedAntiSpoofing" 1 "18.9.10.1.1" "Configure enhanced anti-spoofing" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "PreventOneDriveFileSync" 1 "18.9.55.1" "Prevent the usage of OneDrive for file storage" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices" "fDisableCdm" 1 "18.9.62.3.3.2" "Do not allow drive redirection" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices" "fPromptForPassword" 1 "18.9.62.3.9.1" "Always prompt for password upon connection" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices" "fRequireSecureRPC" 1 "18.9.62.3.9.2" "Require secure RPC communication" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices" "SecurityLayer" 2 "18.9.62.3.9.3" "Require specific security layer for RDP" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices" "UserAuthentication" 1 "18.9.62.3.9.4" "Require user authentication for RDP" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices" "EncryptionLevel" 3 "18.9.62.3.9.5" "Set client connection encryption level" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices" "MaxIdleTime" 900000 "18.9.62.3.10.1" "Set time limit for active but idle RDP sessions" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteDesktopServices" "MaxDisconnectionTime" 60000 "18.9.62.3.10.2" "Set time limit for disconnected sessions" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RSS Feeds" "PreventDownloadingEnclosures" 1 "18.9.63.1" "Prevent downloading of enclosures" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Search" "AllowCloudSearch" 0 "18.9.64.2" "Allow Cloud Search" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Search" "AllowIndexingEncryptedStores" 0 "18.9.64.3" "Allow indexing of encrypted files" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" "EnableScriptBlockLogging" 1 "18.9.95.1" "Turn on PowerShell Script Block Logging" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" "EnableTranscription" 0 "18.9.95.3" "Turn on PowerShell Transcription" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "ManagePreviewBuilds" 1 "18.9.102.1.1" "Manage preview builds" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferFeatureUpdatesPeriodInDays" 180 "18.9.102.1.2" "Select when Preview Builds are received" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferQualityUpdatesPeriodInDays" 0 "18.9.102.1.3" "Select when Quality Updates are received" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "NoAutoUpdate" 0 "18.9.102.2" "Configure Automatic Updates" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "ScheduledInstallDay" 0 "18.9.102.3" "Configure Automatic Updates: Scheduled install day" "All"
Check-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "NoAutoRebootWithLoggedOnUsers" 0 "18.9.102.4" "No auto-restart for scheduled updates" "All"

# 19. Administrative Templates (User)
Write-Host "Checking Administrative Templates (User)..."
Check-RegistryValue "HKCU:\Software\Policies\Microsoft\Control Panel\Desktop" "ScreenSaveActive" 1 "19.1.3.1" "Enable screen saver" "All"
Check-RegistryValue "HKCU:\Software\Policies\Microsoft\Control Panel\Desktop" "SCRNSAVE.EXE" "scrnsave.scr" "19.1.3.2" "Force specific screen saver" "All"
Check-RegistryValue "HKCU:\Software\Policies\Microsoft\Control Panel\Desktop" "ScreenSaverIsSecure" 1 "19.1.3.3" "Password protect the screen saver" "All"
Check-RegistryValue "HKCU:\Software\Policies\Microsoft\Control Panel\Desktop" "ScreenSaveTimeOut" 900 "19.1.3.4" "Screen saver timeout" "All"
Check-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\Notifications" "NoToastOnLockScreen" 1 "19.5.1.1" "Turn off toast notifications on the lock screen" "All"
Check-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" "DisableWindowsSpotlight" 1 "19.7.8.1" "Configure Windows spotlight on lock screen" "All"
Check-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" "DisableThirdPartySuggestions" 1 "19.7.8.2" "Do not suggest third-party content in Windows spotlight" "All"
Check-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiences" 1 "19.7.8.3" "Do not use diagnostic data for tailored experiences" "All"
Check-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\AttachmentManager" "PreserveZoneInfo" 0 "19.7.4.1" "Do not preserve zone information in file attachments" "All"
Check-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\AttachmentManager" "NotifyAntivirus" 1 "19.7.4.2" "Notify antivirus programs when opening attachments" "All"
Check-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\NetworkSharing" "NoInplaceSharing" 1 "19.7.28.1" "Prevent users from sharing files within their profile" "All"
Check-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\WindowsMediaPlayer" "PreventCodecDownload" 1 "19.7.47.2.1" "Prevent Codec Download" "All"

# 20. Additional STIG Settings (Manual)
Write-Host "Adding manual STIG checks..."
$stigManual = @(
    @{ID="20.1"; Name="Accounts require passwords"; Details="Requires manual verification: Ensure all accounts have passwords configured."; AppliesTo="All"; RiskRating="High"; Remediation="Manually set passwords for all accounts via Active Directory Users and Computers or Local Users and Groups."},
    @{ID="20.2"; Name="Active Directory AdminSDHolder object audit settings (DC)"; Details="Requires manual verification on Domain Controller: Ensure proper audit settings for AdminSDHolder object."; AppliesTo="DC"; RiskRating="High"; Remediation="Manually configure audit settings for AdminSDHolder object using Active Directory administrative tools."},
    @{ID="20.3"; Name="Active Directory Domain Controllers OU permissions (DC)"; Details="Requires manual verification on Domain Controller: Ensure proper access control permissions for Domain Controllers OU."; AppliesTo="DC"; RiskRating="High"; Remediation="Manually adjust permissions on Domain Controllers OU using Active Directory administrative tools."},
    @{ID="20.4"; Name="Active Directory Domain Controllers OU audit settings (DC)"; Details="Requires manual verification on Domain Controller: Ensure proper audit settings for Domain Controllers OU."; AppliesTo="DC"; RiskRating="High"; Remediation="Manually configure audit settings for Domain Controllers OU using Active Directory administrative tools."},
    @{ID="20.5"; Name="Active Directory Domain object audit settings (DC)"; Details="Requires manual verification on Domain Controller: Ensure proper audit settings for Domain object."; AppliesTo="DC"; RiskRating="High"; Remediation="Manually configure audit settings for Domain object using Active Directory administrative tools."},
    @{ID="20.6"; Name="Active Directory Group Policy objects audit settings (DC)"; Details="Requires manual verification on Domain Controller: Ensure proper audit settings for Group Policy objects."; AppliesTo="DC"; RiskRating="High"; Remediation="Manually configure audit settings for Group Policy objects using Group Policy Management."},
    @{ID="20.7"; Name="Active Directory Group Policy objects permissions (DC)"; Details="Requires manual verification on Domain Controller: Ensure proper access control permissions for Group Policy objects."; AppliesTo="DC"; RiskRating="High"; Remediation="Manually adjust permissions for Group Policy objects using Group Policy Management."},
    @{ID="20.8"; Name="Active Directory Infrastructure object audit settings (DC)"; Details="Requires manual verification on Domain Controller: Ensure proper audit settings for Infrastructure object."; AppliesTo="DC"; RiskRating="High"; Remediation="Manually configure audit settings for Infrastructure object using Active Directory administrative tools."},
    @{ID="20.9"; Name="Active Directory RID Manager$ object audit settings (DC)"; Details="Requires manual verification on Domain Controller: Ensure proper audit settings for RID Manager$ object."; AppliesTo="DC"; RiskRating="High"; Remediation="Manually configure audit settings for RID Manager$ object using Active Directory administrative tools."},
    @{ID="20.10"; Name="Active Directory SYSVOL directory permissions (DC)"; Details="Requires manual verification on Domain Controller: Ensure proper access control permissions for SYSVOL directory."; AppliesTo="DC"; RiskRating="Critical"; Remediation="Manually adjust permissions on SYSVOL directory using File Explorer with administrative privileges."},
    @{ID="20.11"; Name="Active Directory user accounts require CAC/PIV/ALT (DC)"; Details="Requires manual verification on Domain Controller: Ensure user accounts require CAC, PIV, or ALT for authentication."; AppliesTo="DC"; RiskRating="Critical"; Remediation="Manually configure authentication policies in Active Directory to enforce CAC/PIV/ALT."},
    @{ID="20.12"; Name="Administrative accounts restricted from Internet apps"; Details="Requires manual verification: Ensure administrative accounts are not used with Internet-facing applications like web browsers or email."; AppliesTo="All"; RiskRating="Critical"; Remediation="Manually enforce policy to restrict admin accounts from Internet apps using Group Policy or manual user training."},
    @{ID="20.13"; Name="Audit records backed up to different system"; Details="Requires manual verification: Ensure audit records are backed up to a different system or media."; AppliesTo="All"; RiskRating="High"; Remediation="Manually configure a backup schedule to export audit logs to a separate system."},
    @{ID="20.14"; Name="Automated mechanisms for system component state"; Details="Requires manual verification: Ensure automated mechanisms are employed to monitor system component states."; AppliesTo="All"; RiskRating="Medium"; Remediation="Manually deploy a monitoring tool like System Center or a custom script to track component states."},
    @{ID="20.15"; Name="Data files on different partition (DC)"; Details="Requires manual verification on Domain Controller: Ensure user data files are on a different logical partition from directory server data files."; AppliesTo="DC"; RiskRating="High"; Remediation="Manually move user data files to a separate partition using Disk Management."},
    @{ID="20.16"; Name="HKEY_LOCAL_MACHINE permissions"; Details="Requires manual verification: Ensure default permissions for HKEY_LOCAL_MACHINE registry hive are maintained."; AppliesTo="All"; RiskRating="Critical"; Remediation="Manually review and restore default permissions for HKEY_LOCAL_MACHINE using regedit."},
    @{ID="20.17"; Name="Deny-all, permit-by-exception policy"; Details="Requires manual verification: Ensure a deny-all, permit-by-exception policy is implemented for software execution."; AppliesTo="All"; RiskRating="High"; Remediation="Manually configure AppLocker or Software Restriction Policies to enforce deny-all policy."},
    @{ID="20.18"; Name="LDAP connection termination after 5 minutes (DC)"; Details="Requires manual verification on Domain Controller: Ensure LDAP connections terminate after 5 minutes of inactivity."; AppliesTo="DC"; RiskRating="Medium"; Remediation="Manually configure LDAP timeout settings in Active Directory administrative tools."},
    @{ID="20.19"; Name="DoD Interoperability Root CA certificates"; Details="Requires manual verification: Ensure DoD Interoperability Root CA cross-certificates are in the Untrusted Certificates Store."; AppliesTo="All"; RiskRating="High"; Remediation="Manually import DoD Interoperability Root CA certificates into the Untrusted Certificates Store via certmgr.msc."},
    @{ID="20.20"; Name="DoD Root CA certificates"; Details="Requires manual verification: Ensure DoD Root CA certificates are installed in the Trusted Root Store."; AppliesTo="All"; RiskRating="High"; Remediation="Manually import DoD Root CA certificates into the Trusted Root Store via certmgr.msc."},
    @{ID="20.21"; Name="Domain Controller PKI certificates (DC)"; Details="Requires manual verification on Domain Controller: Ensure PKI certificates are issued by DoD PKI or approved ECA."; AppliesTo="DC"; RiskRating="Critical"; Remediation="Manually request and install PKI certificates from DoD PKI or an approved ECA."},
    @{ID="20.22"; Name="Domain controllers have PKI certificate (DC)"; Details="Requires manual verification on Domain Controller: Ensure domain controllers have a PKI server certificate."; AppliesTo="DC"; RiskRating="Critical"; Remediation="Manually request and install a PKI server certificate on each domain controller."},
    @{ID="20.23"; Name="Domain controllers dedicated machine (DC)"; Details="Requires manual verification on Domain Controller: Ensure domain controllers run on dedicated machines."; AppliesTo="DC"; RiskRating="Critical"; Remediation="Manually reconfigure domain controllers to run on dedicated hardware or VMs."},
    @{ID="20.24"; Name="Trusted Platform Module enabled"; Details="Requires manual verification: Ensure systems have TPM enabled and ready for use."; AppliesTo="All"; RiskRating="High"; Remediation="Manually enable TPM in BIOS/UEFI settings and configure it via tpm.msc."},
    @{ID="20.25"; Name="Emergency accounts removal"; Details="Requires manual verification: Ensure emergency accounts are removed or disabled within 72 hours."; AppliesTo="All"; RiskRating="High"; Remediation="Manually disable or remove emergency accounts via Active Directory or Local Users and Groups after 72 hours."},
    @{ID="20.26"; Name="Event Viewer protection"; Details="Requires manual verification: Ensure Event Viewer is protected from unauthorized modification and deletion."; AppliesTo="All"; RiskRating="Critical"; Remediation="Manually configure NTFS permissions to restrict Event Viewer log access to Administrators only."},
    @{ID="20.27"; Name="Fax Server role not installed"; Details="Requires manual verification: Ensure Fax Server role is not installed."; AppliesTo="Server"; RiskRating="Medium"; Remediation="Manually uninstall Fax Server role via Server Manager if installed."},
    @{ID="20.28"; Name="FTP servers prevent system drive access"; Details="Requires manual verification: Ensure FTP servers are configured to prevent access to the system drive."; AppliesTo="Server"; RiskRating="High"; Remediation="Manually configure FTP server settings to restrict system drive access."},
    @{ID="20.29"; Name="FTP servers prevent anonymous logons"; Details="Requires manual verification: Ensure FTP servers are configured to prevent anonymous logons."; AppliesTo="Server"; RiskRating="High"; Remediation="Manually disable anonymous logon in FTP server configuration."},
    @{ID="20.30"; Name="Host-based firewall installed"; Details="Requires manual verification: Ensure a host-based firewall is installed and enabled."; AppliesTo="All"; RiskRating="Critical"; Remediation="Manually install and enable Windows Firewall or a third-party firewall."},
    @{ID="20.31"; Name="krbtgt account password age (DC)"; Details="Requires manual verification on Domain Controller: Ensure krbtgt account password is no more than 180 days old."; AppliesTo="DC"; RiskRating="High"; Remediation="Manually reset krbtgt account password using Active Directory administrative tools."},
    @{ID="20.32"; Name="Local volumes use NTFS"; Details="Requires manual verification: Ensure local volumes use a format supporting NTFS attributes."; AppliesTo="All"; RiskRating="Medium"; Remediation="Manually convert volumes to NTFS using 'convert X: /fs:ntfs' if not already NTFS."},
    @{ID="20.33"; Name="Application account password length"; Details="Requires manual verification: Ensure manually managed application account passwords are at least 15 characters."; AppliesTo="All"; RiskRating="High"; Remediation="Manually update application account passwords to 15+ characters via account management tools."},
    @{ID="20.34"; Name="Application account password change"; Details="Requires manual verification: Ensure application account passwords are changed annually or upon admin departure."; AppliesTo="All"; RiskRating="High"; Remediation="Manually schedule annual password changes or update upon admin departure."},
    @{ID="20.35"; Name="Backup Operators separate accounts"; Details="Requires manual verification: Ensure Backup Operators have separate accounts for backup and operational tasks."; AppliesTo="All"; RiskRating="Medium"; Remediation="Manually create separate accounts for Backup Operators via Active Directory or Local Users and Groups."},
    @{ID="20.36"; Name="Printer share permissions"; Details="Requires manual verification: Ensure only non-administrative accounts have print permissions on printer shares."; AppliesTo="Server"; RiskRating="Medium"; Remediation="Manually adjust printer share permissions to exclude admin accounts."},
    @{ID="20.37"; Name="Non-system file share permissions"; Details="Requires manual verification: Ensure non-system-created file shares limit access to required groups."; AppliesTo="Server"; RiskRating="Medium"; Remediation="Manually configure file share permissions to restrict access to required groups only."},
    @{ID="20.38"; Name="Audit record off-load"; Details="Requires manual verification: Ensure audit records are off-loaded in real-time for interconnected systems or weekly for standalone systems."; AppliesTo="All"; RiskRating="High"; Remediation="Manually configure a script or tool to off-load audit logs according to the schedule."},
    @{ID="20.39"; Name="Only Administrators have Admin rights (MS)"; Details="Requires manual verification: Ensure only Administrators have Administrator rights on the system (MS only)."; AppliesTo="MS"; RiskRating="Critical"; Remediation="Manually review and remove non-Administrator accounts from the Administrators group."},
    @{ID="20.40"; Name="Only responsible admins have Admin rights (DC)"; Details="Requires manual verification on Domain Controller: Ensure only responsible administrators have Admin rights."; AppliesTo="DC"; RiskRating="Critical"; Remediation="Manually review and restrict Admin rights to responsible administrators in Active Directory."},
    @{ID="20.41"; Name="Supported OS servicing level"; Details="Requires manual verification: Ensure system is running a supported OS servicing level."; AppliesTo="All"; RiskRating="Critical"; Remediation="Manually upgrade to a supported OS servicing level via Windows Update or media installation."}
)

foreach ($item in $stigManual) {
    if ($item.AppliesTo -eq "All" -or ($item.AppliesTo -eq "DC" -and $envType -eq "ActiveDirectory") -or ($item.AppliesTo -eq "MS" -and $envType -in @("WindowsOS", "Server"))) {
        Add-Result $item.ID $item.Name "Manual" $item.Details $item.RiskRating $item.Remediation
    }
}

# Generate HTML Report
Write-Host "Generating HTML report..."
$reportPath = Join-Path $scriptDir "Security_Compliance_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
$css = @"
<style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1 { color: #333; }
    table { border-collapse: collapse; width: 100%; margin-top: 20px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background-color: #f2f2f2; }
    tr:nth-child(even) { background-color: #f9f9f9; }
    .pass { background-color: #90ee90; }
    .fail { background-color: #ff6347; }
    .manual { background-color: #ffd700; }
    .error { background-color: #d3d3d3; }
    .critical { color: red; }
    .high { color: orange; }
    .medium { color: yellow; }
    .low { color: green; }
</style>
"@

$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>CIS Benchmark Compliance Report</title>
    $css
</head>
<body>
    <h1>CIS Benchmark Compliance Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</h1>
    <p>Environment: $envType</p>
    <table>
        <tr>
            <th>Policy ID</th>
            <th>Policy Name</th>
            <th>Status</th>
            <th>Details</th>
            <th>Risk Rating</th>
            <th>Remediation</th>
        </tr>
"@

foreach ($result in $global:results) {
    $statusClass = $result.Status.ToLower()
    $riskClass = $result.RiskRating.ToLower()
    $html += @"
        <tr>
            <td>$($result.PolicyID)</td>
            <td>$($result.PolicyName)</td>
            <td class="$statusClass">$($result.Status)</td>
            <td>$($result.Details)</td>
            <td class="$riskClass">$($result.RiskRating)</td>
            <td>$($result.Remediation)</td>
        </tr>
"@
}

$html += @"
    </table>
</body>
</html>
"@

$html | Out-File -FilePath $reportPath -Encoding UTF8
Write-Host "Report generated at: $reportPath"

# Cleanup
if (Test-Path $seceditFile) { Remove-Item $seceditFile -Force }
