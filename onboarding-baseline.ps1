# Define the network location and local temporary folder
## Edit to reflect source and destination of your software installation files.
## Comment out '$NetworkPath' if you intend to move files outside of this script.
$NetworkPath = "\\upa-azdc1\deploy$\SoftwareInstall_Baseline"
$LocalTempFolder = "C:\temp\SoftwareInstall"

# Define the list of software to install
## Path MUST be location of installation file FROM 'LocalTempFolder' : i.e. "'C:\temp\SoftwareInstall' \ 'nextiva\Nextiva-win.exe'"
$SoftwareList = @(
    @{Name = "Cisco VPN"; Path = "cisco-secure-client\cisco-secure-client.msi"; Arguments = "/qn /norestart"}
    @{Name = "Cisco VPN Profile"; Path = "cisco-secure-client\profile-copy.bat"; Arguments = ""}
    @{Name = "Chrome"; Path = "chrome\ChromeSetup.exe"; Arguments = "/silent /install"}
    @{Name = "Wondershare"; Path = "wondershare\pdfelement8_en.exe"; Arguments = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-"}
    @{Name = "Adobe Reader"; Path = "adobe-reader\adobe-reader.exe"; Arguments = "/sAll /silent /install"}
    @{Name = "VLC Media Player"; Path = "vlc\vlc.exe"; Arguments = "/L=1033 /S"}
    @{Name = "7zip Archiver"; Path = "7zip\7zip.exe"; Arguments = "/S"}
    @{Name = "MS Office"; Path = "ms-office-deployment\ms-office-install.bat"; Arguments = ""}
)

# Define programs to uninstall (Program Display Names as seen in "Apps & Features")
## Script can handle AppxPackages and UWP App names and GUID if known; it SHOULD hunt everything down on its own, but the more detail for your specific package, the better.
$UninstallList = @(

### Windows Default Apps ###
	"Copilot"
	"Copilot 365"
	"Cortana"
	"Mail and Calendar"
	"Maps"
	"Microsoft 365"
	"Microsoft Family"
	"Microsoft OneNote"
	"Microsoft Teams"
	"Movies & TV"
	"Office"
	"OneNote"
	"Skype"
	"Solitaire"
	"Windows 11 Installation Assistant"
	"Xbox Console Companion"
	"Xbox Live"
	"*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
	"*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"
	"Microsoft.BingNews"
	"Microsoft.GamingApp"
	"Microsoft.GetHelp"
    "Microsoft.Getstarted"
	"Microsoft.Microsoft3DViewer"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
	"Microsoft.MixedReality.Portal"
	"Microsoft.News"
	"Microsoft.Office.Lens"
	"Microsoft.Office.OneNote"
	"Microsoft.OutlookForWindows"
    "Microsoft.People"
	"Microsoft.SkyeApp"
	"MicrosoftTeams"
	"Microsoft.Wallet"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.XboxApp"
	"Microsoft.YourPhone"
	"Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
	"MicrosoftCorporationII.MicrosoftFamily"
	"MicrosoftCorporationII.QuickAssist"
	"MicrosoftWindows.Client.WebExperience"
	"MicrosoftWindows.CrossDevice"
	
### HP Bloatware ###
	"HP Connection Optimizer"
	"HP Documentation"
	"HP Notifications"
    "HP PC Hardware Diagnostics Windows"
	"HP Privacy Settings"
	"HP SMART"
	"HP Support Assistant"
	"HP Sure Recover"
    "HP Sure Run Module"
	"HP System Information"
	"myHP"
	"AD2F1837.HPJumpStarts"
    "AD2F1837.HPPCHardwareDiagnosticsWindows"
    "AD2F1837.HPPowerManager"
    "AD2F1837.HPPrivacySettings"
    "AD2F1837.HPSupportAssistant"
    "AD2F1837.HPSureShieldAI"
    "AD2F1837.HPSystemInformation"
    "AD2F1837.HPQuickDrop"
    "AD2F1837.HPWorkWell"
    "AD2F1837.myHP"
    "AD2F1837.HPDesktopSupportUtilities"
    "AD2F1837.HPQuickTouch"
    "AD2F1837.HPEasyClean"
    "AD2F1837.HPSystemInformation"
	
### UPA Obsolete Apps ###
	"Actian"
	"ASUS"
	"Allworx Interact"
	"Citrix"
	"Ecosystem agent"
	"File Cache Service Agent"
	"Install MFC Application"
	"Local Administrator Password Solution"
	"Mozilla Firefox"
	"PaperVision"
	"Patch Management Service Controller"
	"PDF Pro 10"
	"Request Handler Agent"
	"Skyline"
	"Skype for Business"
	"TSPrint"
	"TSPrint Client"
	"TSScan"
	"Xerox Desktop Print Experience"
    "Xerox Print and Scan Experience"
	
## Fresh Start (uninstall to reinstall specific executable version)
	"Adobe"
	"Chrome"
	"Cisco"
	"Kaseya"
	"Nextiva"
	"Webroot SecureAnywhere"
	"Wondershare PDFelement"
	"Wondershare Helper Compact"
	"OneDrive"
	"Printer Installer Client"
	"Poly Lens"
	"YARDI"
	"CINC"
	"Strongroom"
	"Invoice Upload"
	"Panini"
	"Ranger"
	"Check Scanner"
)

$HPWolfList = @(
# Required Separation due to HPWolf killing File Explorer and forcing restart. This list is completed AFTER the Installations. 
	"HP Wolf Security"
	"HP Wolf Security - Console"
    "HP Security Update Service"
)
########## DO NOT EDIT BELOW THIS LINE ##########

function Uninstall-Program {
    param (
        [Parameter(Mandatory)]
        [string[]]$UninstallList
    )

    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($program in $UninstallList) {
        Write-Host "`n=== Processing: $program ==="

        # Stop associated processes
        Get-Process | Where-Object { $_.Name -like "*$program*" } | ForEach-Object {
            try {
                Stop-Process -Id $_.Id -Force -ErrorAction Stop
                Write-Host "Stopped process: $($_.Name)"
            } catch {
                Write-Host "Could not stop process: $($_.Name) - $_"
            }
        }

        # EXE / MSI uninstall using registry
        foreach ($regPath in $registryPaths) {
            Get-ItemProperty $regPath -ErrorAction SilentlyContinue | Where-Object {
                $_.DisplayName -like "*$program*"
            } | ForEach-Object {
                $displayName = $_.DisplayName
                $uninstallString = $_.UninstallString
                $quietUninstallString = $_.QuietUninstallString

                if ($uninstallString) {
                    try {
                        $command = if ($quietUninstallString) { $quietUninstallString } else { $uninstallString }
                        $commandParts = $command -split '\s+', 2
                        $exe = $commandParts[0].Trim('"')
                        $args = if ($commandParts.Count -gt 1) { $commandParts[1] } else { '' }

                        Write-Host "Uninstalling (EXE/MSI): $displayName"
                        Start-Process -FilePath $exe -ArgumentList $args -Wait -NoNewWindow
                    } catch {
                        Write-Host "Uninstall failed for $displayName: $_"
                    }
                }
            }
        }

        # GUID-based uninstall fallback
        $msiGuidPattern = '^\{[0-9A-Fa-f\-]{36}\}$'
        foreach ($regPath in $registryPaths) {
            Get-ChildItem $regPath -ErrorAction SilentlyContinue | Where-Object {
                $_.PSChildName -match $msiGuidPattern
            } | ForEach-Object {
                $props = Get-ItemProperty $_.PSPath
                if ($props.DisplayName -like "*$program*") {
                    try {
                        Write-Host "Uninstalling via GUID: $($_.PSChildName)"
                        Start-Process "msiexec.exe" -ArgumentList "/x $($_.PSChildName) /qn /norestart" -Wait -NoNewWindow
                    } catch {
                        Write-Host "GUID uninstall failed: $($_.PSChildName) - $_"
                    }
                }
            }
        }

        # AppxPackage (UWP) user-level removal
        $appxPackages = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*$program*" -or $_.PackageFullName -like "*$program*" }
        foreach ($pkg in $appxPackages) {
            try {
                Write-Host "Removing AppxPackage: $($pkg.Name)"
                Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction SilentlyContinue
            } catch {
                Write-Host "Failed to remove AppxPackage: $($pkg.Name) - $_"
            }
        }

        # AppxProvisionedPackage removal (future user installs)
        $provPackages = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*$program*" }
        foreach ($provPkg in $provPackages) {
            try {
                Write-Host "Removing Provisioned Package: $($provPkg.DisplayName)"
                Remove-AppxProvisionedPackage -Online -PackageName $provPkg.PackageName -ErrorAction SilentlyContinue
            } catch {
                Write-Host "Failed to remove provisioned Appx package: $($provPkg.DisplayName) - $_"
            }
        }

        # Final check to confirm removal
        $remaining = $false
        foreach ($regPath in $registryPaths) {
            $remaining = Get-ItemProperty $regPath -ErrorAction SilentlyContinue | Where-Object {
                $_.DisplayName -like "*$program*"
            }
            if ($remaining) { break }
        }

        if ($remaining) {
            Write-Host "$program still detected after uninstall attempts."
        } else {
            Write-Host "$program fully removed."
        }

        Write-Host "---------------------------------------"
    }
}

$LogPath = "C:\kworking\onboarding-log_$env:COMPUTERNAME.txt"
Start-Transcript -Path $LogPath -Append

# Ensure the script is running with administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator!" -ForegroundColor Red
    exit 1
}

## Update Active Directory to Reflect Device Type and Unassigned Status

# Check if machine is domain-joined
if (-not (Test-ComputerSecureChannel)) {
    Write-Error "This computer is not joined to a domain. Exiting script."
    exit 1
}

# Check if Active Directory module is available
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "Active Directory module not found. Installing RSAT: Active Directory..." -ForegroundColor Yellow
    try {
        Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ErrorAction Stop
        Write-Host "RSAT Active Directory module installed successfully." -ForegroundColor Green
    } catch {
        Write-Error "Failed to install RSAT Active Directory module. Error: $_"
        exit 1
    }
}

Import-Module ActiveDirectory

# Get local computer name
$ComputerName = $env:COMPUTERNAME

# Get the computer object from AD
try {
    $Computer = Get-ADComputer -Identity $ComputerName -ErrorAction Stop
} catch {
    Write-Error "Failed to get AD computer object: $_"
    exit 1
}

# Prompt user for a description
$Description = Read-Host "Enter a new description for the computer object"

# Prompt user for a Serial Number
$Serial = Read-Host "Enter the device's serial number"

# Define the new OU Distinguished Name (modify this)
$NewOU = "OU=Unassigned,OU=UPA-Workstations,DC=unitedpropertyassociates.com,DC=com"

# Move the computer to the new OU
Move-ADObject -Identity $Computer.DistinguishedName -TargetPath $NewOU -Confirm:$false
if ($Computer -eq $null) {
    Write-Error "Could not find computer object '$ComputerName' in AD. Exiting."
    exit 1
}

# Update attributes
Set-ADComputer -Identity $ComputerName `
    -Description $Description `
	-serialNumber $Serial `
    -ManagedBy $null `
    -PhysicalDeliveryOfficeName $null

Write-Host "Moved $ComputerName to $NewOU and updated attributes." -ForegroundColor Green

## Uninstall Cycle

# **Step 1: Uninstall Existing Software**
## Backup existing URL handler registry keys
$httpKey = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice"
$httpsKey = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice"
$backupHttp = Get-ItemProperty -Path $httpKey -ErrorAction SilentlyContinue
$backupHttps = Get-ItemProperty -Path $httpsKey -ErrorAction SilentlyContinue

## Remove browser URL associations
#Remove-Item -Path $httpKey -Force -ErrorAction SilentlyContinue
#Remove-Item -Path $httpsKey -Force -ErrorAction SilentlyContinue
Write-Output "Starting uninstallation of specified programs..."

## Call Uninstall Function
foreach ($Program in $UninstallList) {
    Uninstall-Program -ProgramName $Program
}

Write-Output "Uninstallation process completed."

# **Step 2: Install Software**
Write-Output "Starting software installation process..."

if (-not (Test-Path -Path $LocalTempFolder)) {
    Write-Output "Creating local temporary folder at $LocalTempFolder..."
    New-Item -Path $LocalTempFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
}

Write-Output "Copying files from $NetworkPath to $LocalTempFolder..."
Copy-Item -Path "$NetworkPath\*" -Destination $LocalTempFolder -Recurse -Force -ErrorAction SilentlyContinue

## Install each program in the list
foreach ($Software in $SoftwareList) {
    $InstallerPath = Join-Path -Path $LocalTempFolder -ChildPath $Software.Path
    if (Test-Path -Path $InstallerPath) {
        Write-Output "Running $($Software.Name)..."
        try {
            if ($InstallerPath -match "\.bat$") {
                # If it's a .bat file, use cmd.exe /c to execute
                Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$InstallerPath`"" -Wait -NoNewWindow
            }
            elseif ($InstallerPath -match "\.msi$") {
                # If it's an .msi file, use msiexec.exe /i
                $MsiArguments = "/i `"$InstallerPath`" /quiet /norestart"
                
                # Use custom arguments if provided
                if (![string]::IsNullOrWhiteSpace($Software.Arguments)) {
                    $MsiArguments = "/i `"$InstallerPath`" $($Software.Arguments)"
                }

                Start-Process -FilePath "msiexec.exe" -ArgumentList $MsiArguments -Wait -NoNewWindow
            }
            elseif ([string]::IsNullOrWhiteSpace($Software.Arguments)) {
                # If Arguments is empty, run without -ArgumentList
                Start-Process -FilePath $InstallerPath -Wait -NoNewWindow
            } else {
                # If Arguments exist, include -ArgumentList
                Start-Process -FilePath $InstallerPath -ArgumentList $Software.Arguments -Wait -NoNewWindow
            }
            Write-Output "$($Software.Name) completed."
        } catch {
            Write-Output "Failed to execute $($Software.Name): $_"
        }
    } else {
        Write-Output "Installer not found for $($Software.Name) at $InstallerPath."
    }
}

Write-Output "Installation process completed."

# **Step 3: Cleanup
Write-Output "Starting Cleanup Processes..."

##	Delete SoftwareInstall Files
Remove-Item -Path $LocalTempFolder -Recurse -Force -ErrorAction SilentlyContinue
Write-Output "Temporary Installation Files Removed."

## Delete all local user accounts except Administrator & Guest
Write-Host "Deleting all local user accounts except 'Administrator', 'UPA_Local', and 'Guest'..." -ForegroundColor Yellow
$ExcludedUsers = @("Administrator","UPA_Local","Guest","DefaultAccount","WDAGUtilityAccount")

$Users = Get-WmiObject Win32_UserAccount | Where-Object { $_.LocalAccount -eq $true -and $_.Name -notin $ExcludedUsers }
foreach ($User in $Users) {
    Write-Host "Deleting user: $($User.Name)" -ForegroundColor Cyan
    try {
        Remove-LocalUser -Name $User.Name -ErrorAction Stop
        Write-Host "User $($User.Name) deleted successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to delete user $($User.Name): $_" -ForegroundColor Red
    }
}

## Run System File Checker (SFC) to scan and repair system files
Write-Host "Running System File Checker (sfc /scannow)..." -ForegroundColor Yellow
Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -Wait -NoNewWindow

## Run DISM to Repair Windows Image
Write-Host "Checking and repairing Windows image with DISM..." -ForegroundColor Yellow
Start-Process -FilePath "dism.exe" -ArgumentList "/Online /Cleanup-Image /RestoreHealth" -Wait -NoNewWindow

## Run CHKDSK (Without Reboot) to Check for Disk Errors
Write-Host "Checking for disk errors on C: (CHKDSK /scan)..." -ForegroundColor Yellow
Start-Process -FilePath "chkdsk.exe" -ArgumentList "C: /scan" -Wait -NoNewWindow

## Force Group Policy Update
Write-Host "Updating Group Policies..." -ForegroundColor Yellow
Start-Process -FilePath "gpupdate.exe" -ArgumentList "/force" -Wait -NoNewWindow

## Check and Install Pending Windows Updates
Write-Host "Checking for Windows updates..." -ForegroundColor Yellow

Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$False

If(-not(Get-InstalledModule PSWindowsUpdate -ErrorAction SilentlyContinue)){
	Install-Module PSWindowsUpdate -Confirm:$False -Force
}
Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot

## Schedule CHKDSK on C: for next reboot (full repair)
Write-Host "Scheduling CHKDSK for C: on next reboot..." -ForegroundColor Yellow
Start-Process -FilePath "fsutil.exe" -ArgumentList "dirty set C:" -Wait -NoNewWindow

# **Step 4: Uninstall HPWolf Security (This FORCES a restart after finishing)**
Write-Output "Starting uninstallation of specified programs..."
foreach ($Program in $HPWolfList) {
    Uninstall-Program -ProgramName $Program
}
Write-Output "Uninstallation process completed."

Stop-Transcript

if ((Read-Host "Do you want to restart now? (Y/N)") -match "^(Y|y)$") { Restart-Computer -Force }
