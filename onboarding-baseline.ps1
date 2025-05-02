
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
        [string]$ProgramName
    )

    Write-Output "Searching for $ProgramName to uninstall..."
    $Remaining = $true
    $MaxAttempts = 3
    $Attempts = 0

    while ($Remaining -and $Attempts -lt $MaxAttempts) {
        $Remaining = $false
        $Attempts++

        # 1️⃣ Uninstall via Registry (for EXE and MSI-based programs)
        $RegistryPaths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )

        foreach ($Path in $RegistryPaths) {
            $Apps = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*$ProgramName*" }

            if ($Apps) {
                $Remaining = $true

                foreach ($App in $Apps) {
                    Write-Output "Found $ProgramName in registry."

                    # 2️⃣ Stop Related Processes Only If Program Exists
                    Write-Output "Checking for running processes related to $ProgramName..."
                    $Processes = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like "*$ProgramName*" }
                    if ($Processes) {
                        Write-Output "Found running processes. Attempting to close them..."
                        foreach ($Process in $Processes) {
                            try {
                                Stop-Process -Id $Process.Id -Force -ErrorAction Stop
                                Write-Output "Successfully closed: $($Process.ProcessName) (PID: $($Process.Id))"
                            } catch {
                                Write-Output "Failed to close process $($Process.ProcessName). Trying taskkill..."
                                Start-Process -FilePath "taskkill.exe" -ArgumentList "/F /IM $($Process.ProcessName).exe" -NoNewWindow -Wait
                            }
                        }
                    }

                    # **3️⃣ Prefer QuietUninstallString if available, otherwise use UninstallString**
                    $UninstallString = $App.QuietUninstallString
                    if (-not $UninstallString) {
                        $UninstallString = $App.UninstallString
                    }

                    # Ensure UninstallString is a proper string
                    $UninstallString = [string]$UninstallString -replace '"', ''

                    # **4️⃣ Handle MSI-based uninstalls**
                    if ($UninstallString -match "\{[0-9A-Fa-f\-]{36}\}") {
                        Write-Output "Detected MSIExec uninstall command."

                        # Extract only the GUID
                        $GUID = $matches[0]
                        Write-Output "Extracted MSI GUID: $GUID"

                        # Construct a clean MSI uninstall command
                        $Arguments = "/X $GUID /quiet /norestart /qn /passive"

                        try {
                            Write-Output "Executing MSI uninstall: msiexec.exe $Arguments"
                            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments -NoNewWindow -Wait -PassThru
                            if ($process.ExitCode -eq 0) {
                                Write-Output "$ProgramName (MSI) uninstalled successfully."
                            } elseif ($process.ExitCode -eq 1605) {
                                Write-Output "$ProgramName (MSI) not installed (Exit Code 1605)."
                            } else {
                                Write-Output "Failed to uninstall $ProgramName (MSI). Exit Code: $($process.ExitCode)"
                            }
                        } catch {
                            Write-Output "Error uninstalling $ProgramName (MSI): $_"
                        }

                        continue  # Skip to the next program entry
                    }

                    # **5️⃣ Handle EXE-based uninstalls**
                    if ($UninstallString -match ".*\.exe") {
                        Write-Output "Running EXE Uninstaller: $UninstallString"

                        # Extract EXE path and existing arguments
                        if ($UninstallString -match '^"?(.*?\.exe)"?\s*(.*)$') {
                            $ExePath = $matches[1]   # Extracts the EXE file path
                            $ExeArguments = $matches[2] # Extracts everything after the EXE path (arguments)
                        } else {
                            $ExePath = $UninstallString
                            $ExeArguments = ""
                        }

                        # Ensure EXE path is properly quoted
                        if ($ExePath -notmatch '^".+"$') {
                            $ExePath = "`"$ExePath`""  # Wrap EXE path in quotes if missing
                        }

                        # If the UninstallString contains key-pair arguments (e.g., scenario=install), preserve them
                        if ($ExeArguments -match "=\w+") {
                            Write-Output "Detected key-pair arguments in UninstallString. Preserving original parameters."
                            $ExeArguments = "$ExeArguments DisplayLevel=False"  # Append only DisplayLevel=False
                        } else {
                            # If no structured key-pairs exist, append silent flags
                            $SilentFlags = "/S /quiet /norestart /silent /VERYSILENT"
                            if ($ExeArguments) {
                                $ExeArguments = "$ExeArguments $SilentFlags"
                            } else {
                                $ExeArguments = $SilentFlags
                            }
                        }

                        try {
                            Write-Output "Executing: cmd.exe /c $ExePath $ExeArguments"
                            $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $ExePath $ExeArguments" -NoNewWindow -Wait -PassThru
                            if ($process.ExitCode -eq 0) {
                                Write-Output "$ProgramName (EXE) uninstalled successfully."
                            } else {
                                Write-Output "Uninstall failed for $ProgramName (EXE). Exit Code: $($process.ExitCode)"
                            }
                        } catch {
                            Write-Output "Error uninstalling $ProgramName (EXE): $_"
                        }
                    }
                }
            }
        }

        # **6️⃣ Remove Windows Store Apps (UWP Apps)**
        $AppxPackages = Get-AppxPackage -AllUsers | Where-Object { $_.Name -ilike "*$ProgramName*" -or $_.PackageFamilyName -ilike "*$ProgramName*" }
        if ($AppxPackages) {
            $Remaining = $true
            foreach ($App in $AppxPackages) {
                Write-Output "Removing UWP App: $($App.PackageFullName)..."
                try {
                    Remove-AppxPackage -Package $App.PackageFullName -AllUsers -ErrorAction Stop
                    Write-Output "$ProgramName removed successfully."
                } catch {
                    Write-Output "Failed to remove $ProgramName. Error: $_"
                }
            }
        }

        # **7️⃣ Remove Provisioned Windows Store Apps (For Future Users)**
        $ProvisionedApps = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -ilike "*$ProgramName*" }
        if ($ProvisionedApps) {
            $Remaining = $true
            foreach ($ProvApp in $ProvisionedApps) {
                Write-Output "Removing provisioned package: $($ProvApp.PackageName)..."
                try {
                    Remove-AppxProvisionedPackage -Online -PackageName $ProvApp.PackageName -ErrorAction Stop
                    Write-Output "$ProgramName removed successfully for future users."
                } catch {
                    Write-Output "Failed to remove provisioned package: $_"
                }
            }
        }

        if (-not $Remaining) {
            Write-Output "$ProgramName fully removed."
        } else {
            Write-Output "$ProgramName still detected. Retrying ($Attempts/$MaxAttempts)..."
            Start-Sleep -Seconds 3
        }
    }

    if ($Remaining) {
        Write-Output "Could not completely remove $ProgramName after $MaxAttempts attempts."
    }
}



# Ensure the script is running with administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator!" -ForegroundColor Red
    exit 1
}

## Update Active Directory to Reflect Device Type and Unassigned Status

# Check if machine is domain-joined
if (-not (Test-ComputerSecureChannel)) {
    Write-Error "❌ This computer is not joined to a domain. Exiting script."
    exit 1
}

# Check if Active Directory module is available
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "🔍 Active Directory module not found. Installing RSAT: Active Directory..." -ForegroundColor Yellow
    try {
        Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ErrorAction Stop
        Write-Host "✅ RSAT Active Directory module installed successfully." -ForegroundColor Green
    } catch {
        Write-Error "❌ Failed to install RSAT Active Directory module. Error: $_"
        exit 1
    }
}

Import-Module ActiveDirectory

# Get local computer name
$ComputerName = $env:COMPUTERNAME

# Get the computer object from AD
$Computer = Get-ADComputer -Identity $ComputerName

# Prompt user for a description
$Description = Read-Host "Enter a new description for the computer object"

# Prompt user for a Serial Number
$Serial = Read-Host "Enter the device's serial number"

# Define the new OU Distinguished Name (modify this)
$NewOU = "OU=Unassigned,OU=UPA-Workstations,DC=unitedpropertyassociates.com,DC=com"

# Move the computer to the new OU
Move-ADObject -Identity $Computer.DistinguishedName -TargetPath $NewOU

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

if ((Read-Host "Do you want to restart now? (Y/N)") -match "^(Y|y)$") { Restart-Computer -Force }
