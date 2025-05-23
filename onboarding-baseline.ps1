# Define the network location and local temporary folder
## Edit to reflect source and destination of your software installation files.
## Comment out '$NetworkPath' if you intend to move files outside of this script.

$NetworkPath = "\\UPA\SHARE$\SoftwareInstall_Baseline"
$LocalTempFolder = "C:\temp\SoftwareInstall"

# Define the list of software to install
## Path MUST be location of installation file FROM 'LocalTempFolder' : i.e. "'C:\temp\SoftwareInstall' \ 'nextiva\Nextiva-win.exe'"

$SoftwareList = @(
    @{Name = "Chrome"; Path = "chrome\ChromeSetup.exe"; Arguments = "/silent /install"}
    @{Name = "Adobe Reader"; Path = "adobe-reader\adobe-reader.exe"; Arguments = "/sAll /silent /install"}
    @{Name = "VLC Media Player"; Path = "vlc\vlc.exe"; Arguments = "/L=1033 /S"}
    @{Name = "7zip Archiver"; Path = "7zip\7zip.exe"; Arguments = "/S"}
    @{Name = "Eclipse OpenJDK"; Path = "Eclipse\openjdk.msi"; Arguments = "ADDLOCAL=FeatureMain,FeatureEnvironment,FeatureJarFileRunWith,FeatureJavaHome INSTALLDIR='c:\Program Files\Temurin\' /qn"}
    @{Name = "MS Office"; Path = "ms-office-deployment\ms-office-install.bat"; Arguments = ""}
)

# Define Windows Optional Features that are to be installed, outside of WindowsUpdate

$FeatureList = @(
	"SNMP.Client~~~~0.0.1.0"
	"WINS.Client~~~~0.0.1.0"
)

# Define programs to uninstall (Program Display Names as seen in "Apps & Features")
## Script can handle AppxPackages and UWP App names and GUID if known; it SHOULD hunt everything down on its own, but the more detail for your specific package, the better.

$UninstallList = @(

### Windows Default Apps ###
	"Copilot"
	"Copilot 365"
	"Cortana"
	"Linkedin"
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
	"Windows 11 Installation Assistant"
	
### HP Bloatware ###
	"HP Connection Optimizer"
	"HP Documentation"
	"HP Jumpstart"
	"HP Notifications"
	"HP PC Hardware Diagnostics Windows"
	"HP Privacy Settings"
	"HP Smart"
	"HP Support Assistant"
	"HP Sure Recover"
	"HP Sure Run Module"
	"HP System Information"
	"HPSmartDeviceAgentBase"
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
	
### Other Software ###
	"Actian"
	"ASUS"
	"Allworx Interact"
	"BleachBit"
	"Bonjour"
	"Canon IJ Network"
	"Canon IJ Printer"
	"Canon IJ Scan"
	"Canon Inkjet"
	"Canon TS9500"
	"HP LaserJet E50145"
	"Java"
	"Microsoft ODBC"
	"Netgear"
	"Netsurion"
	"Notepad++"
	"NPCap"
	"Printer Registration"
	"Scribe"
	"Wireshark"
	
### UPA Obsolete Apps ###
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
	"TeamViewer"
	"TSPrint"
	"TSPrint Client"
	"TSScan"
	"Xerox Desktop Print Experience"
	"Xerox Print and Scan Experience"
	
## Fresh Start (uninstall to reinstall specific executable version)
	"7-Zip"
	"Adobe"
	"Chrome"
	"Cisco"
	"File Queue Uploader"
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
	"VLC"
)

# Required Separation due to HPWolf killing File Explorer and forcing restart. This list is completed AFTER the Installations.
$HPWolfList = @( 
	"HP Wolf Security"
	"HP Wolf Security - Console"
	"HP Security Update Service"
)

# Define any custom uninstall argument overrides here
$UseOriginalUninstallString = @(
	"Ecosystem agent"
    "File Cache Service Agent"
	"Kaseya"
	"OneDrive"
	"Patch Management Service Controller"
	"Request Handler Agent"
	"TSPrint"
	"TSPrint Client"
	"TSScan"
)

$UninstallCommandSuffixOverrides = @{
    "Chrome" = "--uninstall --system-level --force-uninstall"
	"Firefox" = "/S"
	"PDFPro" = "/VERSILENT"
	"Citrix Workspace" = "/silent uninstall"
}

########## DO NOT EDIT BELOW THIS LINE ##########

function Install-WindowsFeatures {
	param (
		[Parameter()]
		[string[]]$FeatureList = @()
	)

    foreach ($feature in $FeatureList) {
        $installed = Get-WindowsCapability -Online | Where-Object { $_.Name -eq $feature -and $_.State -eq "Installed" }
        if ($installed) {
            Write-Host "$($feature.Split('~')[0]) is already installed."
        } else {
            try {
                Write-Host "Installing $($feature.Split('~')[0])..."
                Add-WindowsCapability -Online -Name $feature -ErrorAction Stop
                Write-Host "Successfully installed $($feature.Split('~')[0])."
            } catch {
                Write-Warning "Failed to install $($feature.Split('~')[0]): $_"
            }
        }
    }
}


function Get-UninstallRegistryEntries {
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $allEntries = foreach ($path in $registryPaths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, UninstallString, QuietUninstallString, PSChildName
    }

    return $allEntries
}

function Uninstall-Program {
    param (
        [Parameter(Mandatory)]
        [string[]]$UninstallList,

        [Parameter()]
        [array]$RegistryEntries = $(Get-UninstallRegistryEntries),

        [Parameter()]
		[string[]]$UseOriginalUninstallString = @(),
		
		[Parameter()]
		[string[]]$HPWolfList = @(),
		
		[Parameter()]
		[hashtable]$UninstallCommandSuffixOverrides = @{}
    )

    $standardArgs = @{
        "msi"      = "/qn /norestart"
        "exe"      = "/quiet /S /qn /norestart /allusers"
        "fallback" = "/quiet /norestart"
    }

    foreach ($programName in $UninstallList) {
        Write-Host "`nSearching for: $programName"

        $matches = $RegistryEntries | Where-Object { $_.DisplayName -like "*$programName*" }

        if (-not $matches) {
            Write-Host "No registry uninstall entries found for: $programName"
        }

        foreach ($match in $matches) {
            $displayName  = $match.DisplayName
			# DEBUG: Check what we're trying to match against
			Write-Host "Checking for override match on display name: '$displayName'"
			Write-Host "UseOriginalUninstallString list: $($UseOriginalUninstallString -join ', ')"

            $uninstallCmd = $match.QuietUninstallString
            if (-not $uninstallCmd) {
                $uninstallCmd = $match.UninstallString
            }

            if (-not $uninstallCmd) {
                Write-Warning "No uninstall string found for $displayName. Skipping..."
                continue
            }

            Write-Host "Found: $displayName"
			
			# === Attempt to stop related processes ===
			try {
				$procMatches = Get-Process | Where-Object { $_.Name -like "*$($programName)*" }
				foreach ($proc in $procMatches) {
					Write-Host "Stopping process: $($proc.Name)"
					Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
				}
			} catch {
				Write-Warning "Failed to stop process for $displayName : $_"
			}

			# === Attempt to stop related services ===
			try {
				$svcMatches = Get-Service | Where-Object {
					$_.Name -like "*$($programName)*" -or $_.DisplayName -like "*$($programName)*"
				}

				foreach ($svc in $svcMatches) {
					if ($svc.Status -eq 'Running') {
						Write-Host "Stopping service: $($svc.Name)"
						Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
					}
				}
			} catch {
				Write-Warning "Failed to stop services related to $displayName : $_"
			}

            Write-Host "Original Uninstall Command: $uninstallCmd"

            # Check if we should use the original uninstall string
            $useOriginal = $false
			foreach ($term in $UseOriginalUninstallString) {
				$termLower = $term.ToLower()
				$nameLower = $displayName.ToLower()
				Write-Host "Comparing '$nameLower' -like '*$termLower*'"
				if ($nameLower -like "*$termLower*") {
					Write-Host "Matched override pattern: '$term'"
					$useOriginal = $true
					break
				}
			}


            if ($useOriginal -eq $true) {
                Write-Host "Using original uninstall command for: $displayName"
                Write-Host "Running: $uninstallCmd"
				
				# Append known suffix arguments if necessary
				foreach ($suffixKey in $UninstallCommandSuffixOverrides.Keys) {
					if ($displayName.ToLower() -like "*$($suffixKey.ToLower())*") {
						$suffix = $UninstallCommandSuffixOverrides[$suffixKey]
						Write-Host "Appending extra uninstall flags: $suffix"
						$uninstallCmd = "$uninstallCmd $suffix"
						break
					}
				}
				
                Write-Host "Final uninstallCmd: $uninstallCmd"
				
				try {
					Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$uninstallCmd`"" -Wait -NoNewWindow
                    Start-Sleep -Seconds 2
                } catch {
                    Write-Warning "Uninstall failed for $displayName using original string: $_"
                }
                continue
            }
			
            try {
                $exeCandidate = ($uninstallCmd -split '\s+')[0].Trim('"')
                $exeName = [System.IO.Path]::GetFileName($exeCandidate)

			if ($exeName -ieq "msiexec.exe") {
				$productCode = ""
				if ($uninstallCmd -match '{.*}') {
					$productCode = [regex]::Match($uninstallCmd, '{.*}').Value
				} else {
					$productCode = $match.PSChildName
				}

				if ($customArgs) {
					$argTail = $customArgs
				} else {
					$argTail = $standardArgs['msi']
				}

				# Combine full string to run as a cmd line
				$fullCommand = "msiexec.exe /x $productCode $argTail"

				Write-Host "Executing via cmd.exe: $fullCommand"
				Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$fullCommand`"" -Wait -NoNewWindow
				Start-Sleep -Seconds 2
				continue
			}
                
                elseif ($uninstallCmd -match '\.exe') {
                    $regexResult = [regex]::Match($uninstallCmd, '(^\"?.+?\.exe\")|(^\S+?\.exe)')
                    if ($regexResult.Success) {
                        $exePath = $regexResult.Value.Trim('"')

                        if ($exePath -notmatch '^".+"$') {
                            $exePath = "`"$exePath`""
                        }

                        if ($customArgs) {
							$argTail = $customArgs
						} else {
							$argTail = $standardArgs['exe']
						}
                        Write-Host "Start-Process -FilePath $exePath -ArgumentList '$argTail'"
                        Start-Process -FilePath $exePath -ArgumentList $argTail -Wait -NoNewWindow
                    } else {
                        Write-Warning "Could not extract executable path from: $uninstallCmd"
                        continue
                    }
                }
                else {
                    $argTail = $standardArgs['fallback']
                    $args = "/c $uninstallCmd $argTail"
                    Write-Host "Start-Process -FilePath cmd.exe -ArgumentList '$args'"
                    Start-Process "cmd.exe" -ArgumentList $args -Wait -NoNewWindow
                }
				
                Start-Sleep -Seconds 2
            } catch {
                Write-Warning "Uninstall failed for $displayName : $_"
            }

            # Kill browser popups
            Get-Process -Name "chrome", "msedge", "firefox" -ErrorAction SilentlyContinue | Stop-Process -Force

            $matchID = $match.PSChildName
            $stillInstalled = $RegistryEntries | Where-Object { $_.PSChildName -eq $matchID }

            if ($stillInstalled) {
                Write-Warning "$displayName still appears installed. Attempting registry removal..."
                $keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$matchID"
                Remove-Item -Path $keyPath -Force -ErrorAction SilentlyContinue
            } else {
                Write-Host "$displayName uninstalled successfully."
            }
        }

        # Handle Appx
        $appxMatches = Get-AppxPackage -Name "*$programName*" -ErrorAction SilentlyContinue
        foreach ($pkg in $appxMatches) {
            Write-Host "Removing Appx package: $($pkg.Name)"
            Remove-AppxPackage -Package $pkg.PackageFullName -ErrorAction SilentlyContinue
        }

        # Handle provisioned Appx
        $provPkg = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*$programName*" }
        foreach ($prov in $provPkg) {
            Write-Host "Removing provisioned Appx package: $($prov.DisplayName)"
            Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction SilentlyContinue
        }

        Write-Host "Uninstall checks completed for: $programName`n"
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

# Define domain search base and target OU
$domainBase = "DC=unitedpropertyassociates,DC=com"
$targetOU   = "OU=Unassigned,OU=UPA-Workstations,DC=unitedpropertyassociates,DC=com"
 
# Ensure AD module is available
Import-Module ActiveDirectory -ErrorAction Stop
 
# Get the computer object from anywhere in the domain
$computer = Get-ADComputer -Filter "Name -eq '$env:COMPUTERNAME'" -SearchBase $domainBase -Properties Description, serialNumber, DistinguishedName, managedBy, physicalDeliveryOfficeName
 
# Validate target OU
if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$targetOU'" -ErrorAction SilentlyContinue)) {
    Write-Error "Target OU '$targetOU' does not exist. Aborting move operation."
    return
}
 
# Validate the computer object
if ($null -eq $computer -or [string]::IsNullOrWhiteSpace($computer.DistinguishedName)) {
    Write-Error "Computer object '$env:COMPUTERNAME' not found in domain or missing DistinguishedName."
    return
}
 
# Prompt for optional updates to 'Description' and 'serialNumber'
$descriptionInput = Read-Host "Enter new description (ENTER to keep current: '$($computer.Description)')"
$serialInput      = Read-Host "Enter new serial number (ENTER to keep current: '$($computer.serialNumber)')"
 
# Build a hashtable for properties to update
$replaceProps = @{}
 
if ($descriptionInput) { $replaceProps["Description"] = $descriptionInput }
if ($serialInput)      { $replaceProps["serialNumber"] = $serialInput }
 
# Always clear managedBy and physicalDeliveryOfficeName
$clearProps = @("managedBy","physicalDeliveryOfficeName")
 
# Perform AD object update
try {
	if ($replaceProps.Count -gt 0) {
		Set-ADComputer -Identity $computer.DistinguishedName -Replace $replaceProps
	}
	
	if ($clearProps.Count -gt 0) {
		Set-ADComputer -Identity $computer.DistinguishedName -Clear $clearProps
	}
	
	Write-Host "Computer Object updated successfully."
}
catch {
	Write-Error "Failed to update Computer Object attributes: $_"
}
 
# Attempt to move the computer object to the correct OU
try {
    Move-ADObject -Identity $computer.DistinguishedName -TargetPath $targetOU -Confirm:$false
    Write-Host "Successfully moved '$($computer.Name)' to OU: $targetOU"
}
catch {
    Write-Error "Failed to move computer object: $_"
}
 
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
# Registry entries cache
$RegistryCache = Get-UninstallRegistryEntries

# Call the Uninstall-Program function
Uninstall-Program -UninstallList $UninstallList -RegistryEntries $RegistryCache -UseOriginalUninstallString $UseOriginalUninstallString -UninstallCommandSuffixOverrides $UninstallCommandSuffixOverrides

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

# **Step 3: Install Windows Features
Write-Output "Starting Windows Feature Installation..."
Install-WindowsFeatures -FeatureList $FeatureList
Write-Output "Windows Feature Installation Complete."

# **Step 4: Cleanup
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
Write-Host "Running System File Checker..."
$sfcResult = Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -Wait -NoNewWindow -PassThru
if ($sfcResult.ExitCode -ne 0) {
    Write-Host "SFC failed or found issues. Exit Code: $($sfcResult.ExitCode)"
}

## Run DISM to Repair Windows Image
Write-Host "Running DISM /ScanHealth..."
$scanHealth = Start-Process -FilePath "dism.exe" -ArgumentList "/online", "/cleanup-image", "/scanhealth" -Wait -NoNewWindow -PassThru
if ($scanHealth.ExitCode -ne 0) {
    Write-Host "DISM ScanHealth failed. Exit Code: $($scanHealth.ExitCode)"
}

Write-Host "Running DISM /RestoreHealth..."
$restoreHealth = Start-Process -FilePath "dism.exe" -ArgumentList "/online", "/cleanup-image", "/restorehealth" -Wait -NoNewWindow -PassThru
if ($restoreHealth.ExitCode -ne 0) {
    Write-Host "DISM RestoreHealth failed. Exit Code: $($restoreHealth.ExitCode)"
}

## Run CHKDSK (Without Reboot) to Check for Disk Errors
Write-Host "Checking for disk errors on C: (CHKDSK /scan)..." -ForegroundColor Yellow
Start-Process -FilePath "chkdsk.exe" -ArgumentList "C: /scan" -Wait -NoNewWindow

## Force Group Policy Update
Write-Host "Updating Group Policies..." -ForegroundColor Yellow
Start-Process -FilePath "gpupdate.exe" -ArgumentList "/force" -Wait -NoNewWindow

## Run Repair of Windows Update
Write-Host "Checking Windows Update components..."
try {
    Start-Process -FilePath "PowerShell" -ArgumentList "-NoProfile", "-Command Reset-WindowsUpdateComponents" -Wait -NoNewWindow
} catch {
    Write-Host "Windows Update repair failed: $_"
}

## Check and Install Pending Windows Updates
Write-Host "Checking for Windows updates..." -ForegroundColor Yellow

Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$False

If(-not(Get-InstalledModule PSWindowsUpdate -ErrorAction SilentlyContinue)){
	Install-Module PSWindowsUpdate -Confirm:$False -Force
}

## Schedule CHKDSK on C: for next reboot (full repair)
Write-Host "Scheduling CHKDSK for C: on next reboot..." -ForegroundColor Yellow
Start-Process -FilePath "fsutil.exe" -ArgumentList "dirty set C:" -Wait -NoNewWindow

# **Step 4: Uninstall HPWolf Security (This FORCES a restart after finishing)**
Write-Output "Starting uninstallation of HPWolf Security programs..."
foreach ($Program in $HPWolfList) {
    Uninstall-Program -ProgramName $Program
}
Write-Output "HPWolf Uninstallation process completed."

Stop-Transcript

if ((Read-Host "Do you want to restart now? (Y/N)") -match "^(Y|y)$") { Restart-Computer -Force }
