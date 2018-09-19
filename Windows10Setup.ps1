<#
.SYNOPSIS
Configures popular settings on a workstation for first time use

.DESCRIPTION
This script can be used to remove built in windows 10 apps,Export a Custome Start Menu config file,Import a default start menu config file,
Disable OneDrive, Disbale Cortana, Disable Hibernate, Join a workstation to a domain, Rename the workstation, Set the page file size, Disable Windows Tips,
Disable the Consumer experience and Disable the Xbox Services.

.PARAMETER RemoveApps
Use this switch enable app removal

.PARAMETER AppsToRemove
Specifyes the list of apps to be removed, if not used then will use a list of apps built into the script

.PARAMETER Preset
The preset parameter will run the script with specific settings
CleanOS - Disables Ads, Widnows Store, Consumer Experience, Windows Tip, Cortana, Xbox Services, and OneDrive. Sets the page file removes all most all apps
EveryDayUser - Disables Ads, Removes all most all apps and Sets the page file size

.PARAMETER StartMenuLayout
Specifyes the xml file for the start menu layout, Only new users on the device will get the layout
Accounts that already exist will not see a change. This is due to the fact that the layout is applied
to the default user profile.

.PARAMETER ExportStartMenuLayout
Exports the curent start menu layout to be used on other workstations

.PARAMETER DisableAds
Disables all ads and sujested apps from the start menu, explorer, and lock screen

.PARAMETER DisableOneDrive
Disables OneDrive on the workstation

.PARAMETER DisableCortana
Disables Cortana on the workstation

.PARAMETER DisableHibernate
Disables the hibernate power setting

.PARAMETER SetPowerConfig
Sets the disk to never sleep and the device will not go to sleep

.PARAMETER DisableWindowsStore
Disables access to the Windows Store, The app is still listed

.PARAMETER DisableConsumerExperience
Disables The installation of extra apps and the pinning of links to Windows Store pages of third-party applications

.PARAMETER JoinDomain
Joins the computer to a domain

.PARAMETER Account
Account used to join to a domain, if not specified you will be asked for the account

.PARAMETER Domain
Domain to join when the JoinDomain Parameter is used, if not specified you will be asked for the domain

.PARAMETER RenameComputer
Renames the workstation to what is specified for the parameter

.PARAMETER SetPageFile
Sets the page file size to the recomended size based on the ammount of memmory installed on the device

.PARAMETER PageFileDrive
Moves the page file to a new drive, if not specified will default to the C drive

.PARAMETER LogFile
Specifies the location of the logfile byt default it is set to C:\Win10Setup.log
the log file is in a foramt for csmtrace https://docs.microsoft.com/en-us/sccm/core/support/cmtrace

.PARAMETER DisableConnectToInternetUpdates
Unless specified with GPO or this reg key Windows 10 will look to other update locations to pull
critial updates that have not bet installed on the device
https://social.technet.microsoft.com/Forums/en-US/46f992d3-e4eb-466f-8993-b791193dae2d/forcing-windows-10-clients-to-pull-updates-from-wsus-only?forum=win10itprosetup

.PARAMETER Reboot
Reboots the computer after all other taskes have been performed

.PARAMETER SetTimeZone
Sets the Time Zone of the computer

.EXAMPLE
.\Win10Setup.ps1 -RemoveApps -AppsToRemove AppsList.txt
Removes all apps in the AppsList.txt file

.EXAMPLE
.\Win10Setup.ps1 -StartMenuLayout StartMenuLayout.xml
Imports the xml file to use as the default start menu layout for all new users
To build your xml run Export-StartLayout -Path "C:\example\StartMenuLayout.xml"

.EXAMPLE
.\Win10Setup.ps1 -StartMenuLayout StartMenuLayout.xml -RemoveApps -AppsToRemove AppsToRemove.txt -DisableOneDrive -DisableCortana
Imports the start menu config removes apps listed in the txt file disbales one drive and cortana.

.NOTES
Created By: Kris Gross
Contact: Contact@mosaicmk.com
Facebook: MosaicMK Software
Version 2.5.0.1

.LINK
http://www.mosacimk.com

#>

Param(
        [Switch]$RemoveApps,
        [string]$AppsToRemove,
        [string]$StartMenuLayout,
        [Switch]$SetPageFile,
        [string]$PageFileDrive,
        [Switch]$EnableRDP,
        [Switch]$DisableOneDrive,
        [Switch]$DisableCortana,
        [Switch]$DisableWindowsTips,
        [Switch]$DisableConsumerExperience,
        [Switch]$DisableHibernate,
        [Switch]$SetPowerConfig,
        [Switch]$DisableXboxServices,
        [Switch]$DisableAds,
        [Switch]$DisableWindowsStore,
        [Switch]$DisableConnectToInternetUpdates,
        [switch]$DisableUAC,
        [string]$SetTimeZone,
        [Switch]$JoinDomain,
        [string]$Account,
        [string]$Domain,
        [string]$RenameComputer,
        [ValidateSet('CleanOS','EveryDayUser','DomainComputerSetup')]
        [string]$Preset,
        [Switch]$ExportStartMenuLayout,
        [Switch]$Reboot,
        [string]$LogFile = "C:\Win10Setup.log"
    )

$ScriptName = $MyInvocation.MyCommand.Name

function Read-Error{
    PARAM(
        [string]$ErrorText
    )
    Add-LogEntry -LogMessage $ErrorText -Messagetype 3
    Exit-Script
    exit 1
}

function New-LogFile(){
    $LogFilePaths =  "$LogFile"
    Foreach ($LogFilePath in $LogFilePaths){
        $script:NewLogError = $null
        $script:ConfigMgrLogFile = $LogFilePath
        Add-LogEntry "********************************************************************************************************************" "1"
        Add-LogEntry "Log file successfully intialized for $ScriptName." 1
        If (-Not($script:NewLogError)) { break }
    }
    If ($script:NewLogError){
        $script:Returncode = 1
        Exit $script:Returncode
    }
}
function Add-LogEntry{
    PARAM(
        $LogMessage,
        $Messagetype = 1
    )
    # Date and time is set to the CMTrace standard
    # The Number after the log message in each function corisponts to the message type
    # 1 is info
    # 2 is a warning
    # 3 is a error
    If ($Messagetype -eq 1){Write-Host "$LogMessage"}
    If ($Messagetype -eq 2){Write-Warning "$LogMessage"}
    If ($Messagetype -eq 3){Write-Error "$LogMessage"}
    Add-Content $script:ConfigMgrLogFile "<![LOG[$LogMessage]LOG]!><time=`"$((Get-Date -format HH:mm:ss)+".000+300")`" date=`"$(Get-Date -format MM-dd-yyyy)`" component=`"$ScriptName`" context=`"`" type=`"$Messagetype`" thread=`"`" file=`"powershell.exe`">"  -Errorvariable script:NewLogError
}

function Exit-Script(){
    Add-LogEntry "Closing the log file for $ScriptName."
    Add-LogEntry "********************************************************************************************************************"
}

Function Export-StartMenuLayout{
    $ExportFile = Read-Host "Export Config Name (Must be a XML file)"
    Export-StartLayout -Path "$PSScriptRoot\$ExportFile"
    Write-Host "Config Saved To: $PSScriptRoot\$ExportFile"
    exit 0
}

Function Import-StartMenuLayout{
    Param
    (
        [ValidateSet('Blank','Admin','EveryDayUser')]
        $PreSetLayout
    )
$BlankLayout = @"
<LayoutModificationTemplate Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
    <LayoutOptions StartTileGroupCellWidth="6" />
    <DefaultLayoutOverride>
    <StartLayoutCollection>
        <defaultlayout:StartLayout GroupCellWidth="6" xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout">
        <start:Group Name="" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout">
            <start:DesktopApplicationTile Size="2x2" Column="0" Row="0" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk" />
        </start:Group>
        </defaultlayout:StartLayout>
    </StartLayoutCollection>
    </DefaultLayoutOverride>
</LayoutModificationTemplate>
"@

$EveryDayUser = @"
<LayoutModificationTemplate Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
<LayoutOptions StartTileGroupCellWidth="6" />
<DefaultLayoutOverride>
  <StartLayoutCollection>
    <defaultlayout:StartLayout GroupCellWidth="6" xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout">
      <start:Group Name="" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout">
        <start:Tile Size="2x2" Column="4" Row="2" AppUserModelID="Microsoft.WindowsCalculator_8wekyb3d8bbwe!App" />
        <start:DesktopApplicationTile Size="2x2" Column="2" Row="0" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\computer.lnk" />
        <start:DesktopApplicationTile Size="2x2" Column="4" Row="0" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk" />
        <start:Tile Size="2x2" Column="0" Row="0" AppUserModelID="Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge" />
        <start:Tile Size="2x2" Column="0" Row="2" AppUserModelID="Microsoft.ZuneVideo_8wekyb3d8bbwe!Microsoft.ZuneVideo" />
        <start:Tile Size="2x2" Column="2" Row="2" AppUserModelID="Microsoft.Windows.Photos_8wekyb3d8bbwe!App" />
        <start:Tile Size="2x2" Column="0" Row="4" AppUserModelID="Microsoft.WindowsStore_8wekyb3d8bbwe!App" />
        <start:Tile Size="2x2" Column="2" Row="4" AppUserModelID="windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" />
        <start:Tile Size="2x2" Column="4" Row="4" AppUserModelID="Microsoft.BingWeather_8wekyb3d8bbwe!App" />
      </start:Group>
    </defaultlayout:StartLayout>
  </StartLayoutCollection>
</DefaultLayoutOverride>
</LayoutModificationTemplate>
"@

    #Configures the start menu layout
    #Copyies a IE Shortcut to the all users start menu so all users will have it on the start menu
    #Copy-Item -Path "Internet Explorer.lnk" -Destination "C:\ProgramData\Microsoft\Windows\Start Menu\Programs"
    IF (!($StartMenuLayout) -and ($PreSetLayout -EQ "Blank")){
        add-content $Env:TEMP\BlankLayout.xml $BlankLayout
        $StartMenuLayout = "$Env:TEMP\BlankLayout.xml"
    }
    IF (!($StartMenuLayout) -and ($PreSetLayout -EQ "EveryDayUser")){
        add-content $Env:TEMP\EveryDayUser.xml $EveryDayUser
        $StartMenuLayout = "$Env:TEMP\EveryDayUser.xml"
    }
    Add-LogEntry -LogMessage "Importing startmenu layout: $StartMenuLayout"
    try {
        Import-StartLayout -LayoutPath $StartMenuLayout -MountPath C:\ -ErrorAction Stop
        Add-LogEntry "SUCCESS: Start menu layout was succefully imported"
    }catch {
        Add-LogEntry -LogMessage "ERROR: Unable to import start menu layout: $_" -Messagetype 3
    }
}

Function Disable-OneDrive{
    Add-LogEntry -LogMessage "Disabling OneDrive"
    $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
    $Name = "DisableFileSyncNGSC"
    $Value = "1"
    $Type = "DWORD"

    Set-Location HKLM:
    if (!(test-Path .\SOFTWARE\Policies\Microsoft\Windows\OneDrive)) {New-Item .\SOFTWARE\Policies\Microsoft\Windows\OneDrive}
    try {
        New-ItemProperty -Path $RegPath -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop
        Add-LogEntry -LogMessage "SUCCESS:OneDrive scusessfuly disabled"
    } catch {
        Add-LogEntry "ERROR: Unale to disble OneDrive: $_" -Messagetype 3
    }
    Set-Location $PSScriptRoot
}

Function Disable-XboxServices{
    Add-LogEntry  -LogMessage "Disabling Xbox Services"
    try {
        Get-Service XblAuthManager -ErrorAction Stop | stop-service -passthru -ErrorAction Stop | set-service -startuptype disabled -ErrorAction Stop
        Add-LogEntry -LogMessage "SUCCESS: Disabled Xbox Services"
    }catch {
        Add-LogEntry -LogMessage "ERROR: Unable to Disable Xbox Services: $_" -Messagetype 3
    }
}

Function Disable-UAC{
    Add-LogEntry -LogMessage "Disabling UAC"
    Set-Location HKLM:
    if (!(test-Path .\Software\Microsoft\Windows\CurrentVersion\policies\system)) {New-Item .\Software\Microsoft\Windows\CurrentVersion\policies\system | Out-Null}
    try {
        New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000 -Force
        Add-LogEntry -LogMessage "SUCCESS: Disabled UAC"
    }
    catch {
        Add-LogEntry -LogMessage "ERROR: Unable to disable UAC: $_" -Messagetype 3
    }
    Set-Location $PSScriptRoot
}


Function Disable-Cortana{
    Add-LogEntry -LogMessage "Disabling Cortana"
    $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    $Name = "AllowCortana"
    $Value = "0"
    $Type = "DWORD"

    Set-Location HKLM:
    if (!(test-Path .\SOFTWARE\Policies\Microsoft\Windows\"Windows Search")) {New-Item .\SOFTWARE\Policies\Microsoft\Windows\"Windows Search"}
    try {
        New-ItemProperty -Path $RegPath -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop
        Add-LogEntry -LogMessage "SUCCESS: disabled Cortana"
    }
    catch {
        Add-LogEntry -LogMessage "ERROR: Unable to disable Cortana: $_" -Messagetype 3
    }
    Set-Location $PSScriptRoot
}

Function Disable-WindowsTips{
    Add-LogEntry -LogMessage 'Disabling Windows Tip'
    $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $Name = "DisableSoftLanding"
    $Value = "1"
    $Type = "DWORD"

    Set-Location HKLM:
    if (!(test-Path .\SOFTWARE\Policies\Microsoft\Windows\CloudContent)) {New-Item .\SOFTWARE\Policies\Microsoft\Windows\CloudContent}
    try {
        New-ItemProperty -Path $RegPath -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop
        Add-LogEntry -LogMessage "SUCCESS: disabled Windows Tips"
    }
    catch {
        Add-LogEntry -LogMessage "ERROR: Unsable to disable Windows Tips: $_" -Messagetype 3
    }
    Set-Location $PSScriptRoot
}

Function Disable-ConsumerExperience{
    Add-LogEntry -LogMessage 'Disabling Consumer Experience'
    $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $Name = "DisableWindowsConsumerFeatures"
    $Value = "1"
    $Type = "DWORD"

    Set-Location HKLM:
    if (!(test-Path .\SOFTWARE\Policies\Microsoft\Windows\CloudContent)) {New-Item .\SOFTWARE\Policies\Microsoft\Windows\CloudContent}
    try {
        New-ItemProperty -Path $RegPath -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop
        Add-LogEntry -LogMessage "SUCCESS: disabled Consumer Experience"
    }catch {
        Add-LogEntry -LogMessage "ERROR: Unable to disabled Consumer Experience: $_" -Messagetype 3
    }
    Set-Location $PSScriptRoot
}

Function Disable-Hibernate{
    Add-LogEntry -LogMessage "Disabling Hibernate"
    powercfg.exe /hibernate off
    If (!(test-Path -path $Env:SystemDrive\Hiberfil.sys)){
        Add-LogEntry -LogMessage "SUCCESS: Hibernate Disabled"
    }
    IF (Test-Path -Path $Env:SystemDrive\Hiberfil.sys){
        Add-LogEntry -LogMessage "ERROR: Hibernate was not disabled" -Messagetype 3
    }
}

Function Disable-Ads{
    $reglocation = "HKCU"
    #Start menu ads
    Add-LogEntry 'Disabling Start Menu Ads for Current User'
    Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SystemPaneSuggestionsEnabled" /D 0 /F
    #Lock Screen suggestions
    Add-LogEntry 'Disabling Lock Screen Suggentions for Current User'
    Reg Add "$reglocation\SOFTWARE\Microsoft\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SoftLandingEnabled" /D 0 /F
    Add-LogEntry "Disabling explorer ads for current user"
    Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /T REG_DWORD /V "ShowSyncProviderNotifications" /D 0 /F

    $reglocation = "HKLM\AllProfile"
    reg load "$reglocation" c:\users\default\ntuser.dat
    IF ($LASTEXITCODE -ne 0) {Add-LogEntry "Could not mount default user profile reg hive" -Messagetype 3}
    IF ($LASTEXITCODE -eq 0){
        Add-LogEntry 'Disabling Start Menu Ads for default user'
        Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SystemPaneSuggestionsEnabled" /D 0 /F
        IF ($LASTEXITCODE -ne 0) {Add-LogEntry "ERROR: Could not disable Start Menu Ads for default user" -Messagetype 3} Else {Add-LogEntry -LogMessage "SUCCESS: Disabled Start Menu Ads for default user"}

        Add-LogEntry 'Disabling Lock Screen Suggentions for Current User'
        Reg Add "$reglocation\SOFTWARE\Microsoft\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SoftLandingEnabled" /D 0 /F
        IF ($LASTEXITCODE -ne 0) {Add-LogEntry "ERROR: Could not disable Lock Screen Suggentions for Current User" -Messagetype 3}Else {Add-LogEntry -LogMessage "SUCCESS: Disabled Lock Screen Suggentions for Current User"}

        Add-LogEntry "Disabling explorer ads for default user"
        Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /T REG_DWORD /V "ShowSyncProviderNotifications" /D 0 /F
        IF ($LASTEXITCODE -ne 0) {Add-LogEntry "ERROR: Could not disable explorer ads for default user" -Messagetype 3}Else {Add-LogEntry -LogMessage "SUCCESS: Disabled explorer ads for default user"}
        #unload default user hive
        [gc]::collect()
        reg unload "$reglocation"
        IF ($LASTEXITCODE -ne 0) {Add-LogEntry "ERROR: Could not dismount default user reg hive" -Messagetype 3}
    }
}

Function Disable-WindowsStore{
    Add-LogEntry -LogMessage 'Disabling Windows Store'
    $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $Name = "DisableSoftLanding"
    $Value = "1"
    $Type = "DWORD"

    Set-Location HKLM:
    if (!(test-Path .\SOFTWARE\Policies\Microsoft\Windows\CloudContent)) {New-Item .\SOFTWARE\Policies\Microsoft\Windows\CloudContent}
    try {
        New-ItemProperty -Path $RegPath -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop
        Add-LogEntry -LogMessage "SUCCESS: Windows Store was disabled"
    } catch {
        Add-LogEntry -LogMessage "ERROR: Windows Store was not disabled: $_" -Messagetype 3
    }
    Set-Location $PSScriptRoot
}

Function Remove-Apps
{
    If ($AppsToRemove){
        If (!(Test-Path $AppsToRemove)){Read-Error -ErrorText "ERROR: Could not find $AppsToRemove"}
        $AppsList = Get-Content $AppsToRemove
    }

    If (!($AppsToRemove)){$AppsList = Get-AppxProvisionedPackage -online | where-object {$_.displayname -notlike "*Store*" -and $_.displayname -notlike "*Calculator*" -and $_.displayname -notlike "*Windows.Photos*" -and $_.displayname -notlike "*SoundRecorder*"  -and $_.displayname -notlike "*MSPaint*" -and $_.displayname -notlike "*ZuneVideo*" -and $_.displayname -notlike "*BingWeather*" -and $_.displayname -notlike "*sticky*" }}
        #Removes some windows apps
    Foreach ($item in $AppsList){
        $Name = $item.Displayname | Out-String
        Add-LogEntry -LogMessage "Attemptng to remove $Name Provisioned Package"
        try {
            Remove-AppxProvisionedPackage -Online -PackageName $item.PackageName -ErrorAction Stop
            Add-LogEntry -LogMessage "SUCCESS: $name Provisioned Package was succefully removed"
        } catch {
            Add-LogEntry -LogMessage "Could not remove $name Provisioned Package, will retry: $_" -Messagetype 2
            try {
                Remove-AppxProvisionedPackage -Online -PackageName $item.PackageName -ErrorAction Stop
                Add-LogEntry "SUCCESS: Retry for removal of $name Provisioned Pakcage was succefull"
            } catch {
                Add-LogEntry -LogMessage "ERROR: Could not remove $Name Provisioned Package: $_" -Messagetype 3
            }
        }

        Add-LogEntry -LogMessage "Attemptng to remove $Name Package"
        try {
            Get-AppxPackage -AllUsers -Name $Item.DisplayName | Remove-AppxPackage -ErrorAction Stop
            Add-LogEntry -LogMessage "SUCCESS: $Name package was succefully removed"
        } catch {
            Add-LogEntry -LogMessage "$Name package was not removed, will retry: $_" -Messagetype 2
            try {
                Get-AppxPackage -AllUsers -Name $Item.DisplayName | Remove-AppxPackage -ErrorAction Stop
                Add-LogEntry -LogMessage "SUCCESS: $Name package was succefully removed"
            } catch {
                Add-LogEntry -LogMessage "ERROR: $Name package was not removed: $_" -Messagetype 3
            }
        }
    }
}

Function Set-PageFile{
    #Gets total memory
    $Getmemorymeasure = Get-WMIObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
    #Converts the memory into GB
    $TotalMemSize = $($Getmemorymeasure.sum/1024/1024/1024)

    if (!($PageFileDrive)){$Drive = "C:"}else{IF ($PageFileDrive -like "*:"){$Drive = $PageFileDrive}else{$Drive = $PageFileDrive + ":"}}
    #recomended Page file size is double the memory installed
    Add-LogEntry -LogMessage "Setting Page file size on: $Drive"
    Add-LogEntry -LogMessage "Total Memory Installed (gb): $TotalMemSize"
    try {
            #2gb
            If (($TotalMemSize -gt "1") -and ($TotalMemSize -le "2.1")){Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 4096 4096" -ErrorAction Stop}
            #4gb
            If (($TotalMemSize -gt "2") -and ($TotalMemSize -le "4.1")){Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 8194 8194" -ErrorAction Stop}
            #6gb
            If (($TotalMemSize -gt "4") -and ($TotalMemSize -le "6.1")){Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 12288 12288" -ErrorAction Stop}
            #8gb
            If (($TotalMemSize -gt "6") -and ($TotalMemSize -le "8.1")){Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 16384 16384" -ErrorAction Stop}
            #12
            If (($TotalMemSize -gt "8") -and ($TotalMemSize -le "12.1")){Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 24576 24576" -ErrorAction Stop}
            #16
            If (($TotalMemSize -gt "12") -and ($TotalMemSize -le "16.1")){Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 32768 32768" -ErrorAction Stop}
            #24
            If (($TotalMemSize -gt "16") -and ($TotalMemSize -le "24.1")){Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 49152 49152" -ErrorAction Stop}
            #32
            If (($TotalMemSize -gt "24") -and ($TotalMemSize -le "32.1")){Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 65536 65536" -ErrorAction Stop}
            #64
            If (($TotalMemSize -gt "32") -and ($TotalMemSize -le "64.1")){Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 131072 131072" -ErrorAction Stop}
            Add-LogEntry -LogMessage "SUCCESS: Set page file size"
        }catch {Add-LogEntry -LogMessage "ERROR: Could not set page file: $_" -Messagetype 3}
}

function Enable-RDP{
    Add-LogEntry -LogMessage "Enabling RDP"
    try {
        Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled "False" -ErrorAction Stop
        If (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections"){Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value "0"}Else{New-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value "0"}
        Add-LogEntry -LogMessage "SUCCESS: Enabled RDP"
    }catch {Add-LogEntry "ERROR: Could not enable RDP: $_" -Messagetype 3}
}

function Join-Domain{
    IF (!($Domain)) {$domain = Read-Host "Domain"}
    IF (!($Account)) {$account = Read-Host "Account"}
    $password = Read-Host "Password for $Account" -AsSecureString
    Write-host "Joining $Domain as $Account"
    $username = "$domain\$account"
    $credential = New-Object System.Management.Automation.PSCredential($username,$password)
    Add-Computer -DomainName $domain -Credential $credential
    $password = $null
    $credential = $null
}

Function Set-Time{
    Add-LogEntry -LogMessage "Setting Time Zone"
    try {
        Set-TimeZone -Name "$SetTimeZone" -ErrorAction Stop
        Add-LogEntry -LogMessage "SUCCESS: set Time Zone"
    } catch {Add-LogEntry -LogMessage "ERROR: Could not set Time Zone" -Messagetype 3}
}

Function Set-PowerConfig{
    Add-LogEntry -LogMessage "Setting power config"
    powercfg.exe -X disk-timeout-ac 0
    IF ($LASTEXITCODE -ne 0){Add-LogEntry -LogMessage "ERROR: Unable to set Disk Time out on AC power" -Messagetype 3} Else {Add-LogEntry -LogMessage "SUCCESS: set disk time out on AC power"}
    powercfg.exe -X disk-timeout-dc 0
    IF ($LASTEXITCODE -ne 0){Add-LogEntry -LogMessage "ERROR: Unable to set Disk Time out on DC power" -Messagetype 3} Else {Add-LogEntry -LogMessage "SUCCESS: set disk time out on DC power"}
    powercfg.exe -x -standby-timeout-ac 0
    IF ($LASTEXITCODE -ne 0){Add-LogEntry -LogMessage "ERROR: Unable to set Standby on AC power" -Messagetype 3} Else {Add-LogEntry -LogMessage "SUCCESS: set Standby on AC power"}
    powercfg.exe -x -standby-timeout-dc 0
    IF ($LASTEXITCODE -ne 0){Add-LogEntry -LogMessage "ERROR: Unable to set Standby on DC power" -Messagetype 3} Else {Add-LogEntry -LogMessage "SUCCESS: set Standby on DC power"}
}

Function Disable-ConnectToInternetUpdates{
    Add-LogEntry -LogMessage 'Disabling Consumer Experience'
    $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $Name = "DoNotConnectToWindowsUpdateInternetLocations"
    $Value = "1"
    $Type = "DWORD"

    Set-Location HKLM:
    if (!(test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null}
    try {
        New-ItemProperty -Path $RegPath -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop
        Add-LogEntry -LogMessage 'SUCCESS: Connect to Internet for Updates was disabled'
    } catch {Add-LogEntry -LogMessage "ERROR: Connect to Internet for Updates was not disabled: $_" -Messagetype 3}
    Set-Location $PSScriptRoot
}

#Checks to see what switches are being used
If (($StartMenuLayout) -and ($ExportStartMenuLayout)){Read-Error -ErrorText "You can not use ExportStartMenuLayout parameter and StartMenuLayout parameter at the sametime"}

#Exports the current start menu config
If ($ExportStartMenuLayout){Export-StartMenuLayout}

New-LogFile

If ($Preset -EQ "CleanOS"){
    IF (!($StartMenuLayout)) {Import-StartMenuLayout -PreSetLayout Blank}
    Set-PageFile
    Disable-Ads
    Disable-WindowsStore
    Disable-ConsumerExperience
    Disable-WindowsTips
    Disable-Cortana
    Disable-XboxServices
    Disable-OneDrive
    Remove-Apps
}

IF ($Preset -EQ "EveryDayUser"){
    IF (!($StartMenuLayout)) {Import-StartMenuLayout -PreSetLayout EveryDayUser}
    Disable-Ads
    Remove-Apps
    Set-PageFile
}

IF ($Preset -EQ "DomainComputerSetup"){
    Join-Domain
    Set-PageFile
    Disable-Ads
    Disable-ConsumerExperience
    Disable-WindowsTips
    Disable-XboxServices
    Remove-Apps
}

#If a config file is specifed will import it
IF ($StartMenuLayout) {Import-StartMenuLayout}

#Enable RDP
IF ($EnableRDP) {Enable-RDP}

#Sets the Tiemzone
IF ($SetTimeZone) {Set-Time}

#Disabled UAC
IF ($DisableUAC){Disable-UAC}

#Disbales Xbox Services and stops them
If ($DisableXboxServices) {Disable-XboxServices}

#Add regkeys to disable OneDrive
If ($DisableOneDrive) {Disable-OneDrive}

#adds regkey needed to disable Cortana
If ($DisableCortana) {Disable-Cortana}

#Disables the windows store, The app is still listed
If ($DisableWindowsStore) {Disable-WindowsStore}

#Disables add on the start menu and lock screen
If ($DisableAds) {Disable-Ads}

#Disables Hibernate
If ($DisableHibernate) {Disable-Hibernate}

#Disables Windows Tips
If ($DisableWindowsTips) {Disable-WindowsTips}

#Disables Consumer Experience
If ($DisableConsumerExperience) {Disable-ConsumerExperience}

#Disable Connect to Windows Update Internet Location
IF ($DisableConnectToInternetUpdates) {Disable-ConnectToInternetUpdates}

#If a list file is specifyed will run the uninstall process
IF ($RemoveApps) {Remove-Apps}

#renames the computer
If ($RenameComputer) {Rename-Computer -NewName $RenameComputer}

#Sets the page file
If ($SetPageFile) {Set-PageFile}

#Sets power config
IF ($SetPowerConfig) {Set-PowerConfig}

#Reboots the computer
If ($Reboot){Restart-Computer -ComputerName $env:COMPUTERNAME ; Exit-Script}else{
    Write-Host "You will need to reboot the computer before you see the change take affect"
    Exit-Script
}
