#strip defender by zoic
#this script will use dism and trusted installer to remove windows defender from an iso file

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) 
{	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	}

#remove file function using nsudo
function Remove-File([string]$path)
{

if(!(Test-Path -LiteralPath "$PSScriptRoot\NSudoLG.exe")){
	#downloading nsudo to delete files protected by trusted installer
Invoke-RestMethod 'https://github.com/M2TeamArchived/NSudo/releases/download/9.0-Preview1/NSudo_9.0_Preview1_9.0.2676.0.zip' -OutFile "C:\Nsudo.zip"
Expand-Archive "C:\Nsudo.zip" -DestinationPath "C:\Nsudo"
Remove-Item "C:\Nsudo.zip" -Recurse -Force
Move-Item -LiteralPath "C:\Nsudo\x64\NSudoLG.exe" -Destination $PSScriptRoot -Force
#cleanup
Remove-Item -LiteralPath "C:\Nsudo" -Recurse -Force -ErrorAction SilentlyContinue
}

if(Test-Path -LiteralPath "$PSScriptRoot\NSudoLG.exe"){


#delete file with trusted installer
$arguments = "-U:T -P:E -M:S Powershell.exe -windowstyle Hidden -command `"Remove-Item -Path '$path' -Recurse -Force`""

Start-Process "$PSScriptRoot\NSudoLG.exe" -ArgumentList $arguments -WindowStyle Hidden -Wait 

#ensure all files have been deleted
if(Test-Path -Path $path){

#if files still there delete all files and folders inside and then delete the folder (-recurse is a bit buggy sometimes)

$arguments = "-U:T -P:E -M:S Powershell.exe -windowstyle Hidden -command `"Get-ChildItem -Path '$path' -Force | Remove-Item -Recurse -Force | Remove-Item $path -Force`""

Start-Process "$PSScriptRoot\NSudoLG.exe" -ArgumentList $arguments -WindowStyle Hidden -Wait
Write-Host $($path).Split('\')[-1] "Removed!"
}
else{
Write-Host $($path).Split('\')[-1] "Removed!"
return 0
}

}
else{

Write-Host "NSudo not found!"
return 1
}






}


function Disable-Defender([String]$edition) {
$disableDefendContent = @"
Reg add "HKLM\OFFLINE_SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtectionSource" /t REG_DWORD /d "2" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Microsoft\Windows Defender\Signature Updates" /v "FirstAuGracePeriod" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Microsoft\Windows Defender\UX Configuration" /v "DisablePrivacyMode" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /t REG_BINARY /d "030000000000000000000000" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" /v "HideSystray" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender" /v "PUAProtection" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScriptScanning" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableCatchupFullScan" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableCatchupQuickScan" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableRemovableDriveScanning" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableRestorePoint" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableScanningMappedNetworkDrivesForFullScan" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableScanningNetworkFiles" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "ScanParameters" /t REG_DWORD /d 0 /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "ScheduleDay" /t REG_DWORD /d 8 /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "ScheduleTime" /t REG_DWORD /d 0 /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableUpdateOnStartupWithoutEngine" /t REG_DWORD /d 1 /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "ScheduleDay" /t REG_DWORD /d 8 /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "ScheduleTime" /t REG_DWORD /d 0 /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "SignatureUpdateCatchupInterval" /t REG_DWORD /d 0 /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting" /t REG_DWORD /d 0 /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SYSTEM\ControlSet001\Services\EventLog\System\Microsoft-Antimalware-ShieldProvider" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SYSTEM\ControlSet001\Services\EventLog\System\WinDefend" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SYSTEM\ControlSet001\Services\MsSecFlt" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SYSTEM\ControlSet001\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SYSTEM\ControlSet001\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SYSTEM\ControlSet001\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SYSTEM\ControlSet001\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SYSTEM\ControlSet001\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SYSTEM\ControlSet001\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SYSTEM\ControlSet001\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SYSTEM\ControlSet001\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SYSTEM\ControlSet001\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\OFFLINE_DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f >nul 2>&1
Reg add "HKLM\OFFLINE_DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "PreventOverride" /t REG_DWORD /d 0 /f >nul 2>&1
Reg add "HKLM\OFFLINE_DEFAULT\SOFTWARE\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
Reg add "HKLM\OFFLINE_NTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f >nul 2>&1
Reg add "HKLM\OFFLINE_NTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "PreventOverride" /t REG_DWORD /d 0 /f >nul 2>&1
Reg add "HKLM\OFFLINE_NTUSER\SOFTWARE\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Microsoft\Windows Security Health\State" /v "AppAndBrowser_StoreAppsSmartScreenOff" /t REG_DWORD /d 0 /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControl" /t REG_SZ /d "Anywhere" /f >nul 2>&1
Reg add "HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
"@

#disable smart app control on win 11
if($edition -like "*Windows 11*"){

$win11 = 'Reg add "HKLM\OFFLINE_SYSTEM\ControlSet001\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d "0" /f >nul 2>&1'
$disableDefendContent += "`n" + $win11
}

#run bat with trusted installer to apply reg keys properly
$dPath = New-Item -Path "$PSScriptRoot\disableDefend.bat" -ItemType File -Force
 
Set-Content -Path $dPath.FullName -Value $disableDefendContent -Force

$arguments = "-U:T -P:E -M:S `"$($dPath.FullName)`""

Start-Process "$PSScriptRoot\NSudoLG.exe" -ArgumentList $arguments -WindowStyle Hidden -Wait 

Remove-Item -Path $dPath.FullName -Force

}






function install-adk {

$testP = Test-Path -Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\x86\Oscdimg\oscdimg.exe'  

if(!($testP)){
Write-Host "Installing Windows ADK"
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2196127" -UseBasicParsing -OutFile "$PSScriptRoot\adksetup.exe"
&"$PSScriptRoot\adksetup.exe" /quiet /features OptionId.DeploymentTools | Wait-Process 
Remove-Item -Path "$PSScriptRoot\adksetup.exe" -Force
}

#check if adk installed correctly
$testP = Test-Path -Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\x86\Oscdimg\oscdimg.exe'  

if($testP){
Write-Host "ADK Installed"
return $true
}
else{
return $false
}

}



function remove-Defender([String]$folderPath, [String]$edition, [String]$removeDir) {

[System.Windows.Forms.MessageBox]::Show('Please Make Sure File Explorer is Closed While Removing Defender.', 'Strip Defender')

Write-Host "Removing Defender from $edition..."
Mount-WindowsImage -ImagePath "$tempDir\sources\install.wim" -Name $edition -Path $removeDir

$featureList = dism /image:$removeDir /Get-Features | Select-String -Pattern "Feature Name : " -CaseSensitive -SimpleMatch
$featureList = $featureList -split "Feature Name : " | Where-Object {$_}
foreach ($feature in $featureList){
if($feature -like "*Defender*"){
Write-Host "Removing $feature..."
dism /image:$removeDir /Disable-Feature /FeatureName:$feature /Remove /NoRestart

}

}

#uninstall sec center app
$packages = dism /image:$removeDir /get-provisionedappxpackages | Select-String "PackageName :"
$packages = $packages -split "PackageName : " | Where-Object {$_}
foreach($package in $packages){
if($package -like "*SecHealth*"){
Write-Host "Removing $package Package..."
dism /image:$removeDir /Remove-ProvisionedAppxPackage /PackageName:$package
}

}

Write-Host "Removing Defender Files..."

Remove-File -path "$removeDir\Program Files\Windows Defender"
Remove-File -path "$removeDir\Program Files (x86)\Windows Defender"
Remove-File -path "$removeDir\Program Files\Windows Defender Advanced Threat Protection"
Remove-File -path "$removeDir\ProgramData\Microsoft\Windows Defender"
Remove-File -path "$removeDir\ProgramData\Microsoft\Windows Defender Advanced Threat Protection"
Remove-File -path "$removeDir\Windows\System32\SecurityHealth*"
Remove-File -path "$removeDir\Windows\System32\SecurityCenter*"
Remove-File -path "$removeDir\Windows\System32\smartscreen.exe" 

#win11 sec app
if($edition -like "*Windows 11*"){
Remove-File -path "$removeDir\Program Files\WindowsApps\Microsoft.SecHealthUI_*"


}
else{

#win10 sec app
Remove-File -path "$removeDir\Windows\SystemApps\Microsoft.Windows.SecHealthUI_*"

}

Write-Host "Disabling Defender and Smart Screen..."

#load offline registry 
reg load HKLM\OFFLINE_SOFTWARE "$removeDir\Windows\System32\config\SOFTWARE"
reg load HKLM\OFFLINE_SYSTEM "$removeDir\Windows\System32\config\SYSTEM"
reg load HKLM\OFFLINE_NTUSER "$removeDir\Users\Default\ntuser.dat"
reg load HKLM\OFFLINE_DEFAULT "$removeDir\Windows\System32\config\default"

Disable-Defender -edition $edition

reg unload HKLM\OFFLINE_SOFTWARE
reg unload HKLM\OFFLINE_SYSTEM
reg unload HKLM\OFFLINE_NTUSER
reg unload HKLM\OFFLINE_DEFAULT

Write-Host "Compressing WinSXS Folder..."
dism /image:$removeDir /Cleanup-Image /StartComponentCleanup /ResetBase

Write-Host "Unmounting $edition..."
dism /unmount-image /mountdir:$removeDir /commit


}


Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Windows 10 & 11 Defender Remover"
$form.Size = New-Object System.Drawing.Size(500,250)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle

# Create controls for choosing ISO file
$isoLabel = New-Object System.Windows.Forms.Label
$isoLabel.Location = New-Object System.Drawing.Point(10,20)
$isoLabel.Size = New-Object System.Drawing.Size(120,20)
$isoLabel.Text = "Choose ISO File:"
$form.Controls.Add($isoLabel)

$isoTextBox = New-Object System.Windows.Forms.TextBox
$isoTextBox.Location = New-Object System.Drawing.Point(130,20)
$isoTextBox.Size = New-Object System.Drawing.Size(200,20)
$isoTextBox.Text = $null
$form.Controls.Add($isoTextBox)

$label = New-Object System.Windows.Forms.Label
$label.Text = "Remove From Edition:"
$label.Location = New-Object System.Drawing.Point(10, 100)
$label.AutoSize = $true
$form.Controls.Add($label)

$checkboxPro = New-Object System.Windows.Forms.RadioButton
$checkboxPro.Text = "Pro"
$checkboxPro.AutoSize = $true
$checkboxPro.Location = New-Object System.Drawing.Point(20, 120)
$form.Controls.Add($checkboxPro)

$checkboxHome = New-Object System.Windows.Forms.RadioButton
$checkboxHome.Text = "Home"
$checkboxHome.AutoSize = $true
$checkboxHome.Location = New-Object System.Drawing.Point(70, 120)
$form.Controls.Add($checkboxHome)

$checkboxother = New-Object System.Windows.Forms.RadioButton
$checkboxother.Text = "Other"
$checkboxother.AutoSize = $true
$checkboxother.Location = New-Object System.Drawing.Point(125, 120)

$tooltip = New-Object System.Windows.Forms.ToolTip
$tooltip.SetToolTip($checkboxother, "For non standard Windows Versions ex. Server,LTSC,Enterprise.")
$form.Controls.Add($checkboxother)

$isoBrowseButton = New-Object System.Windows.Forms.Button
$isoBrowseButton.Location = New-Object System.Drawing.Point(340,20)
$isoBrowseButton.Size = New-Object System.Drawing.Size(40,20)
$isoBrowseButton.Text = "..."
$isoBrowseButton.Add_Click({
    $fileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $fileDialog.Filter = "ISO Files (*.iso)|*.iso|All Files (*.*)|*.*"
    
    if ($fileDialog.ShowDialog() -eq "OK") {
        $selectedFile = $fileDialog.FileName
        $isoTextBox.Text = $selectedFile
    }
})
$form.Controls.Add($isoBrowseButton)

# Create controls for choosing destination directory
$destLabel = New-Object System.Windows.Forms.Label
$destLabel.Location = New-Object System.Drawing.Point(10,60)
$destLabel.Size = New-Object System.Drawing.Size(120,25)
$destLabel.Text = "Choose Destination Directory:"
$form.Controls.Add($destLabel)

$destTextBox = New-Object System.Windows.Forms.TextBox
$destTextBox.Location = New-Object System.Drawing.Point(130,60)
$destTextBox.Size = New-Object System.Drawing.Size(200,20)
$destTextBox.Text = $null
$form.Controls.Add($destTextBox)

$destBrowseButton = New-Object System.Windows.Forms.Button
$destBrowseButton.Location = New-Object System.Drawing.Point(340,60)
$destBrowseButton.Size = New-Object System.Drawing.Size(40,20)
$destBrowseButton.Text = "..."
$destBrowseButton.Add_Click({
    $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    
    if ($folderDialog.ShowDialog() -eq "OK") {
        $selectedFolder = $folderDialog.SelectedPath
        $destTextBox.Text = $selectedFolder
    }
})
$form.Controls.Add($destBrowseButton)


# Create "Remove Editions" button

$removeButton = New-Object System.Windows.Forms.Button
$removeButton.Location = New-Object System.Drawing.Point(130, 160)
$removeButton.Size = New-Object System.Drawing.Size(120, 30)
$removeButton.Text = "Remove Defender"
$removeButton.Add_Click({
 
 if(!($checkboxPro.Checked) -and !($checkboxHome.Checked) -and !($checkboxother.Checked)){

 Write-Host "Select the edition to remove from!"

 }
elseif($isoTextBox.Text -eq "" -or $destTextBox.Text -eq ""){
 Write-Host "Please Select an ISO file and Destination folder"

 }else{
 $selectedFile = $isoTextBox.Text
 $selectedFolder = $destTextBox.Text  
Write-Host "Mounting ISO..."
# Mount the ISO
$mountResult = Mount-DiskImage -ImagePath $selectedFile -PassThru
$isoDriveLetter = ($mountResult | Get-Volume).DriveLetter

# Create a temporary directory to copy the ISO contents
$tempDir = "$selectedFolder\TEMP"
New-Item -ItemType Directory -Force -Path $tempDir
$removeDir = New-Item -Path $selectedFolder -Name "RemoveDir" -ItemType Directory 

Write-Host "Moving files to TEMP directory..."
# Copy the ISO contents to the temporary directory
Copy-Item -Path "${isoDriveLetter}:\\*" -Destination $tempDir -Recurse

# Dismount the ISO
Dismount-DiskImage -ImagePath $selectedFile

# Get all files in the folder and its subfolders
$files = Get-ChildItem -Path $tempDir -Recurse -File

# Loop through each file
foreach ($file in $files) {
    # Remove the read-only attribute
    $file.Attributes = 'Normal'
}

# Get all directories in the folder and its subfolders
$directories = Get-ChildItem -Path $tempDir -Recurse -Directory

# Loop through each directory
foreach ($directory in $directories) {
    # Remove the read-only attribute
    $directory.Attributes = 'Directory'
}


$version = dism /Get-WimInfo /WimFile:"${tempDir}\sources\install.wim" | Select-String -Pattern "Name :"
$Global:edition = $null

if($checkboxother.Checked){

# Create the form
$form2 = New-Object System.Windows.Forms.Form
$form2.Text = "Choose Edition"
$form.Size = New-Object System.Drawing.Size(300,300)
$form2.StartPosition = "CenterScreen"
$radioButtons = @()
for ($i = 0; $i -lt $version.Count; $i++) {
    # Create the radio button
    $radioButton = New-Object System.Windows.Forms.RadioButton
    $radioButton.Location = [System.Drawing.Point]::new(20, 20+$i*40)
    $radioButton.Size = [System.Drawing.Size]::new(200, 30)
    $radioButton.Text = ($version[$i] -split 'Name :').trim()
    $form2.Controls.Add($radioButton)
    $radioButtons += $radioButton
}


# Create the OK button
$okButton = New-Object System.Windows.Forms.Button
$okButton.Location = [System.Drawing.Point]::new(100, 200)
$okButton.Size = [System.Drawing.Size]::new(90, 25)
$okButton.Text = "OK"
$okButton.Add_Click({
    $checkedButton = $radioButtons | Where-Object { $_.Checked -eq $true }
    $Global:edition = $checkedButton.Text
    $form2.Close()
    $form2.Dispose()
})
$form2.Controls.Add($okButton)

# Show the form
$form2.ShowDialog() | Out-null

$edition = $edition.Trim()


}else{

if($version -match "Windows 10"){
if($checkboxPro.Checked){
$edition = "Windows 10 Pro"

}
else{
$edition = "Windows 10 Home"

}


}
elseif($version -match "Windows 11"){
if($checkboxPro.Checked){
$edition = "Windows 11 Pro"

}
else{
$edition = "Windows 11 Home"

}

}


}




if($edition -eq $null){
Write-Host "Windows Version not Supported!"
exit
}

if(install-adk){
$oscdimg = 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\x86\Oscdimg\oscdimg.exe'
}
else{
Write-Host "ADK Not Found"
$null = Read-Host "Press Enter to EXIT..."
exit
}

remove-Defender -folderPath $tempDir -edition $edition -removeDir $removeDir

Write-Host "Compressing ISO File"
Export-WindowsImage -SourceImagePath "$tempDir\sources\install.wim" -SourceName $edition -DestinationImagePath "$tempDir\sources\install2.wim" -CompressionType "max"
Remove-Item "$tempDir\sources\install.wim"
Rename-Item "$tempDir\sources\install2.wim" -NewName "install.wim" -Force

Write-Host "Creating ISO File in Destination Directory"
$title = [System.IO.Path]::GetFileNameWithoutExtension($selectedFile) 
$path = "$selectedFolder\$title(ND).iso"
Start-Process -FilePath $oscdimg -ArgumentList "-m -o -u2 -udfver102 -bootdata:2#p0,e,b$tempDir\boot\etfsboot.com#pEF,e,b$tempDir\efi\microsoft\boot\efisys.bin $tempDir `"$path`"" -NoNewWindow -Wait  

if(!(Test-Path -Path "$selectedFolder\$title(ND).iso")){
Write-Host "ISO File Not Found, Something Went Wrong"

}else{
# Delete the temporary directory
Get-ChildItem -Path $tempDir -Recurse -Force | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $removeDir -Recurse -Force | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path $removeDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "DONE!"
}

}

})
$form.Controls.Add($removeButton)

# Show the form
$form.ShowDialog()


