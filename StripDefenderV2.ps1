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



function install-adk {

$testP = Test-Path -Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\x86\Oscdimg\oscdimg.exe'  

if(!($testP)){
Write-Host "Installing Windows ADK"
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2196127" -UseBasicParsing -OutFile "$PSScriptRoot\adksetup.exe"
.\adksetup /quiet /features OptionId.DeploymentTools | Wait-Process 
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

Write-Host "Preventing Windows Update from installing Defender..."

$folders = @("$removeDir\Program Files\Windows Defender","$removeDir\Program Files (x86)\Windows Defender","$removeDir\Program Files\Windows Defender Advanced Threat Protection","$removeDir\ProgramData\Microsoft\Windows Defender","$removeDir\ProgramData\Microsoft\Windows Defender Advanced Threat Protection")

# Create new folders with read-only access to all users
foreach($folder in $folders){
$var = New-Item -ItemType Directory -Path $folder -Force

$folderAcl = Get-Acl $folder
$folderAcl.SetAccessRuleProtection($true, $false)
$folderAcl | Set-Acl $folder

}


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


$version = dism /Get-WimInfo /WimFile:"${tempDir}\sources\install.wim"
$edition = $null
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

if($checkboxother.Checked){

if($version -match "Enterprise" -or $version -match "LTSC"){
$version = dism /Get-WimInfo /WimFile:"${tempDir}\sources\install.wim" /Index:1

foreach($line in $version){
if($line -match "Name :"){
$editions = $line -split ':' 
}
}
$edition = $editions[1].Trim()
}
elseif($version -match "Server"){
foreach($line in $version){
if($line -match "Standard Evaluation"){
$editions = $line -split ':' 
}
}
$edition = $editions[1].Trim()

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

