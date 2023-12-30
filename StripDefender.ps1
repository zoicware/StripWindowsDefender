#strip defender by zoic
#this script will use dism to remove windows defender from an iso file


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



#disable service using nsudo
function Disable-Service([String]$location,[String]$Service){
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
#$ogLocation = Get-Location
$WindowsPath = Join-Path $location "Windows"
#disable service
$arguments = "-U:T -P:E -M:S Powershell.exe -windowstyle Hidden -command `"Set-Location -Path $WindowsPath; Set-Service -Name $Service -StartupType Disabled`""

Start-Process "$PSScriptRoot\NSudoLG.exe" -ArgumentList $arguments -WindowStyle Hidden -Wait

Write-Host "$Service Disabled"
}
else{

Write-Host "NSudo Not Found!"

}




}




function New-IsoFile 
{  
  <# .Synopsis Creates a new .iso file .Description The New-IsoFile cmdlet creates a new .iso file containing content from chosen folders .Example New-IsoFile "c:\tools","c:Downloads\utils" This command creates a .iso file in $env:temp folder (default location) that contains c:\tools and c:\downloads\utils folders. The folders themselves are included at the root of the .iso image. .Example New-IsoFile -FromClipboard -Verbose Before running this command, select and copy (Ctrl-C) files/folders in Explorer first. .Example dir c:\WinPE | New-IsoFile -Path c:\temp\WinPE.iso -BootFile "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\efisys.bin" -Media DVDPLUSR -Title "WinPE" This command creates a bootable .iso file containing the content from c:\WinPE folder, but the folder itself isn't included. Boot file etfsboot.com can be found in Windows ADK. Refer to IMAPI_MEDIA_PHYSICAL_TYPE enumeration for possible media types: http://msdn.microsoft.com/en-us/library/windows/desktop/aa366217(v=vs.85).aspx .Notes NAME: New-IsoFile AUTHOR: Chris Wu LASTEDIT: 03/23/2016 14:46:50 #> 
   
  [CmdletBinding(DefaultParameterSetName='Source')]Param( 
    [parameter(Position=1,Mandatory=$true,ValueFromPipeline=$true, ParameterSetName='Source')]$Source,  
    [parameter(Position=2)][string]$Path = "$env:temp\$((Get-Date).ToString('yyyyMMdd-HHmmss.ffff')).iso",  
    [ValidateScript({Test-Path -LiteralPath $_ -PathType Leaf})][string]$BootFile = $null, 
    [ValidateSet('CDR','CDRW','DVDRAM','DVDPLUSR','DVDPLUSRW','DVDPLUSR_DUALLAYER','DVDDASHR','DVDDASHRW','DVDDASHR_DUALLAYER','DISK','DVDPLUSRW_DUALLAYER','BDR','BDRE')][string] $Media = 'DVDPLUSRW_DUALLAYER', 
    [string]$Title = (Get-Date).ToString("yyyyMMdd-HHmmss.ffff"),  
    [switch]$Force, 
    [parameter(ParameterSetName='Clipboard')][switch]$FromClipboard 
  ) 
  
  Begin {  
    ($cp = new-object System.CodeDom.Compiler.CompilerParameters).CompilerOptions = '/unsafe' 
    if (!('ISOFile' -as [type])) {  
      Add-Type -CompilerParameters $cp -TypeDefinition @'
public class ISOFile  
{ 
  public unsafe static void Create(string Path, object Stream, int BlockSize, int TotalBlocks)  
  {  
    int bytes = 0;  
    byte[] buf = new byte[BlockSize];  
    var ptr = (System.IntPtr)(&bytes);  
    var o = System.IO.File.OpenWrite(Path);  
    var i = Stream as System.Runtime.InteropServices.ComTypes.IStream;  
   
    if (o != null) { 
      while (TotalBlocks-- > 0) {  
        i.Read(buf, BlockSize, ptr); o.Write(buf, 0, bytes);  
      }  
      o.Flush(); o.Close();  
    } 
  } 
}  
'@  
    } 
   
    if ($BootFile) { 
      if('BDR','BDRE' -contains $Media) { Write-Warning "Bootable image doesn't seem to work with media type $Media" } 
      ($Stream = New-Object -ComObject ADODB.Stream -Property @{Type=1}).Open()  # adFileTypeBinary 
      $Stream.LoadFromFile((Get-Item -LiteralPath $BootFile).Fullname) 
      ($Boot = New-Object -ComObject IMAPI2FS.BootOptions).AssignBootImage($Stream) 
    } 
  
    $MediaType = @('UNKNOWN','CDROM','CDR','CDRW','DVDROM','DVDRAM','DVDPLUSR','DVDPLUSRW','DVDPLUSR_DUALLAYER','DVDDASHR','DVDDASHRW','DVDDASHR_DUALLAYER','DISK','DVDPLUSRW_DUALLAYER','HDDVDROM','HDDVDR','HDDVDRAM','BDROM','BDR','BDRE') 
  
    Write-Verbose -Message "Selected media type is $Media with value $($MediaType.IndexOf($Media))"
    ($Image = New-Object -com IMAPI2FS.MsftFileSystemImage -Property @{VolumeName=$Title}).ChooseImageDefaultsForMediaType($MediaType.IndexOf($Media)) 
   
    if (!($Target = New-Item -Path $Path -ItemType File -Force:$Force -ErrorAction SilentlyContinue)) { Write-Error -Message "Cannot create file $Path. Use -Force parameter to overwrite if the target file already exists."; break } 
  }  
  
  Process { 
    if($FromClipboard) { 
      if($PSVersionTable.PSVersion.Major -lt 5) { Write-Error -Message 'The -FromClipboard parameter is only supported on PowerShell v5 or higher'; break } 
      $Source = Get-Clipboard -Format FileDropList 
    } 
  
    foreach($item in $Source) { 
      if($item -isnot [System.IO.FileInfo] -and $item -isnot [System.IO.DirectoryInfo]) { 
        $item = Get-Item -LiteralPath $item
      } 
  
      if($item) { 
        Write-Verbose -Message "Adding item to the target image: $($item.FullName)"
        try { $Image.Root.AddTree($item.FullName, $true) } catch { Write-Error -Message ($_.Exception.Message.Trim() + ' Try a different media type.') } 
      } 
    } 
  } 
  
  End {  
    if ($Boot) { $Image.BootImageOptions=$Boot }  
    $Result = $Image.CreateResultImage()  
    [ISOFile]::Create($Target.FullName,$Result.ImageStream,$Result.BlockSize,$Result.TotalBlocks) 
    Write-Verbose -Message "Target image ($($Target.FullName)) has been created"
    $Target
  } 
} 



function remove-Defender([String]$folderPath, [String]$edition, [String]$removeDir) {

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

#win11 sec app
if($edition -like "*Windows 11*"){
Remove-File -path "$removeDir\Program Files\WindowsApps\Microsoft.SecHealthUI_*"
Remove-File -path "$removeDir\Windows\System32\SecurityHealth*"

}
else{

#win10 sec app
Remove-File -path "$removeDir\Windows\SystemApps\Microsoft.SecHealthUI_*"

}



Write-Host "Preventing Windows Update from installing Defender..."

$folders = @("$removeDir\Program Files\Windows Defender","$removeDir\Program Files (x86)\Windows Defender","$removeDir\Program Files\Windows Defender Advanced Threat Protection")

# Create new folders with read-only access to all users
foreach($folder in $folders){
$var = New-Item -ItemType Directory -Path $folder -Force

$folderAcl = Get-Acl $folder
$folderAcl.SetAccessRuleProtection($true, $false)
$folderAcl | Set-Acl $folder

}

Write-Host "Disabling Service..."
Disable-Service -location $removeDir -Service "SecurityHealthService"

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
 
 if(!($checkboxPro.Checked) -and !($checkboxHome.Checked)){

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


remove-Defender -folderPath $tempDir -edition $edition -removeDir $removeDir

Write-Host "Compressing ISO File"
Export-WindowsImage -SourceImagePath "$tempDir\sources\install.wim" -SourceName $edition -DestinationImagePath "$tempDir\sources\install2.wim" -CompressionType "max"
#dism /Export-Image /SourceImageFile:"$tempDir\sources\install.wim" /SourceIndex:$index /DestinationImageFile:"$mountDir\sources\install2.wim" /compress:max
Remove-Item "$tempDir\sources\install.wim"
Rename-Item "$tempDir\sources\install2.wim" -NewName "install.wim" -Force

Write-Host "Creating ISO File in Destination Directory"
$folder = Get-ChildItem -Path "$tempDir\*"
$title = [System.IO.Path]::GetFileNameWithoutExtension($selectedFile) 
New-IsoFile -Source $folder -Path "$selectedFolder\$title(ND).iso" -Force   

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



