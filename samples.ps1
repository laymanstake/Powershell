#region Error handling

$psISE.Options.ErrorForegroundColor = "#FFFF9494"
$psISE.Options.ErrorBackgroundColor = "#00FFFFFF"
$psISE.Options.ConsolePaneBackgroundColor = "BLACK"

trap {    
    "Caught the error"
    Break
}
clear-host
throw "The script is not supposed to run directly"

#endregion 

#region function

([psobject].assembly.gettype("System.Management.Automation.TypeAccelerators")::Get).keys -join ", "


function Simple-function (
    [string]$parameter1, 
    [Parameter(ValueFromPipeline = $true, mandatory = $true, Helpmessage="It should be from given values None,Info,Warning,Error")][ValidateSet('None','Info','Warning','Error')]$parameter2) {
    
    Write-host "Parameter1 value is $parameter1"
    Write-host "Parameter2 value is $parameter2"
}

function Simple-function ([string]$parameter1, [int]$parameter2) {

    Write-host "Parameter1 value is $parameter1"
    Write-host "Parameter2 value is $parameter2"
}

Function New-Function {
[CmdletBinding(SupportsShouldProcess)]
    Param(  
	[Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, mandatory = $true)][Alias("Text")]$input,
	[Parameter(ValueFromPipeline = $true)][ValidateNotNullorEmpty()]$logpath,
    [Parameter(ValueFromPipeline = $true, mandatory = $true, Helpmessage="It should be from given values")][ValidateSet('None','Info','Warning','Error')]$infoType,
	[Parameter(ValueFromPipeline = $false, mandatory = $true)][ValidateScript({$_ -gt 0 –AND $_ -lt 10000})][int]$Number,	
	$RandomParameter
)
    Write-Verbose "This is sample verbose message"
    Write-Debug "This is sample debug message"
    Write-host "Sample normal message"
}

#endregion

#region progress bar

for ($i = 1; $i -le 100; $i++ ) {
    Write-Progress -Activity "Search in Progress" -Status "$i% Complete:" -PercentComplete $i
    Start-Sleep -Milliseconds 250
}

$items = 1..10
$i = 1
foreach ($item in $items) {
    write-progress -id 1 -activity "Parent Progress Bar" -status "Iteration $item" -percentComplete ($i++ / $items.count * 100)
    $j = 1
    foreach ($child in $items) {
        write-progress -parentId 1 -activity "Child Progress Bar" -status "Iteration $item`.$child" -percentComplete ($j++ / $items.count * 100)
        Start-sleep 1
    }
}

#endregion

#region credential

Get-Credential  -Message "Provide credentials" | Export-CliXml -Path "C:\temp\myCred_$($env:USERNAME)_$($env:COMPUTERNAME).xml"
$UserCredential = Import-CliXml -Path "C:\temp\myCred_${env:USERNAME}_${env:COMPUTERNAME}.xml"

#endregion

#region CredentialManager
install-module credentialmanager
new-StoredCredential -Target O1365 -Credentials (Get-Credential) -Persist LocalMachine
Get-StoredCredential -target O365

#endregion

#region credential with key file
# Create the credential file with custom encryption key, only password encrypted
$PasswordFile = "c:\temp\mypassword.txt"
$KeyFile = "c:\temp\my.keyfile"

$key = 0..255 | Get-Random -Count 32 | ForEach-Object { [byte]$_ } | out-file $KeyFile # 32 means AES encryption # Generate a random key and save it to a file

$User = "MyUserName"
$Password = Read-Host "Please enter your password" -AsSecureString
$Password | ConvertFrom-SecureString -Key $Key | Out-File $PasswordFile
$Key = Get-Content $KeyFile
$MyCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, (Get-Content $PasswordFile | ConvertTo-SecureString -Key $key)

#endregion

#region credential with key file with user/password both encrypted

# Create the credential file in xml format where both username and passwords are encrypted
$KeyFile = "c:\temp\my.keyfile"
$key = 0..255 | Get-Random -Count 32 | ForEach-Object { [byte]$_ } | out-file $KeyFile # 32 means AES encryption # Generate a random key and save it to a file
# Get the credential object from the user
$cred = Get-Credential
$secureUserName = ConvertTo-SecureString -String $cred.UserName -AsPlainText -Force
$securePassword = $cred.Password
$encryptedUserName = ConvertFrom-SecureString -SecureString $secureUserName -Key $key
$encryptedPassword = ConvertFrom-SecureString -SecureString $securePassword -Key $key

# Create a custom object with the encrypted username and password
$object = [PSCustomObject]@{
    UserName = $encryptedUserName
    Password = $encryptedPassword
}
# Export the object to an XML file
$object | Export-Clixml -Path "C:\temp\credfile.xml"
$key = Get-Content -Path "C:\temp\keyfile.txt"
$object = Import-Clixml -Path "C:\temp\credfile.xml"

# Decrypt both the username and the password with the key and convert them to secure strings
$encryptedUserName = $object.UserName
$secureUserName = ConvertTo-SecureString -String $encryptedUserName -Key $key
$plainUserName = ConvertFrom-SecureString -SecureString $secureUserName -Key $key -AsPlainText
$encryptedPassword = $object.Password
$securePassword = ConvertTo-SecureString -String $encryptedPassword -Key $key

$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $plainUserName, $securePassword
#endregion

#region Sample code

# program 1
 $header = @"
 <style>
    body { background-color: #b9d7f7; }  
    table { font-size: 12px; border: 1px;  font-family: Arial, Helvetica, sans-serif; }  
    td { padding: 4px; margin: 0px; border: 1; } 
    th { background: #395870; color: #fff; font-size: 11px; vertical-align: middle; }
 </style>
"@
 
 
$htmlParams = @{
      Title = "Processes details"
      Body = Get-Date
      PreContent = "<P>Generated by Corporate IT</P>"
      PostContent = "For details, contact Corporate IT."
      Head = $header
    }
    get-process | Sort-Object WorkingSet64 -Descending |Select-Object Name, Id, PriorityClass, 
@{l="Memory";e={$("{0:N2}" -f ($_.WorkingSet64/1Mb))+ " Mb"}} -First 10 | ConvertTo-Html @htmlParams | Out-File 
Processes.htm
    Invoke-Item Processes.htm
 Get-process | Sort-Object WorkingSet64 -Descending |Select-Object Name, Id, PriorityClass, 
@{l="Memory";e={$("{0:N2}" -f ($_.WorkingSet64/1Mb))+ " Mb"}} -First 10 | ConvertTo-Html -Title "Processes details" -PreContent "<p><b>Generated by Corporate IT</b></p>" -PostContent "<br><b>For details contact Corporate 
IT</b></br>" -Body (get-date) | Out-File Processes.htm


# program 2

 $header = @"
 <style>
    body { background-color: #b9d7f7; }  
    table { font-size: 12px; border: 1px;  font-family: Arial, Helvetica, sans-serif; }  
    td { padding: 4px; margin: 0px; border: 1; } 
    th { background: #395870; color: #fff; font-size: 11px; vertical-align: middle; }
 </style>
"@

$ProcessSummary = Get-process | Sort-Object WorkingSet64 -Descending |Select-Object Name, Id, PriorityClass, 
@{l="Memory";e={$("{0:N2}" -f ($_.WorkingSet64/1Mb))+ " Mb"}} -First 10  | ConvertTo-Html -As Table

$DiskSummary = get-wmiObject -Class Win32_logicaldisk | Select-object PSComputername, VolumeName, DeviceID, @{Name =
 "SizeGB"; Expression = { $_.Size / 1GB -as [int] } }, @{Name = "UsedGB"; Expression = { "{0:N2}" -f (($_.Size - 
$_.Freespace) / 1GB) } }, @{Name = "FreeGB"; Expression = { "{0:N2}" -f ($_.FreeSpace / 1GB) } } | ConvertTo-Html -As Table 

$OSSummary = Get-WmiObject -Class Win32_operatingSystem | Select-Object caption, Version, Buildnumber, Installdate |
 ConvertTo-Html -As Table 

$Report = ConvertTo-Html -Body "$ProcessSummary $DiskSummary $OSSummary" -Title "Multi table report" -head $header -PostContent "<p id='CreationDate'> Creation Date: $(Get-Date)</p>"

$Report | Out-File c:\temp\multitable.htm
Invoke-Item c:\temp\multitable.htm


# program 3

 try {    Remove-Item -Path "C:\temp\file.txt" -ErrorAction Stop}
 catch {    $error[0].exception.message}

 trap  {    
    "I caught the error"
    $error[0].exception.Message    
 }
  Remove-Item -Path "C:\temp\file.txt" -ErrorAction Stop
 

#endregion