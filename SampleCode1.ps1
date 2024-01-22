
#Region Enabling Help

Function Get-ComputerDetail {
    <#
    .SYNOPSIS
    It gets details of the given list of computers

    .DESCRIPTION
    It gets details of the given list of computers using Win32_ComputerSystem and Win32_operatingSystem

    .NOTES
    This is just a sample script
    .EXAMPLE
    Get-ComputerDetail -computer Computer1, Computer2, Computer3 -logicalProc

    #>
    
    [CmdletBinding()]
    Param([Parameter(ValuefromPipeline = $true, Mandatory = $True)][String[]]$Computer, [switch]$LogicalProc)

    ForEach ($Machine in $Computer) {
        $Win32Computer = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $Machine
        $Win32OS = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $Machine

        if ($LogicalProc) {
            $CombinedObj = @{
                ComputerName     = $Machine
                Memory           = $Win32Computer.TotalPhysicalMemory
                FreeMemory       = $Win32OS.FreePhysicalMemory
                Processor        = $Win32Computer.NumberOfProcessors
                LogicalProcessor = $Win32Computer.NumberOfLogicalProcessors
                OSVersion        = $Win32OS.Version
            }
        }
        else {
            $CombinedObj = @{
                ComputerName = $Machine
                Memory       = $Win32Computer.TotalPhysicalMemory
                FreeMemory   = $Win32OS.FreePhysicalMemory
                Processor    = $Win32Computer.NumberOfProcessors
                OSVersion    = $Win32OS.Version
            }
        }

        $OutputObj = New-Object -TypeName psobject -Property $CombinedObj

        Write-Output $OutputObj
    }
}

#EndRegion

#Region Expandable and Verbatim strings

# HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell

Get-Service | Where-Object { $_.Status -eq 'Stopped' }
Get-Service | Where-Object { $PSItem_.Status -eq 'Stopped' }
Get-Service | ? { $_.Status -eq 'Stopped' }
Get-Service | where { $_.Status -eq 'Stopped' }
Get-Service | where  Status -eq 'Stopped' 
Get-Service | ?  Status -eq 'Stopped' 


Write-Host "Hello world!"
Write-Host 'Hello world!'
Write-Host 'Hello world! $env:username'
Write-Host "Hello world! $env:username"

#EndRegion

#Region Function

Param([Parameter(Mandatory = $True)][String[]]$Computer)

ForEach ($Machine in $Computer) {
    $Win32Computer = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $Machine
    $Win32OS = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $Machine

    $CombinedObj = @{
        ComputerName = $Machine
        Memory       = $Win32Computer.TotalPhysicalMemory
        FreeMemory   = $Win32OS.FreePhysicalMemory
        Processor    = $Win32Computer.NumberOfProcessors
        OSVersion    = $Win32OS.Version
    }

    $OutputObj = New-Object -TypeName psobject -Property $CombinedObj

    Write-Output $OutputObj
}

#EndRegion

#Region Parameters samples

Function Get-Greeting {
    Param(
        [Parameter(Mandatory = $true, Position = 1)][String]$Name,
        [Parameter(Mandatory = $true, Position = 2)][String]$Greeting
    )

    Write-Output "$Greeting $Name"
}

Get-Greeting "Nitish" "Good day!"
Get-Greeting -Greeting "Good Day!" -Name "Nitish Kumar"

Function Get-Greeting {
    Param(
        [Parameter(Mandatory = $true, Position = 1)][Alias("Person")][String]$Name,
        [Parameter(Mandatory = $true, Position = 2)][String]$Greeting
    )

    Write-Output "$Greeting $Name"
}

Get-Greeting -Greeting "Good Day!" -Person "Nitish Kumar"

Function Get-ComputerDetail {
    Param([Parameter(Mandatory = $True)][String[]]$Computer, [switch]$LogicalProc)

    ForEach ($Machine in $Computer) {
        $Win32Computer = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $Machine
        $Win32OS = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $Machine

        if ($LogicalProc) {
            $CombinedObj = @{
                ComputerName     = $Machine
                Memory           = $Win32Computer.TotalPhysicalMemory
                FreeMemory       = $Win32OS.FreePhysicalMemory
                Processor        = $Win32Computer.NumberOfProcessors
                LogicalProcessor = $Win32Computer.NumberOfLogicalProcessors
                OSVersion        = $Win32OS.Version
            }
        }
        else {
            $CombinedObj = @{
                ComputerName = $Machine
                Memory       = $Win32Computer.TotalPhysicalMemory
                FreeMemory   = $Win32OS.FreePhysicalMemory
                Processor    = $Win32Computer.NumberOfProcessors
                OSVersion    = $Win32OS.Version
            }
        }

        $OutputObj = New-Object -TypeName psobject -Property $CombinedObj

        Write-Output $OutputObj
    }
}


Function Get-ComputerDetail {
    [CmdletBinding()]
    Param([Parameter(ValuefromPipeline = $true, Mandatory = $True)][String[]]$Computer, [switch]$LogicalProc)

    ForEach ($Machine in $Computer) {
        $Win32Computer = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $Machine
        $Win32OS = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $Machine

        if ($LogicalProc) {
            $CombinedObj = @{
                ComputerName     = $Machine
                Memory           = $Win32Computer.TotalPhysicalMemory
                FreeMemory       = $Win32OS.FreePhysicalMemory
                Processor        = $Win32Computer.NumberOfProcessors
                LogicalProcessor = $Win32Computer.NumberOfLogicalProcessors
                OSVersion        = $Win32OS.Version
            }
        }
        else {
            $CombinedObj = @{
                ComputerName = $Machine
                Memory       = $Win32Computer.TotalPhysicalMemory
                FreeMemory   = $Win32OS.FreePhysicalMemory
                Processor    = $Win32Computer.NumberOfProcessors
                OSVersion    = $Win32OS.Version
            }
        }

        $OutputObj = New-Object -TypeName psobject -Property $CombinedObj

        Write-Output $OutputObj
    }
}

#EndRegion

#Region Credentials

# Basic way
$userName = "Nitish"
$Password = "Master@123"
$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
[pscredential]$credObject = New-Object System.Management.Automation.PSCredential ($userName, $SecurePassword)

(Get-Credential).GetNetworkCredential().Password

# Decrypting secure string
$password = ConvertTo-SecureString 'P@ss$w0rd' -AsPlainText -Force
$Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($password)
$result = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)


Read-Host "Enter Password" -AsSecureString |  ConvertFrom-SecureString | Out-File "C:\Temp\Password.txt"
$pass = Get-Content "C:\Temp\Password.txt" | ConvertTo-SecureString

$User = "MyUserName"
$File = "C:\Temp\Password.txt"
$MyCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, (Get-Content $File | ConvertTo-SecureString)

# Saving the credential to file using Windows Data Protection API
# In order for DAPI to work, the GPO setting Network Access: Do not allow storage of passwords and credentials for network authentication must be set to Disabled (or not configured).  Otherwise the encryption key will only last for the lifetime of the user session (i.e. upon user logoff or a machine reboot, the key is lost and it cannot decrypt the secure string text)

If ([System.IO.File]::Exists("C:\temp\myCred_${env:USERNAME}_${env:COMPUTERNAME}.xml")) {
    $UserCredential = Import-CliXml -Path "C:\temp\myCred_${env:USERNAME}_${env:COMPUTERNAME}.xml"
}
Else {
    $Answer = Read-host "Want to create credentials file to re-use (Y/N)"
    If ($Answer.ToUpper() -eq "Y") {
        Get-Credential  -Message "Provide admin credentials" | Export-CliXml -Path "C:\temp\myCred_$($env:USERNAME)_$($env:COMPUTERNAME).xml"
        Write-Output "`nCredentials file created."  -Foregroundcolor GREEN -Backgroundcolor White
    }
    Else {
        Write-Output "`nThese credentials would not be saved for later run." -Foregroundcolor RED -Backgroundcolor YELLOW
        $UserCredential = Get-Credential	
    }
}

# Create the credential file with custom encryption key
$PasswordFile = "c:\temp\mypassword.txt"
$KeyFile = "c:\temp\my.keyfile"


$key = 0..255 | Get-Random -Count 32 | ForEach-Object { [byte]$_ } # 32 means AES encryption
$Key | out-file $KeyFile

$Key = Get-Content $KeyFile
$Password = Read-Host "Please enter your password" -AsSecureString
$Password | ConvertFrom-SecureString -Key $Key | Out-File $PasswordFile

$User = "MyUserName"
$key = Get-Content $KeyFile
$MyCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, (Get-Content $PasswordFile | ConvertTo-SecureString -Key $key)


#EndRegion

