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

#Region Progress bar

# Simple sample progress bar
for ($i = 1; $i -le 100; $i++ ) {
    Write-Progress -Activity "Search in Progress" -Status "$i% Complete:" -PercentComplete $i
    Start-Sleep -Milliseconds 250
}

# Nested progress bar sample
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


# Practical use
$Files = Get-ChildItem -Path "C:\Source"
$Destination = "C:\Destination"
$TotalFiles = $Files.Count
$Count = 0
Write-Progress -Activity "Copying Files" -Status "Starting" -PercentComplete 0
foreach ($File in $Files) {
    $Count++
    $PercentComplete = (($Count / $TotalFiles) * 100)
    $Status = "Copying $($File.Name)"
    Write-Progress -Activity "Copying Files" -Status $Status -PercentComplete $PercentComplete
    Copy-Item $File.FullName $Destination -Force
}
Write-Progress -Activity "Copying Files" -Status "Complete" -PercentComplete 100

#Endregion

#Region Credentials

# Basic way
$userName = "Nitish"
$Password = "Master@123"
$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
[pscredential]$credObject = New-Object System.Management.Automation.PSCredential ($userName, $SecurePassword)

(Get-Credential).GetNetworkCredential().Password # Easily getting back the password as plain text

Read-Host "Enter Password" -AsSecureString |  ConvertFrom-SecureString | Out-File "C:\Temp\Password.txt"
$pass = Get-Content "C:\Temp\Password.txt" | ConvertTo-SecureString
$User = "MyUserName"
$File = "C:\Temp\Password.txt"
$MyCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, (Get-Content $File | ConvertTo-SecureString)

$MyCredential.GetNetworkCredential().Password # Easily getting back the password as plain text

# Saving the credential to file using Windows Data Protection API
# In order for DAPI to work, the GPO setting Network Access: Do not allow storage of passwords and credentials for network authentication must be set to Disabled (or not configured).  Otherwise the encryption key will only last for the lifetime of the user session (i.e. upon user logoff or a machine reboot, the key is lost and it cannot decrypt the secure string text)

Get-Credential  -Message "Provide admin credentials" | Export-CliXml -Path "C:\temp\myCred_$($env:USERNAME)_$($env:COMPUTERNAME).xml"
$UserCredential = Import-CliXml -Path "C:\temp\myCred_${env:USERNAME}_${env:COMPUTERNAME}.xml"


# resuable code suitable for Windows OS and for general usages
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

# Create the credential file with custom encryption key, only password
$PasswordFile = "c:\temp\mypassword.txt"
$KeyFile = "c:\temp\my.keyfile"
$key = 0..255 | Get-Random -Count 32 | ForEach-Object { [byte]$_ } | out-file $KeyFile # 32 means AES encryption
$User = "MyUserName"
$Password = Read-Host "Please enter your password" -AsSecureString
$Password | ConvertFrom-SecureString -Key $Key | Out-File $PasswordFile
$Key = Get-Content $KeyFile
$MyCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, (Get-Content $PasswordFile | ConvertTo-SecureString -Key $key)



# Create the credential file in xml format where both username and passwords are encrypted
# Generate a random key and save it to a file
$KeyFile = "c:\temp\my.keyfile"
$key = 0..255 | Get-Random -Count 32 | ForEach-Object { [byte]$_ } | out-file $KeyFile # 32 means AES encryption

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






#EndRegion

#Region PowerShell Jobs

$lognames = (get-eventlog -List).Log

Measure-Command {
    $logs = $logNames | ForEach-Object {
        Get-WinEvent -LogName $_ -MaxEvents 5000 2>$null
    }
}

Measure-Command {
    $logs = $logNames | ForEach {
        Start-ThreadJob {
            Get-WinEvent -LogName $using:_ -MaxEvents 5000 2>$null
        } -ThrottleLimit 10
    } | Wait-Job | Receive-Job
}


$func = {
    function Inventory {
        [CmdletBinding()]
        Param(
            [Parameter(ValueFromPipeline = $true, mandatory = $true)]$hostname
        )

        $CPUInfo = Get-WmiObject Win32_Processor -ComputerName $hostname
        $PhysicalMemory = Get-WmiObject Win32_PhysicalMemory -ComputerName $hostname | Measure-Object -Property capacity -Sum | ForEach-Object { "{0:N0}" -f ($_.sum / 1GB) }

        $infoObject = New-Object PSObject -Property @{
            ServerName      = $hostname
            "IP Address"    = (Resolve-DnsName $hostname | Where-Object { $_.type -eq "A" }).IPAddress -join ","
            OperatingSystem = (Get-WmiObject win32_operatingsystem -ComputerName $hostname).caption
            Processor       = ($CPUInfo.Name -join ",")
            MemoryInGb      = $PhysicalMemory
        }
        return $infoObject
    }
}

$Servers = ("XYZ", "ABC", "QWERTY")

$i = $Servers.count

ForEach ($hostname in $Servers) {    
    $f1 = { Inventory $using:hostname }

    If (Test-Connection $hostname -Quiet -Ping) {
        Start-Job -Name "Inventory.$hostname" -InitializationScript $func -ScriptBlock $f1 | Out-Null
    }
    Else {
        Write-Host "$hostname not reachable"
    }
}

While (Get-Job "Inventory*" | Where-Object { $_.State -eq "Running" }) {    
    $CurrentRunningJobs = (Get-Job "Inventory*" | Where-Object { $_.State -eq "Running" }).count
    Write-Progress -Activity "Jobs are running, please wait." -Status "$($CurrentRunningJobs) jobs running" -PercentComplete (100 * ($i - $CurrentRunningJobs) / $i)    
    Start-Sleep 1
}

#Collecting the data from Jobs
$Result = @()
foreach ($Job in (Get-Job | Where-Object { $_.Name -like "Inventory.*" })) {
    $JobResult = $null
    $JobResult = Receive-Job $Job
    $Result += $JobResult
    Remove-Job $Job
}
`

# A practical use
$maxParallelJobs = 50
$null = Get-Job | Remove-Job
$jobs = @()

while ((Get-Job -State Running).Count -ge $maxParallelJobs) {
    Start-Sleep -Milliseconds 50  # Wait for 0.05 seconds before checking again
} 

$ScriptBlock = {
    param($computer)
            
    try {                
        $Service = (Get-Service adfssrv, adsync).Name
    }
    catch {
        Write-Output "Could get Service details from $computer : $($_.Exception.Message)"
    }           

    if ($service) {
        if ($service -contains "adfssrv") {
            $adfs = $computer                   
        }
        if ($service -contains "adsync" ) {                    
            $aad = $computer
        }
    }

    Return $adfs, $aad
}

if (Test-Connection -ComputerName $_.Name -count 1 -Quiet ) {
    $jobs += Start-Job -ScriptBlock $scriptBlock -ArgumentList $_.Name
}

$null = Wait-Job -Job $jobs

foreach ($job in $jobs) {
    $result = Receive-Job -Job $job
    $null = Remove-Job -Job $job
 
    if ($result[0]) {
        $adfsServers += $result[0]
    }
    if ($result[1]) {
        $aadconnectservers += $result[1]
    }
}

#EndRegion