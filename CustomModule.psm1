<#

@;:::::,:::;;;oooooooxxxxooooo;oooooooo;;;;;;;;;;;;:;;;;;:o@
;;;;::::::::;;;;oooooo;:::,,,:,,,;oo;;;;;;;;;;;;:::::;;;;::;
;;;;;:::::::::;;;;;;:,.,,,,,::,,.,,:;;;;;:::::::::::;;;;;;;;
;;;;:::,,,::::::::,,,,,,.,,,,,,,...,,,::::::::;;;;;;;;;oo;;o
o;;;;::::,,,,,,,,,.,,,,,,,,,,.,:,.,,,,,,,:;;;;;;oooooooooooo
oo;;;;;;::::,,,,,.,,,,,,,,:,,.,,,.,,,,.,,,;oooooooooooooxxxx
ooooooooo;;;:,,,...,::,,:::,,,,,...,,,,,,,;ooxxxxxxxxxxxxxxx
oooooooooooo;:,,..,,:::,,:,,,,.....,,,,:.,,:oxxxxxxxxxxxxxxx
xxxxxxxxxxooo:,,.,:;::,,,,,,,,,,..,,,,,,,,,,:xxxxxxxxxxxxxxx
xxxxxxxxxxxo;:,..,::,,,.,.....,,.,,,....,,,,,;xxxxxxxoxoxxxx
xxxxxxxxxxxo:,.,,::,....................,,.,,:oxxxxxoooooooo
xxxxxxxxxx;:,,,,,,..... . .............,..,.,:;xxxxxoooooxoo
xxxxxxxxo:,,,,,::,...... ...........,..,,,..,::oxxxxoooooooo
xxxxxxxx;,,,:,,:,..........................,,,,;oooooooooooo
xxxxxxxo,:,:,,,,.....,,,:::,,:,,,....,......,,,:oooooooooooo
xxxxxxx:,,,:,,,,...,,::;;;;;;;;;:::,,,,,,,,.,,::;;;;oooooooo
xxxxxx;,,,::,,,,,,::;;oooooooooo;;;::,,,,,..,,::,:;;;;oo;;;o
xxxxxx::,,::,,,,::;;oooooooxxooooo;;::,,,,,,,,,::,::;;;;;;;;
xxxxxx:,,:,:,,,:;;ooooooxxxxxxxxooo;;::,,,,.,,,,,,,::;;;;;:;
xxxxxo,,,,,,.,:;;oooooxxxxxxxxxxxooo;;:::,,,,,,,,,,,:;;;;:::
xoxxx;:,,,...,:;;oooooxxxxxxxxxxxxooo;;:::,,,,,,,,,,:;;;;:,,
oooooo,,,.,..,:;oooooxxxxxxxxxxxxxxooo;;;::,...,,,,,:;;;::,,
oooooo:,.....,:oooooxxxxxxxxxxxxxxxxxo;;;;:,..,,,,,:;;;;::,,
oooooo;,....,,;ooooxxxxxxxxxxx%%%xxxxxoo;;;:,.,,::::;;o;::,,
oooo;;;,,...,:;oooxxxxxxx%%%%%xxxxxxxxoooo;;;,,::::;;oo;:,,,
;;;;;;::,.,.,;oooxxxxxxxxxxxxxxoooo;;;::;;;;o:,:;::;;oo;;,,,
;;:::::,,.,.,;ooo;;o;ooooxxxxoo::,,,.,,,::;ooo,::::;;oo;:,,,
::::::,,,,..;oo:,,,,,,,::;oooo;:,..,:;;;;:;ooo:;;:::;oo;:,,,
:::::,,,,,.,;;::::::,,,,::;oo;;:::,::::::;;;oo:;;:::;;o;:,,,
::::::::::,:;;::;;;;:::::;oxxx;::,,,,,,,::;ooo;:;;:;;;;;:,,,
::::::::::,:;;;;:::,,,,,:;ox%xo::,;o,,:;::;ooo;:;;:;;;;;;:,,
::::::::::::;;;;:,;,,,:,:;ox%xo;:::;:;;;;oooooo:;;:;;;oo;;;;
;;;;;;;;;;;:oo;:::o;,::::oox%%xxo;;;;;;oxxxxxoo:::::;;oooooo
;;;;;;;;;;;:ooo;;;;;;;;;oxxx%%xxxxooxxxxxxxxxoo:::::;ooooxxx
;;;;;;;;;o;:oooooooooooxxxxx%%xxx%%xxx%%%%xxxoo:::::;;ooxxox
;;;;;;;;;o;:;oooxxxxxxxxxxxx%%xxxx%%%%%%%%xxxoo;::::;;oooooo
;;;;;;;;oo;:;oxxxxxxx%%xxxxx%%%xxx%%%%%%%%xxxoo;,:::;;;;;;;;
;;;;;;;;ooo:;oxxxx%x%%%xoxx%%%%xxxx%%%%%%%xxxoo;,:::;;;;;::,
;;;;;;;oooo:;oxxxx%%%%xoxxx%%%xxxxxx%%%%%%xxxxo;,:::;;;;;:,,
;;;;;;ooooo;;oxxxxx%%xxxxxxxxxxxxxxxx%%%%xxxxxo;,::::;;;::,,
;;;;;;ooooo;;oxxxxxxxxxo;;ooooo;:oxxxxxxxxxxxxo::::::;;;:,,,
;;;;;;;;oo;;;ooxxxxxxxxo;:;;;;:;;ox%%xxxxxxxxoo::::::;;;:,,,
:;;;;;;;;;;;;oooxxxxxxxo;;;::::;;oxxxxxxxxxxxoo::::::;;;:,,,
:;;;;;;;;;;;;;ooxxxxxxoo;;;;;;ooooxxxxxxxxxxooo;;;:::;;::,,,
;;ooo;;;;;;;;;ooooooooo;;;o;;oxxxxooooooxxooooooo;;::;;::,,,
ooxxxooooooo;;ooooooo;;oooooooo;;oooooooooooooxoo;;:;;;::,,,
xxxxxxxxxxooo;oooooo;;;;;:::;::::::::;oooooooo;oo;;:;;;::,,,
x%%%%xxxxxooo;;ooooo;:,,::::;;;o;;::::;ooooo;o,:;;;;;;;::,,,
%%%%%xxxxxooo;;ooooo;;;:;;ooxxxoo;;ooo;oooo;;;,.,:;;;;;:::,,
%%%%%xxxooooo;;oooooooo;;;;;ooo;;;;oooo;;;;;;;,..,:;;;;;;:::
%%%%%xxooooo;;;;;;o;ooooo;;;:::;;;ooooo;;;;;;o,...,:ooo;;;;;
x%%%xxooooo;;;;:;;;;ooooo;;:::::;oooooo;;;:;;o:...,,;oo;;;;;
xxxxxxooooo;;;:::;;;;oooooo;;;;ooxxxooo;;::;oo:...,,,:;;;;;;
xxxxxxoooooo;;::.,:;;;oooooooooxxxxxoo;::::ooo,...,,,,,::::;
xxxxxxxooooo;;:,...:;;;oooooooooxxxoo;::::;oo;....,,,.,,,,,:
xxxxxxxoooooo;,.....::;;oooooooooooo;;:::;ooo:...,,.,,,,...,
xxxxxxooooooo;....  ;::;;;;;;;ooooo;::::;ooo;,.......,,,....
oxxxxooooooo:,...  .:;::;;;;;;;;;;:::::;;ooo:....,...,,,,...
oooooooooo:,...... ,:;o;::::::,::::::;;;;oo;,...,....,,,,,..
ooooooo;,.......  .:;;;o;:::::::::::;;;;oo;:........,,,,,,..
xxooo:,...........,;;;;;;;;;::::::;;;;;;;o;,.......,,,,,,,..
xxo:,.............:;;;;oo;;;;;;:;;;;;;;;oo,.........,..,,,..
o:,...............:;;;;;oooo;;;;;;;;;;;oo:.......,,,,.,.....
,....,............:;;;;;ooooooo;;;;;;;oo:.......,,,,,,,.....
,.,,,,............:;;;;;oooooo;;;;;o;oo,.....,..,,,,.,. ....
,,,,,.............:;;oooooooooooooooo;.......,.,,,.,........
,,,,,.............,;;ooooooooooooooo;.....,..,.,,...........
,,,,,..............;ooooooooooooooo;............  ..........
,,,,,,,............:ooxxxoooxxxxxo;.......,.................
,,,,,,,,...........,ooxxxxxxxxxxxo,.......,,................

#>

function Convert-ImageToAsciiArt {  
	<#
  .SYNOPSIS
     Function to convert an image to ascii art.
     
  .DESCRIPTION
     The function Convert-ImageToAsciiArt takes an image file path and converts the image to ASCII art.
     The ASCII art is created by replacing each pixel in the image with an ASCII character based on the brightness of the pixel.
     The ASCII characters used are specified in the $chars variable, and their brightness is determined by the grayscale value of the original pixel.
     
  .EXAMPLE
      Convert-ImageToAsciiArt -ImagePath "C:\path\to\image.jpg"
      
  .EXAMPLE
      Convert-ImageToAsciiArt -ImagePath "C:\path\to\image.jpg" -MaxWidth 80 -Contrast 75
#>
	param (
		[Parameter(Mandatory = $true)]
		[ValidateScript({ Test-Path $_ -PathType 'Leaf' })]
		[string]$ImagePath,
        
		[Parameter()]
		[int]$MaxWidth = 120
	)
    
	# Load the image and resize it to a maximum width of $MaxWidth.
	$image = [System.Drawing.Image]::FromFile($ImagePath)
	$ratio = $MaxWidth / $image.Width
	$newWidth = [int]($image.Width * $ratio)
	$newHeight = [int]($image.Height * $ratio)
	$resizedImage = $image.GetThumbnailImage($newWidth, $newHeight, $null, [System.IntPtr]::Zero)
    
	# Create a list of ASCII characters to use for the output.
	$chars = @(' ', '.', ',', ':', ';', 'o', 'x', '%', '#', '@')
    
	# Convert each pixel in the image to an ASCII character based on its brightness.
	$asciiChars = for ($y = 0; $y -lt $resizedImage.Height; $y++) {
		$line = for ($x = 0; $x -lt $resizedImage.Width; $x++) {
			$pixel = $resizedImage.GetPixel($x, $y)
			$brightness = ([int]$pixel.R * 0.299 + [int]$pixel.G * 0.587 + [int]$pixel.B * 0.114) / 255
			$charIndex = [int]($brightness * ($chars.Count - 1))
			$chars[$charIndex]
		}
		[string]::Join('', $line)
	}
    
	Write-Output $asciiChars
}

function Read-Text {
	<#
        .SYNOPSIS
        This function reads the provided text
        .DESCRIPTION
        This is just for educational purpose. This function reads the provided text
        .PARAMETER Text
        Specify string of text
        .INPUTS
        None. It doesn't support input via pipeline
        .OUTPUTS
        System.Object[]
        .EXAMPLE
        PS> Read-Text -Text "Hi! My name is Nitish Kumar"

        .EXAMPLE
        PS> "Hi! My name is Nitish Kumar" | Read-text

        .LINK
        https://nitishkumar.net/2022/11/03/collection-of-ps-functions-for-useful-gui-elements/
        #>
	[CmdletBinding()]
	Param(	[Parameter(ValuefromPipeline = $true, Mandatory = $True)]
		[String]$Text
	)
	
	Add-Type -AssemblyName System.Speech
	$ATAVoiceEngine = New-Object System.Speech.Synthesis.SpeechSynthesizer	
	$ATAVoiceEngine.SelectVoice("Microsoft Zira Desktop")
	if ($Text -AND $Text -ne "`n") {
		$ATAVoiceEngine.Speak($text)
		$Text
	}

	#$speaker = new-object -ComObject sapi.spvoice
	#$speaker.speak($Text)
}

function Get-PSTaskManager {
	<#
        .SYNOPSIS
        This function produces common columns of the Windows Task Manager
        .DESCRIPTION
        This is just for educational purpose. This function produces common columns of the Windows Task Manager
        .PARAMETER Name
        No parameters supported
        .INPUTS
        None. It doens't accept pipeline input
        .OUTPUTS
        System.Object[]
        .EXAMPLE
        PS> Get-PSTask-Manager
        .LINK
        https://github.com/laymanstake
        #>

	[CmdletBinding(
		HelpURI = 'https://nitishkumar.net'
	)]
	Param ()	
	$PerDetails = Get-CimInstance -className Win32_PerfFormattedData_PerfProc_Process
	Get-Process -IncludeUserName | Select-Object Name, @{l = "PID"; e = { $_.ID } }, PriorityClass, @{l = "Status"; e = { if ($_.Responding) { "Running" } else { "Suspended" } } }, UserName, SessionId, @{l = 'CPUPercent'; Expression = { [Math]::Round( ($_.CPU * 100 / (New-TimeSpan -Start $_.StartTime).TotalSeconds), 2) } }, @{Name = "Private Working Set"; Expression = { $ProcessID = $_.ID; [math]::Round(($PerDetails | Where-Object { $_.IDprocess -eq $ProcessID }).WorkingSetPrivate / 1kb, 0) } }, Description
}


function Get-DiskSpace {
	<#
        .SYNOPSIS
        This function provides details of disk drives, their size in GBs and free disk space.
        .DESCRIPTION
        This is just for educational purpose. This function provides details of disk drives, their size in GBs and free disk space. It can get the information from multiple computers
        .PARAMETER Servers
        Specify Computername or an array of computer names
        .INPUTS
        None. It doesn't support input via pipeline
        .OUTPUTS
        System.Object[]
        .EXAMPLE
        PS> Get-DiskSpace -Server Computer1, Computer2
        .LINK
        https://nitishkumar.net/2022/11/03/collection-of-ps-functions-for-useful-gui-elements/
        #>
	Param([parameter(mandatory = $True)]$servers)
	ForEach ($Server in $Servers) {
		Get-WmiObject -Class Win32_logicaldisk -computer $Server | Select-object PSComputername, VolumeName, DeviceID, @{Name = "SizeGB"; Expression = { $_.Size / 1GB -as [int] } }, @{Name = "UsedGB"; Expression = { "{0:N2}" -f (($_.Size - $_.Freespace) / 1GB) } }, @{Name = "FreeGB"; Expression = { "{0:N2}" -f ($_.FreeSpace / 1GB) } }
	}
}

Function Run-EncryptedScript {
	<#
	.SYNOPSIS
	This function run an existing encrypted script
	.DESCRIPTION
	This is just for educational purpose. This function run an existing encrypted script
	.PARAMETER ScriptPath
	Specify path for the script to be encrypted.
	.INPUTS
	System.String. Need a correct script path
	.OUTPUTS
	None
	.EXAMPLE
	PS> Run-EncryptedScript -ScriptPath C:\temp\mypublicip_Encrypted.ps1
	.EXAMPLE
	PS> Run-EncryptedScript -ScriptPath C:\temp\mypublicip_Encrypted.ps1 -ShowCodeOnly
	.LINK
	https://nitishkumar.net/2022/10/24/one-stop-bash-script-to-setup-prometheus-grafana-and-windows-exporter-on-centos-linux-machine/
	#>


	[cmdletbinding()]
	param (
		[parameter(Mandatory = $true, ValueFromPipeline = $True, helpmessage = "It should be valid path")][validatescript({ Test-Path $_ })][string]$ScriptPath,
		[parameter(Mandatory = $false, ValueFromPipeline = $True)][switch]$ShowCodeOnly

	)

	[string]$scriptCode = Get-Content $ScriptPath

	$decryptedCode = $scriptCode | ConvertTo-SecureString
	$Code = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($decryptedCode))

	if ($ShowCodeOnly) {
		$Code -split "\t"
	}
 else {
		Invoke-Expression $Code
	}
}

Function Export-EncryptedScript {
	<#
	.SYNOPSIS
	This function encrypts an existing script to encrypted string text file
	.DESCRIPTION
	This is just for educational purpose. This function encrypts an existing script to encrypted string text file
	.PARAMETER ScriptPath
	Specify path for the script to be encrypted.
	.PARAMETER ExportPath
	Specify path for the exported encrypted script.
	.INPUTS
	System.String. Need a correct script path
	.OUTPUTS
	System.String. Need a correct script path
	.EXAMPLE
	PS> Export-EncryptedScript -ScriptPath C:\temp\mypublicip.ps1 -ExportPath C:\temp\mypublicip_Encrypted.ps1
	.LINK
	https://nitishkumar.net/2022/10/24/one-stop-bash-script-to-setup-prometheus-grafana-and-windows-exporter-on-centos-linux-machine/
	#>


	[cmdletbinding()]
	param (
		[parameter(Mandatory = $true, ValueFromPipeline = $True, helpmessage = "It should be valid path")][validatescript({ Test-Path $_ })][string]$ScriptPath,
		[parameter(Mandatory = $true, ValueFromPipeline = $True, helpmessage = "It should be valid path")][string]$ExportPath
	)

	[string]$Code = Get-content -Path $ScriptPath
	$SecureCode = ConvertTo-SecureString $Code -AsPlainText -Force
	$null = ConvertFrom-SecureString -SecureString $SecureCode | Out-File -FilePath $ExportPath

}


function Get-FolderSize {
	<#
	.SYNOPSIS
	This function provides folder size and file counts for the given path
	.DESCRIPTION
	This is just for educational purpose. This function provides folder size and file counts for the given path
	.PARAMETER Path
	Specify path to be checked for folders.
	.INPUTS
	None. It doesn't support input via pipeline
	.OUTPUTS
	System.Object[]
	.EXAMPLE
	PS> Get-FolderSize -Path "c:\temp"
	.LINK
	https://nitishkumar.net/2022/10/24/one-stop-bash-script-to-setup-prometheus-grafana-and-windows-exporter-on-centos-linux-machine/
	#>

	Param([parameter(mandatory = $True)][validatescript({ if (Test-Path $_) { $true } else { throw "$_ is not valid path" } })]$Path)
	$folders = Get-ChildItem -Path $Path -Directory -force -ErrorAction SilentlyContinue
	foreach ($folder in $folders) {
		$folderPath = $folder.FullName
		$folderName = $folder.Name
		$subfolders = Get-ChildItem -Path $folderPath -Directory -Recurse -ErrorAction SilentlyContinue
		$files = Get-ChildItem -Path $folderPath -File -Recurse -force -ErrorAction SilentlyContinue
		$size = "{0:N2}" -f (($files | Measure-Object -Property Length -Sum).Sum / 1gb)
		$fileCount = $files.Count
		$subfolderCount = $subfolders.Count

		[PSCustomObject]@{
			FolderName      = $folderName
			FolderPath      = $folderPath
			Size            = $size
			SubfoldersCount = $subfolderCount
			FileCount       = $fileCount
		}
	}
}


function Get-RandomPassword {
	<#
	.SYNOPSIS
	This function provides a random passsword of the given number of words, min 4 characters and maximum 80 characters
	.DESCRIPTION
	This is just for educational purpose. This function provides a random passsword of the given number of words. Password returned would include at least one Caps, one small letter, one numeric and one special character.
	.PARAMETER Count
	Specify number of characters in the password
	.INPUTS
	None. It doesn't support input via pipeline
	.OUTPUTS
	System.String
	.EXAMPLE
	PS> Get-RandomPassword -count 8
	.LINK
	https://nitishkumar.net/2022/10/21/one-stop-powershell-script-to-setup-prometheus-grafana-and-windows-exporter-on-windows-machine/
	#>
	param ([Parameter(Mandatory = $true)][validatescript({ $_ -ge 4 -and $_ -le 80 })][int]$Count)

	$rest = ""	
	$upper = Get-Random -InputObject ([char[]]"ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	$lower = Get-Random -InputObject ([char[]]"abcdefghijklmnopqrstuvwxyz")
	$digit = Get-Random -InputObject ([char[]]"0123456789")
	$symbol = Get-Random -InputObject ([char[]]"!@#$%^&*()_+-=")
	if ($count - 4 -gt 0) { $rest = (Get-Random -InputObject ([char[]]"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=") -count ($count - 4) ) -join ""	}
	$randomPassword = (($upper , $rest , $lower , $symbol , $digit) | get-random -Count 5) -join ""

	return $RandomPassword
}

function Get-WebPageInfo {
	<#
	.SYNOPSIS
	This function provides status of a given URL
	.DESCRIPTION
	This is just for educational purpose. This function provides status of a given URL
	.PARAMETER URL
	Specify the URL as string
	.INPUTS
	None. It doesn't support input via pipeline
	.OUTPUTS
	System.Object[]
	.EXAMPLE
	PS> Get-WebPageInfo
	.LINK
	https://nitishkumar.net/2021/09/05/powershell-sharepoint-mass-deletion-alert/
	#>
	param ([Parameter(Mandatory = $true)][string]$URL)
	$response = Invoke-WebRequest -Uri $URL
	$info = $response | Select-Object -Property StatusCode, StatusDesciption
	return $info
}


function IsPrime {
	<#
	.SYNOPSIS
	This function checks if an given integer is a PRIME number or not
	.DESCRIPTION
	This is just for educational purpose. This function checks if an given integer is a PRIME number or not
	.PARAMETER Number
	Specify the integer
	.INPUTS
	None. It doesn't support input via pipeline
	.OUTPUTS
	System.Boolean
	.EXAMPLE
	PS> IsPrime -Number 1771
	.LINK
	https://nitishkumar.net/2019/03/10/powershell-for-servers-inventory/
	#>
	Param([parameter(mandatory = $True)][validatescript({ If ($_ -gt 0 -AND $_ -lt 10000) { $true } else { throw "$_ is not valid, input an integer betweek 1-10000" } })][int]$Number)
	if ($Number -le 1) { return $false }# 1 is neither composite nor prime
	for ($i = 2; $i -lt $number; $i++) {	if ($number % $i -eq 0) { return $false } }
	return $true
}

function Get-PrimeFactors {
	<#
	.SYNOPSIS
	This function provides prime factors of a given integer
	.DESCRIPTION
	This is just for educational purpose. This function provides prime factors of a given integer
	.PARAMETER Number
	Specify the integer
	.INPUTS
	None. It doesn't support input via pipeline
	.OUTPUTS
	System.String
	.EXAMPLE
	PS> Get-PrimeFactors -Number 1771
	.LINK
	https://nitishkumar.net/2018/08/24/file-share-inventory-for-all-dfs-shares-via-powershell-permissions-and-size/
	#>

	param ([Parameter(Mandatory = $true)][int]$Number)
	$factors = @()
	$divisor = 2
    
	while ($Number -gt 1) {  
		if ($Number % $divisor -eq 0) {     
			$factors += $divisor
			$Number = $Number / $divisor   
		}
		else {            
			$divisor++        
		}    
	}
	return ($factors -join " x ")
}

Function Advanced-Netstat {
	<#
	.SYNOPSIS
	This function provides prime factors of a given integer
	.DESCRIPTION
	This is just for educational purpose. This function provides prime factors of a given integer
	.PARAMETER Number
	Specify the integer
	.INPUTS
	None. It doesn't support input via pipeline
	.OUTPUTS
	System.String
	.EXAMPLE
	PS> Get-PrimeFactors -Number 1771
	.LINK
	https://nitishkumar.net/2018/08/24/file-share-inventory-for-all-dfs-shares-via-powershell-permissions-and-size/
	#>

	$ipAddresses = @()
	#[int]$i = 0

	$netstat = Get-NetTCPConnection

	$netstat.ForEach(
		{
			$Process = Get-Process -Id $_.OwningProcess
			$ProcessExecutable = If ($Process.Path) { Split-Path ($Process.Path) -Leaf -errorAction SilentlyContinue } else { "" }
			#$null = $i++
			#Write-Progress -Activity "Getting details of $($Process.Name)" -Status "$("{0:N2}" -f ($i * 100 / $netstat.count)) % complete" -CurrentOperation "Working on $($Process.Name)" -PercentComplete (($i / $netstat.count) * 100)
			Write-Host "Working on $($_.RemoteAddress)"

			$RemoteAddress = $_.RemoteAddress

			if ($RemoteAddress -notlike "::*" -AND $RemoteAddress -notlike "0.*" -AND $RemoteAddress -notlike "192.168*" -AND $RemoteAddress -notlike "172.*" -AND $RemoteAddress -notin $ipAddresses) {

				$geoData = Invoke-RestMethod -Method Get -Uri "http://ip-api.com/json/$($RemoteAddress)"
				$ipAddresses += $geoData

				if ($geoData.country) {
					$_ | Add-Member -NotePropertyName RemoteCity -NotePropertyValue $geoData.city
					$_ | Add-Member -NotePropertyName RemoteCountry -NotePropertyValue $geoData.country
					$_ | Add-Member -NotePropertyName RemoteRegion -NotePropertyValue $geoData.RegionName
					$_ | Add-Member -NotePropertyName RemoteCompany -NotePropertyValue $geoData.Org		
				} 
			}
			else {
				$_ | Add-Member -NotePropertyName RemoteCity -NotePropertyValue ($ipAddresses | ? { $_.Query -eq $RemoteAddress }).City
				$_ | Add-Member -NotePropertyName RemoteCountry -NotePropertyValue ($ipAddresses | ? { $_.Query -eq $RemoteAddress }).Country
				$_ | Add-Member -NotePropertyName RemoteRegion -NotePropertyValue ($ipAddresses | ? { $_.Query -eq $RemoteAddress }).RegionName
				$_ | Add-Member -NotePropertyName RemoteCompany -NotePropertyValue ($ipAddresses | ? { $_.Query -eq $RemoteAddress }).Org			    
			}

			[pscustomobject] @{
				LocalAddress       = $_.LocalAddress
				LocalPort          = $_.LocalPort
				RemoteAddress      = $_.RemoteAddress
				RemotePort         = $_.RemotePort
				RemoteCompany      = $_.RemoteCompany
				RemoteCity         = $_.RemoteCity
				RemoteCountry      = $_.RemoteCountry
				RemoteRegion       = $_.RemoteRegion
				State              = $_.State
				ProcessName        = $Process.Name
				ProcessExecutable  = $ProcessExecutable
				ProcessPath        = $Process.Path
				ProcessStartTime   = $Process.StartTime
				ProcessCompany     = $Process.Company
				ProcessDescription = $Process.Description
		
			}
		})
}

Function Super-Netstat {
	<#
	.SYNOPSIS
	This function provides advanced details of the incoming and outgoing IP Addresses connected to the machine
	.DESCRIPTION
	This is just for educational purpose. This function provides advanced details of the incoming and outgoing IP Addresses connected to the machine
	.PARAMETER
	None
	.INPUTS
	None. It doesn't support input via pipeline
	.OUTPUTS
	System.Object[]
	.EXAMPLE
	PS> Super-NetStat 
	.LINK
	https://nitishkumar.net/2018/04/08/powershell-script-for-dns-inventory/
	#>
	
	$netstat = netstat -bn | Select-Object -Skip 4
	$ipAddresses = @()
	$Finalresults = @()

	foreach ($line in $netstat) {
		$remoteipAddress = ($line -split "\s+" | Select-Object -Index 3 ) -split ":" | Select-Object -Index 0
		if ($remoteipAddress -AND ($remoteipAddress -notin $ipAddresses) -AND $remoteIPAddress -notlike "``[*") {
			$ipAddresses += $remoteipAddress
		}  
	}

	foreach ($ipAddress in $ipAddresses) {
		$geoData = Invoke-RestMethod -Method Get -Uri "http://ip-api.com/json/$ipAddress"
		if ($geoData.country) {
			$geoObject = [PSCustomObject]@{
				IP      = $geoData.query
				City    = if ($geoData.city) { $geoData.city } else { "No data" }
				Country = if ($geoData.country) { $geoData.country } else { "No data" }
				Region  = if ($geoData.RegionName) { $geoData.RegionName } else { "No data" }
				Company = if ($geoData.Org) { $geoData.Org } else { "No data" }
			}
		}
		$Finalresults += $geoObject
	}
	$Finalresults | Sort-Object Country 
}

function Get-PublicIP {
	<#
	.SYNOPSIS
		Gets the public IP address
	.DESCRIPTION
		This is for educational purposes. It gets the public IP address of the current machine. 	
	.LINK
		https://nitishkumar.net
	.EXAMPLE
		Get-PublicIP		
	#>
	
	Invoke-RestMethod -Method Get -Uri "http://ip-api.com/json/$(invoke-restMethod -Method Get -Uri "http://api.ipify.org")"
}

function Get-Temperature {
	<#
	.SYNOPSIS
		Gets the temperature for the current public IP area
	.DESCRIPTION
		This is for educational purposes. Gets the temperature for the current public IP area.
	.LINK
		https://nitishkumar.net
	.EXAMPLE
		Get-Temperature
	#>
	
	$PublicIP = Get-PublicIP
	((invoke-RestMethod -Method Get -Uri "https://api.open-meteo.com/v1/forecast?latitude=$($PublicIP.lat)&longitude=$($PublicIP.lon)&current=temperature_2m") | select-Object @{l = "Temperature"; e = { "$($_.current.temperature_2m)$($_.current_units.temperature_2m)" } }).Temperature
}

Function Get-ShareDetail {
	<#
	.SYNOPSIS
		This gets the share details for the given server
	.DESCRIPTION
		This is for educational purpose. This gets the share details for the given server	
	.LINK
		https://github.com/laymanstake
	.EXAMPLE
		Get-ShareDetail -Server Server1
	#>	

	[CmdletBinding()]
	Param (
		# File server name
		[Parameter(Mandatory)][String]$Server		
	)

	$Shares = Get-CIMInstance -class Win32_Share -Computername $Server | Select-Object Name, Path, @{l = "SharePath"; e = { "\\$server\$($_.Name)" } }, Status

	$SharePermissions = ForEach ($Share in $Shares) {
		try {
			$ACLs = Get-ACL $Share.SharePath -ErrorAction Stop
		}
		catch {
			Write-Host "Permissions denied on $($Share.SharePath)" -ForegroundColor YELLOW
		}
        
		if ($ACLS) {
			ForEach ($ACL in $ACLs.Access) {
        
				Switch ($ACL.FileSystemRights) {
					2032127 { $AccessMask = "FullControl" }
					1179785 { $AccessMask = "Read" }
					1180063 { $AccessMask = "Read, Write" }
					1179817 { $AccessMask = "ReadAndExecute" }
					{ -1610612736 } { $AccessMask = "ReadAndExecuteExtended" }                        
					1245631 { $AccessMask = "ReadAndExecute, Modify, Write" }
					1180095 { $AccessMask = "ReadAndExecute, Write" }
					268435456 { $AccessMask = "Write" }
					{ $_ -notmatch '^[-]*[0-9]+$' -AND -NOT($_ -in ("-536084480")) } { $AccessMask = [string]$ACL.FileSystemRights }
					default { $AccessMask = "SpecialPermissions" }
				}
				$IdentityReference = $ACL.Identityreference.Value
				$AccessType = $AccessMask
				$AccessControlType = $ACL.AccessControlType

				[pscustomobject]@{
					Name            = $Share.Name
					Path            = $Share.Path
					SharePath       = $Share.SharePath
					Status          = $Share.Status
					SharePermission = $IdentityReference
					PermissionType  = $AccessType
					Control         = $AccessControlType
				}
			}
		}
		else {
			[pscustomobject]@{
				Name            = $Share.Name
				Path            = $Share.Path
				SharePath       = $Share.SharePath
				Status          = $Share.Status
				SharePermission = "No access"
				PermissionType  = "No access"
				Control         = "No access"
			}
		}
		$ACLs = ""
	}
	$SharePermissions
}

Function Get-DirectReport {
	<#
	.SYNOPSIS
		Function to get all direct reports under the given user recursively
	.DESCRIPTION
		Educational purposes only, function to get all direct reports under the given user recursively	
	.LINK
		https://github.com/laymanstake
	.EXAMPLE
		Get-DirectReport -user Ayush.Mishra
	#>
	
	param (
		# User SamAccountName required
		[String]$user
	)
    
	$Reportees = New-Object System.Collections.Generic.List[PSObject]

	$userDetail = Get-aduser -identity $User -Properties DirectReports, Manager    
	$item = $userDetail | Select-Object Name, SamAccountName, Enabled, @{l = "Manager"; e = { $_.Manager.Split(“,”).Split(“=”)[1] } }    
	$Reportees.Add($item)

	if ($userDetail.DirectReports) {
		ForEach ($Reportee in $userDetail.DirectReports) {            
			$DirectReportees = Get-DirectReport -user $Reportee
            
			foreach ($DirectReportee in $DirectReportees) {
				$Reportees.Add($DirectReportee)
			}
		}
	}    
	$Reportees
}

Function Get-DirectReport-old {
	param (
		# User SamAccountName required
		[String]$user
	)        
    
	$Reportees = @()
	$userDetail = Get-aduser -identity $User -Properties DirectReports, Manager    
	$Reportees += $userDetail | Select-Object Name, SamAccountName, Enabled, @{l = "Manager"; e = { $_.Manager.Split(“,”).Split(“=”)[1] } }    

	if ($userDetail.DirectReports) {
		ForEach ($Reportee in $userDetail.DirectReports) {            
			Get-DirectReport-old -user $Reportee
		}
	}
	$Reportees
}

Function Get-Permission {
	<#
	.SYNOPSIS
		Function to get permission on given folder in readable format
	.DESCRIPTION
		Educational purposes only, Function to get permission on given folder in readable format
	.LINK
		https://github.com/laymanstake
	.EXAMPLE
		Get-Permission -Path c:\windows\Sysvol
	#>

	Param (
		[Parameter(Mandatory)][ValidateScript({ Test-Path $_ })][String]$Path
	)

	try {
		$ACLs = Get-ACL $Path -ErrorAction Stop
	}
	catch {
		Write-Host "Permissions denied on $($Path)" -ForegroundColor YELLOW
	}
        
	if ($ACLS) {
		ForEach ($ACL in $ACLs.Access) {

			$IdentityReference = ""
			$AccessType = ""
			$AccessControlType = ""
        
			Switch ($ACL.FileSystemRights) {
				2032127 { $AccessMask = "FullControl" }
				1179785 { $AccessMask = "Read" }
				1180063 { $AccessMask = "Read, Write" }
				1179817 { $AccessMask = "ReadAndExecute" }
				{ -1610612736 } { $AccessMask = "ReadAndExecuteExtended" }                        
				1245631 { $AccessMask = "ReadAndExecute, Modify, Write" }
				1180095 { $AccessMask = "ReadAndExecute, Write" }
				268435456 { $AccessMask = "Write" }
				{ $_ -notmatch '^[-]*[0-9]+$' -AND -NOT($_ -in ("-536084480")) } { $AccessMask = [string]$ACL.FileSystemRights }
				# -AND -NOT($_ -in ("-1610612736"))
				default { $AccessMask = "SpecialPermissions" }
			}
			$IdentityReference = $ACL.Identityreference.Value
			$AccessType = $AccessMask
			$AccessControlType = $ACL.AccessControlType

			[pscustomobject]@{					
				Path            = $Path
				SharePermission = $IdentityReference
				PermissionType  = $AccessType
				Control         = $AccessControlType
			}
		}
	}
	else {
		[pscustomobject]@{				
			Path            = $Path				
			SharePermission = "No access"
			PermissionType  = "No access"
			Control         = "No access"
		}
	}
	$ACLs = ""
}