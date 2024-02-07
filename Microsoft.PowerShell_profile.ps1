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

function prompt {
	set-executionPolicy Unrestricted -Scope CurrentUser
	set-PSReadLineOption -Colors @{ InlinePrediction = "$([char]0x1b)[96m" }
	Write-Host "$(Get-Date) | $($pwd.path):" -foregroundcolor BLACK -nonewline -backgroundcolor CYAN
	$a = Get-History -Count 1
	Write-host " $([math]::Round(($a.EndExecutionTime - $a.StartExecutionTime).TotalSeconds, 2)) seconds " -ForeGroundColor GREEN -nonewline
}

#Clear-Host
