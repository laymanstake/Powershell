<#  
    Author : Nitish Kumar (nitish@nitishkumar.net)
    Performs Entra ID Intune Assessment
    version 1.0 | 26-03-2025 Initial version
    
    Disclaimer: This script is designed to only read data from the entra id and should not cause any problems or change configurations but author do not claim to be responsible for any issues. Do due dilligence before running in the production environment
#>

<#
.SYNOPSIS
	Get-EntraIDIntuneDetails.ps1 - Perform Entra ID Intune assessment and generate a HTML report.
.DESCRIPTION
	Script to get important details of Entra ID Intune
.NOTES
	This would need a number of permissions, which would involve the Global admin permissions for the first time but all these permissions are READ permissions (except two) and would not make change in curnt configuration. The script is NOT using any POST or PATCH methods with API so it would not change anything in the environment
.LINK
	https://nitishkumar.net
.EXAMPLE
	.\Get-EntraIDIntuneDetails.ps1	
#>

# This function creates log entries for the major steps in the script.
function Write-Log {
	[CmdletBinding()]
	Param(
		[Parameter(ValueFromPipeline = $true, mandatory = $true)]$logtext,
		[Parameter(ValueFromPipeline = $true, mandatory = $true)]$logpath
	)

	$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
	$LogMessage = "$Stamp : $logtext"
    
	$isWritten = $false

	do {
		try {
			Add-content $logpath -value $LogMessage -Force -ErrorAction SilentlyContinue
			$isWritten = $true
		}
		catch {
		}
	} until ( $isWritten )
}

# This function creates a balloon notification to display on client computers.
function New-BaloonNotification {
	Param(
		[Parameter(ValueFromPipeline = $true, mandatory = $true)][String]$title,
		[Parameter(ValueFromPipeline = $true, mandatory = $true)][String]$message,        
		[Parameter(ValueFromPipeline = $true, mandatory = $false)][ValidateSet('None', 'Info', 'Warning', 'Error')][String]$icon = "Info",
		[Parameter(ValueFromPipeline = $true, mandatory = $false)][scriptblock]$Script
	)
	Add-Type -AssemblyName System.Windows.Forms

	if ($null -eq $script:balloonToolTip) { $script:balloonToolTip = New-Object System.Windows.Forms.NotifyIcon }

	$tip = New-Object System.Windows.Forms.NotifyIcon


	$path = Get-Process -id $pid | Select-Object -ExpandProperty Path
	$tip.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
	$tip.BalloonTipIcon = $Icon
	$tip.BalloonTipText = $message
	$tip.BalloonTipTitle = $title    
	$tip.Visible = $true            
    
	try {
		register-objectevent $tip BalloonTipClicked BalloonClicked_event -Action { $script.Invoke() } | Out-Null
	}
	catch {}
	$tip.ShowBalloonTip(10000) # Even if we set it for 1000 milliseconds, it usually follows OS minimum 10 seconds
	Start-Sleep -seconds 1
    
	$tip.Dispose() # Important to dispose otherwise the icon stays in notifications till reboot
	Get-EventSubscriber -SourceIdentifier "BalloonClicked_event"  -ErrorAction SilentlyContinue | Unregister-Event # In case if the Event Subscription is not disposed
}

# This function gives user option to opt out from some of the permissions required, report would be reduced as well
function Get-PermSelection {
	[CmdletBinding()]
	Param(
		[Parameter(ValueFromPipeline = $true, mandatory = $true)]$permissions
	)

	Add-Type -AssemblyName System.Windows.Forms
	[System.Windows.Forms.Application]::EnableVisualStyles() # To enable system theme
    
	$OKButton = New-Object System.Windows.Forms.Button -Property @{
		Location     = New-Object System.Drawing.Point(75, 220)
		Size         = New-Object System.Drawing.Size(75, 23)
		Text         = 'OK'
		DialogResult = [System.Windows.Forms.DialogResult]::OK
	}

	$CancelButton = New-Object System.Windows.Forms.Button -Property @{
		Location     = New-Object System.Drawing.Point(250, 220)
		Size         = New-Object System.Drawing.Size(75, 23)
		Text         = 'Cancel'
		DialogResult = [System.Windows.Forms.DialogResult]::Cancel
	}

	$label = New-Object System.Windows.Forms.Label -Property @{
		Location = New-Object System.Drawing.Point(10, 20)
		Size     = New-Object System.Drawing.Size(370, 20)
		Text     = 'Select the permissions, you wish to allow, all needed for complete report'
	}

	$listBox = New-Object System.Windows.Forms.Listbox -Property @{
		Location      = New-Object System.Drawing.Point(10, 50)
		Size          = New-Object System.Drawing.Size(370, 150)
		Height        = 150
	}
    
	[void] $listBox.Items.AddRange($permissions)
    
	$SScreen = New-Object system.Windows.Forms.Form -Property @{
		Width           = 400
		Height          = 300
		TopMost         = $true
		StartPosition   = 1
		FormBorderStyle = 5
		BackColor       = [System.Drawing.Color]::White
		AcceptButton    = $OKButton
		CancelButton    = $CancelButton        
	}    

	$SScreen.Controls.AddRange(@($OKButton, $CancelButton, $label, $listBox))   
    
	# All permissions are selected by default
	for ($i = 0; $i -lt $listBox.Items.Count; $i++) {
		$listBox.SetSelected($i, $true)
	}    

	$result = $SScreen.ShowDialog()
    
	if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
		return $listBox.SelectedItems        
	}
	else {
		return $null
	}
}

# Function to parse datetime string with different cultures
function Convert-ToDateTime {
	param (
		[string[]]$dateStrings
	)

	# List of cultures to test
	$cultures = @('en-US', 'en-GB', 'fr-FR', 'de-DE', 'es-ES', 'en-IN')
	$results = @()

	if (-Not $dateStrings) {
		return $null
	}

	foreach ($dateString in $dateStrings) {
		if ([string]::IsNullOrEmpty($dateString)) {
			$results += $null
			continue
		}

		$parsed = $null
		foreach ($culture in $cultures) {
			try {
				$cultureInfo = [System.Globalization.CultureInfo]::GetCultureInfo($culture)
				$parsed = [datetime]::Parse($dateString, $cultureInfo)
				break
			}
			catch {
				# Continue to the next culture if parsing fails
				continue
			}
		}

		if (-NOT $parsed) {
			throw "Unable to parse date string: $dateString"
		}

		$results += $parsed.ToString("dd-MM-yyyy HH:mm:ss")
	}

	return $results
}

$logpath = "c:\temp\EntraIDIntuneReport_$(get-date -Uformat "%Y%m%d-%H%M%S").txt"

#Import PowerShell Module, install if not already installed
if (get-module -List Microsoft.Graph.Authentication) {
	Import-Module Microsoft.Graph.Authentication
}
Else {
	Write-Output "Installing the module Microsoft.Graph.Authentication as current user scope"
	try {
		Set-PSRepository PSGallery -InstallationPolicy Trusted
		Install-Module -Name Microsoft.graph.authentication -Scope CurrentUser 	-Confirm:$False -Force	
	}
	catch {
		Write-Output "Could not load the necessary module Microsoft.Graph.Authentication, so can not proceed."
		exit
	}	
}

$message = "Modules check done"
Write-Log -logtext $message -logpath $logpath
New-BaloonNotification -title "Information" -message $message

# Output formating options
$logopath = "https://atos.net/content/assets/global-images/atos-logo-blue-2023.svg"
$ReportPath = "c:\temp\EntraIDIntuneReport_$(get-date -Uformat "%Y%m%d-%H%M%S").html"
$CopyRightInfo = " @Copyright Nitish Kumar <a href='https://github.com/laymanstake'>Visit nitishkumar.net</a>"

# CSS codes to format the report
$header = @"
<style>    
	body { background-color: #D3D3D3; }
    h1 { font-family: Arial, Helvetica, sans-serif; color: #e68a00; font-size: 28px; }    
    h2 { font-family: Arial, Helvetica, sans-serif; color: #000099; font-size: 16px; }    
    table { font-size: 12px; border: 1px;  font-family: Arial, Helvetica, sans-serif; } 	
    td { padding: 4px; margin: 0px; border: 1; }	
    th { background: #395870; background: linear-gradient(#49708f, #293f50); color: #fff; font-size: 11px; text-transform: uppercase; padding: 10px 15px; vertical-align: middle; }
    tbody tr:nth-child(even) { background: #f0f0f2; }
    CreationDate { font-family: Arial, Helvetica, sans-serif; color: #ff3300; font-size: 12px; }
</style>
"@

If ($logopath) {
	$header = $header + "<img src=$logopath alt='Company logo' width='150' height='150' align='right'>"
}

<#
	# Need to run below if you wish remove ALL user consented delegated permissions from the Microsoft Graph Command Line Tools enterprise application	
	connect-mggraph -Scopes Directory.ReadWrite.All
	$PrincipalId = (invoke-mggraphrequest -uri "https://graph.microsoft.com/v1.0/me?`$select=id").id
	$sp = (invoke-mggraphrequest -uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$search=`"displayName:Microsoft Graph Command Line Tools`"`&`$select=id,displayName" -Headers @{ "ConsistencyLevel" = "eventual" }).value
	$oAuthgrants = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientid eq '$($sp.id)'and PrincipalId eq '$($PrincipalId)'").value
	invoke-mggraphrequest -method DELETE -uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($oAuthgrants.id)"
#>

$requiredscopes = @(
	"IdentityProvider.Read.All", # Required for reading configured identity providers
	"Directory.Read.All", # Required for reading licenses, organization settings, roles
	"OnPremDirectorySynchronization.Read.All", # Required for on-prem directory synchronization settings
	"Application.Read.All", # Required for reading enabled directory extensions
	"RoleManagement.Read.All" # Required for reading Piviledged and RBAC roles
	"AccessReview.Read.All", # Required for reading access review settings
	"Policy.Read.All", # Required for reading conditional access policy details
	"SecurityEvents.Read.All", # Required for reading Identity security score details
	"Directory.ReadWrite.All", # Required for reading Pass Through authenication agent details
	"Policy.ReadWrite.AuthenticationMethod" # Required for reading authentication method details
) # Enterprise Application named Microsoft Graph Command Line Tools would be granted delegated permissions

$message = "opt out screen though all permissions are required for full report"
Write-Log -logtext $message -logpath $logpath

#$selectscopes = Get-PermSelection -permissions @('IdentityProvider.Read.All', 'Directory.Read.All', 'OnPremDirectorySynchronization.Read.All', 'Application.Read.All', 'RoleManagement.Read.All', 'AccessReview.Read.All', 'Policy.Read.All', 'SecurityEvents.Read.All', 'Organization.Read.All', 'Policy.ReadWrite.AuthenticationMethod')
$selectscopes = ('Directory.Read.All', 'OnPremDirectorySynchronization.Read.All', 'Organization.Read.All')

if ($selectscopes) {
	$requiredscopes = $selectscopes
}

if (Get-MgContext) {	
	# Disconnect current connection before starting
	try {
		$null = Disconnect-MGGraph		
		Connect-MGGraph -NoWelcome -scopes $requiredscopes -ErrorAction Stop
	}
	catch {		
		$message = "MS Graph login: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath			
		Write-Output "Unable to login to Graph Command Line Tools 1"
	}

}
else {
	# Connect with tenant if no existing connection
	try {
		Write-Host "No starting connection"
		Connect-MGGraph -NoWelcome -scopes $requiredscopes -ErrorAction Stop		
	}
	catch {	
		$message = "MS Graph login: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath			
		Write-Output "Unable to login to Graph Command Line Tools"
		exit
	}
}

$ConnectionDetail = Get-MgContext | Select-Object Account, TenantId, Environment, Scopes

$message = "Microsoft Graph connection done"
Write-Log -logtext $message -logpath $logpath
New-BaloonNotification -title "Information" -message $message

$IntuneStatus = "Not available"

if ($ConnectionDetail.scopes -contains "Directory.Read.All" -OR $ConnectionDetail.scopes -contains "Directory.ReadWrite.All") {
	try {
		$response = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/subscribedSkus?`$select=skuPartNumber,servicePlans,consumedUnits,prepaidUnits"		
		$skuAlreadyCountedForIntune = $false

		foreach ($sku in $response.value) {
			foreach ($plan in $sku.servicePlans) {
				if ($plan.servicePlanName -match 'intune' -and $plan.provisioningStatus -eq "Success") {
					if (-not $skuAlreadyCountedForIntune) {
                		if ($sku.prepaidUnits.enabled -gt 0) {
                    		$totalIntuneLicensesAvailable += $sku.prepaidUnits.enabled
						}
                		if ($sku.consumedUnits) {
                    		$totalIntuneLicensesConsumed += $sku.consumedUnits
                		}
                		$skuAlreadyCountedForIntune = $true
            		}
					break
				}
			}
		}		

		if ($totalIntuneLicensesAvailable.Count -gt 0) {
			$IntuneStatus = "Enabled"			
		} else {
			$IntuneStatus = "Not availalble"
		}

	}
	catch {
		$message = "Intune status check: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}

	$ServicePlans = ($response.value | Where-Object {$_.servicePlans.provisioningStatus -eq "Success"}).servicePlans.servicePlanName

	If ($ServicePlans -contains "AAD_Premium_P2") {
		$EntraLicense = "Entra ID P2"
	}
	elseif ($ServicePlans -contains "AAD_Premium") {
		$EntraLicense = "Entra ID P1"
	}
	else {
		$EntraLicense = "Entra ID Free"
	}
}

# Capturing tenant basic details
$TenantBasicDetail = (invoke-MgGraphRequest -uri "https://graph.microsoft.com/v1.0/organization?`$select=VerifiedDomains,createdDateTime,displayName,countryLetterCode,id,onPremisesSyncEnabled,onPremisesLastSyncDateTime,tenantType").value | ForEach-Object{[pscustomobject]@{DisplayName=$_.displayName;createdDateTime=$_.createdDateTime;countryLetterCode=$_.countryLetterCode;TenantID=$_.Id;OnPremisesSyncEnabled=$_.OnPremisesSyncEnabled;OnPremisesLastSyncDateTime=$_.OnPremisesLastSyncDateTime;TenantType=$_.TenantType;IntuneStatus=$IntuneStatus;EntraLicense=$EntraLicense;MDMAuthority=(Invoke-MgGraphRequest -uri "https://graph.microsoft.com/v1.0/organization/$($_.id)?`$select=mobileDeviceManagementAuthority")["mobileDeviceManagementAuthority"];Domain=(($_.VerifiedDomains ) | ForEach-Object { "$($_.Type):$($_.Name)" } ) -join "`n";SecurityDefaults=(Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/policies/identitySecurityDefaultsEnforcementPolicy")["isEnabled"];deviceInactivityBeforeRetirementInDays = (invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDeviceCleanupSettings").deviceInactivityBeforeRetirementInDays }}

# Capture all role definitions
$uri = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions?`$top=999"
$RoleDefs = @()
$details = @()
$RoleDefSummary = @()

do {
		$response = Invoke-MgGraphRequest -Uri $uri
		$details = $response.value | ForEach-Object {[pscustomobject]$_}
		$RoleDefs += $details
		$uri = $response.'@odata.nextLink'		
	} while ($uri)

ForEach($roleDef in $RoleDefs){
	$RoleAssignments = @()
	$details = @()

	do {
		$response = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions/$($roleDef.id)/roleAssignments?`$top=999"
		$details = $response.value | ForEach-Object {[pscustomobject]$_} | Select-Object id, displayName, description
		$RoleAssignments += $details
		$uri = $response.'@odata.nextLink'		
	} while ($uri)
	
	If($RoleAssignments){
		ForEach($RoleAssignment in $RoleAssignments){
			$details = @()
			$response = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/roleAssignments('$($RoleAssignment.id)')?`$expand=microsoft.graph.deviceAndAppManagementRoleAssignment/roleScopeTags&`$select=scopeType,scopeMembers,members?`$top=999"
			$details = $response | ForEach-Object {[pscustomobject]$_} | Select-Object scopeType,scopeMembers,@{l="members";e={($_.members | ForEach-Object{Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/groups/$($_)"}).displayName -join "`n"}}

			$RoleDefSummary += [PSCustomObject]@{
				RoleName = $roleDef.displayName
				RoleDescription = $roleDef.Description
				RoleAssignmentName = $RoleAssignment.displayName
				RoleAssignmentDescription = $RoleAssignment.Description
				RoleAssignmentScopeType = $details.scopeType
				RoleAssignmentScopeMembers = $details.scopeMembers -join "`n"
				RoleAssignmentMembers = $details.Members
			}
		}
	} else {
		$RoleDefSummary += [PSCustomObject]@{
				RoleName = $roleDef.displayName
				RoleDescription = $roleDef.Description
				RoleAssignmentName = ""
				RoleAssignmentDescription = ""
				RoleAssignmentScopeType = ""
				RoleAssignmentScopeMembers = ""
				RoleAssignmentMembers = ""
			}
	}
}

# Capture device details
$uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$top=999"
$devices = @()
$details = @()

do {
		$response = Invoke-MgGraphRequest -Uri $uri
		$details = $response.value
		$devices += $details
		$uri = $response.'@odata.nextLink'
		
	} while ($uri)

$devices = $devices | ForEach-Object {[pscustomobject]$_} 
$deviceSummary = [PSCustomObject]($devices | Group-Object OperatingSystem | Select-Object Name, Count | Where-Object Name | ForEach-Object -Begin {$obj = [ordered]@{}} -Process {$obj.$($_.Name) = $_.Count} -End {$obj})

# Capture configuration profiles
$allConfigurationProfiles = @()
$details = @()
$endpointsToQuery = @(
    "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations",    
    "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations",
	"https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
)

foreach ($endpoint in $endpointsToQuery) {
	$Uri = $endpoint
	do {
		$response = Invoke-MgGraphRequest -Uri $uri
		if($endpoint -like "*configurationPolicies") {
			$details = $response.value | ForEach-Object {[pscustomobject]$_} | Select-Object id, @{l='DisplayName';e={$_.Name}}, description, createdDateTime
		}
		else {
			$details = $response.value | ForEach-Object {[pscustomobject]$_} | Select-Object id, displayName, description, createdDateTime
		}		
		$allConfigurationProfiles += $details | Select-Object DisplayName, description, createdDateTime
		$uri = $response.'@odata.nextLink'		
	} while ($uri)
}

# Capture device management scripts
$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts?`$top=999&`$select=displayName,description,runAsAccount,fileName,createdDateTime,lastModifiedDateTime"
$deviceConfigScripts = @()
$details = @()

do {
		$response = Invoke-MgGraphRequest -Uri $uri
		$details = $response.value
		$deviceConfigScripts += $details
		$uri = $response.'@odata.nextLink'
		
	} while ($uri)


# Capture Windows feature updates
$uri = "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles?`$top=200"
$WindowsFeatureUpdates = @()
$WindowsFeatureUpdateSummary = @()
$details = @()

do {
		$response = Invoke-MgGraphRequest -Uri $uri
		$details = $response.value | ForEach-Object {[PSCustomObject]$_} | Select-Object id, displayName, description, createdDateTime, endOfSupportDate, featureUpdateVersion, installLatestWindows10OnWindows11IneligibleDevice, installFeatureUpdatesOptional
		$WindowsFeatureUpdates += $details
		$uri = $response.'@odata.nextLink'
		
	} while ($uri)

ForEach($WindowsFeatureUpdate in $WindowsFeatureUpdates){
	$asisgnments = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles('$($WindowsFeatureUpdate.id)')/assignments").value.target | ForEach-Object {[pscustomobject]$_}
	$assigned = ($asisgnments | Where-Object {$_.'@odata.type' -eq "#microsoft.graph.groupAssignmentTarget"}).groupid
	$exclusion = ($asisgnments | Where-Object {$_.'@odata.type' -eq "#microsoft.graph.exclusionGroupAssignmentTarget"}).groupid

	$WindowsFeatureUpdateSummary += [PSCustomObject]@{
		displayName = $WindowsFeatureUpdate.displayName
		Description = $WindowsFeatureUpdate.description
		createddateTime = $WindowsFeatureUpdate.createdDateTime
		endOfSupportDate = $WindowsFeatureUpdate.endOfSupportDate
		featureUpdateVersion = $WindowsFeatureUpdate.featureUpdateVersion
		installLatestWindows10OnWindows11IneligibleDevice = $WindowsFeatureUpdate.installLatestWindows10OnWindows11IneligibleDevice
		installFeatureUpdatesOptional = $WindowsFeatureUpdate.installFeatureUpdatesOptional
		assignedGroup = if ($assigned) { ($assigned | ForEach-Object {Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/groups/$($_)?`$select=displayName"}).displayName -join "`n" } else { "No Assigned groups" }
		excludedGroup = if ($exclusion) { ($exclusion | ForEach-Object {Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/groups/$($_)?`$select=displayName"}).displayName -join "`n" } else { "No Excluded groups" }
	}
}

# Capture Windows update rings
$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')&`$expand=groupAssignments,assignments"
$WindowsUpdateRings = @()
$WindowsUpdateRingSummary = @()
$details = @()

do {
		$response = Invoke-MgGraphRequest -Uri $uri
		$details = $response.value | ForEach-Object {[PSCustomObject]$_} | Select-Object id, Displayname, Description, qualityUpdatesPaused, featureUpdatesPaused, qualityUpdatesDeferralPeriodInDays, featureUpdatesDeferralPeriodInDays, deadlineGracePeriodInDays, driversExcluded, allowWindows11Upgrade, postponeRebootUntilAfterDeadline, microsoftUpdateServiceAllowed
		$WindowsUpdateRings += $details
		$uri = $response.'@odata.nextLink'
		
	} while ($uri)

ForEach($WindowsUpdateRing in $WindowsUpdateRings){
	$asisgnments = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$($WindowsUpdateRing.id)')/assignments").value.target | ForEach-Object {[pscustomobject]$_}
	$assigned = ($asisgnments | Where-Object {$_.'@odata.type' -eq "#microsoft.graph.groupAssignmentTarget"}).groupid
	$exclusion = ($asisgnments | Where-Object {$_.'@odata.type' -eq "#microsoft.graph.exclusionGroupAssignmentTarget"}).groupid

	$WindowsUpdateRingSummary += [PSCustomObject]@{
		displayName = $WindowsUpdateRing.displayName
		Description = $WindowsUpdateRing.description
		qualityUpdatesPaused = $WindowsUpdateRing.qualityUpdatesPaused
		featureUpdatesPaused = $WindowsUpdateRing.featureUpdatesPaused
		qualityUpdatesDeferralPeriodInDays = $WindowsUpdateRing.qualityUpdatesDeferralPeriodInDays
		featureUpdatesDeferralPeriodInDays = $WindowsUpdateRing.featureUpdatesDeferralPeriodInDays
		deadlineGracePeriodInDays = $WindowsUpdateRing.deadlineGracePeriodInDays
		driversExcluded = $WindowsUpdateRing.driversExcluded
		allowWindows11Upgrade = $WindowsUpdateRing.allowWindows11Upgrade
		postponeRebootUntilAfterDeadline = $WindowsUpdateRing.postponeRebootUntilAfterDeadline
		OtherMSProductsAllowed = $WindowsUpdateRing.microsoftUpdateServiceAllowed
		assignedGroup = if ($assigned) { ($assigned | ForEach-Object {Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/groups/$($_)?`$select=displayName"}).displayName -join "`n" } else { "No Assigned groups" }
		excludedGroup = if ($exclusion) { ($exclusion | ForEach-Object {Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/groups/$($_)?`$select=displayName"}).displayName -join "`n" } else { "No Excluded groups" }
	}
}

# Capture conditional access policies
$Uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$top=999"
$CASPolicyDetail = @()
$details = @()
do {
		$response = Invoke-MgGraphRequest -Uri $uri
		$details = $response.value | ForEach-Object {[PSCustomObject]$_} | Select-Object DisplayName, state, createdDateTime, modifiedDateTime, @{l="Locations";e={$_.conditions.locations.includeLocations -join "`n"}}, @{l="Platforms";e={$_.conditions.platforms.includeplatforms -join "`n"}}, @{l="ClientAppTypes";e={$_.conditions.clientAppTypes -join "`n"}}
		$CASPolicyDetail += $details
		$uri = $response.'@odata.nextLink'
		
	} while ($uri)

$CASPolicyDetail = $details | Select-Object DisplayName, state, createdDateTime, modifiedDateTime, locations, platforms, clientAppTypes

# Capture deployed apps details
$Uri = "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps?`$top=999"
$deployedApps = @()
$details = @()
do {
		$response = Invoke-MgGraphRequest -Uri $uri
		$details = $response.value | ForEach-Object {[PSCustomObject]$_}
		$deployedApps += $details
		$uri = $response.'@odata.nextLink'
		
	} while ($uri)

$deployedApps = $deployedApps | Select-Object displayName, description, publisher, publishingState, applicableArchitectures, setupFilePath, createdDateTime

# Capture App protection policies

# Capture iOS App protection policies
$Uri = "https://graph.microsoft.com/v1.0/deviceAppManagement/iosManagedAppProtections?`$top=999"
$AppProtectionPolicies = @()
$details = @()
do {
		$response = Invoke-MgGraphRequest -Uri $uri
		$details = $response.value | ForEach-Object {[PSCustomObject]$_}
		$AppProtectionPolicies += $details | Select-Object displayName, description, isAssigned, deviceComplianceRequired, deployedAppCount, allowedInboundDataTransferSources, allowedOutboundDataTransferDestinations, saveAsBlocked, minimumWarningOsVersion, allowedOutboundClipboardSharingLevel
		$uri = $response.'@odata.nextLink'
		
	} while ($uri)

# Capture Android App protection policies
$Uri = "https://graph.microsoft.com/v1.0/deviceAppManagement/androidManagedAppProtections?`$top=999"
$details = @()
do {
		$response = Invoke-MgGraphRequest -Uri $uri
		$details = $response.value | ForEach-Object {[PSCustomObject]$_}
		$AppProtectionPolicies += $details | Select-Object displayName, description, isAssigned, deviceComplianceRequired, deployedAppCount, allowedInboundDataTransferSources, allowedOutboundDataTransferDestinations, saveAsBlocked, minimumWarningOsVersion, allowedOutboundClipboardSharingLevel
		$uri = $response.'@odata.nextLink'
		
	} while ($uri)

# Capture App configuration policies
$Uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations?`$top=999&`$select=displayName,description,createdDateTime"
$AppConfigurationPolicies = @()
$details = @()
do {
		$response = Invoke-MgGraphRequest -Uri $uri
		$details = $response.value | ForEach-Object {[PSCustomObject]$_}  | Select-Object displayName, description, createdDateTime
		$AppConfigurationPolicies += $details
		$uri = $response.'@odata.nextLink'
		
	} while ($uri)

$Uri = "https://graph.microsoft.com/v1.0/deviceAppManagement/targetedManagedAppConfigurations?`$top=999&`$select=displayName,description,createdDateTime"
$details = @()
do {
		$response = Invoke-MgGraphRequest -Uri $uri
		$details = $response.value | ForEach-Object {[PSCustomObject]$_}| Select-Object displayName, description, createdDateTime
		$AppConfigurationPolicies += $details 
		$uri = $response.'@odata.nextLink'
		
	} while ($uri)

# Capture device compliance policies
$Uri = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies?`$top=999"
$DeviceCompliancePolicies = @()
$details = @()
do {
		$response = Invoke-MgGraphRequest -Uri $uri
		$details = $response.value | ForEach-Object {[PSCustomObject]$_} | Select-Object displayName, description, @{l="Type";e={($_.'@odata.type' -replace "#microsoft.graph.") -replace "CompliancePolicy"}}, createdDateTime
		$DeviceCompliancePolicies += $details 
		$uri = $response.'@odata.nextLink'		
	} while ($uri)

# Capture device compliance policy setting state summaries
$Uri = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicySettingStateSummaries?`$top=999"
$CompliancePolicySettingStateSummary = @()
$details = @()
do {
		$response = Invoke-MgGraphRequest -Uri $uri
		$details = $response.value | ForEach-Object {[PSCustomObject]$_} | select-object Settingname, PlatformType, CompliantDeviceCount, nonCompliantDeviceCount, notApplicableDeviceCount, errorDeviceCount, conflictDeviceCount, unknownDeviceCount, remediatedDeviceCount 
		$CompliancePolicySettingStateSummary += $details 
		$uri = $response.'@odata.nextLink'		
	} while ($uri)

#Capture Security Baseline Templates
$Uri = "https://graph.microsoft.com/beta/deviceManagement/templates?`$filter=(isof('microsoft.graph.securityBaselineTemplate'))&`$top=999"
$SeurityBaselineTemplates = @()
$details = @()
do {
		$response = Invoke-MgGraphRequest -Uri $uri
		$details = $response.value | ForEach-Object {[PSCustomObject]$_} | select-object displayName, description, publishedDateTime, templatetype, templateSubtype, isDeprecated
		$SeurityBaselineTemplates += $details 
		$uri = $response.'@odata.nextLink'		
	} while ($uri)

# Capture Device Enrollment Configurations
$Uri = "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations?`$top=999"
$DeviceEnrollmentConfigs = @()
$details = @()
do {
		$response = Invoke-MgGraphRequest -Uri $uri
		$details = $response.value | ForEach-Object {[PSCustomObject]$_} 
		$DeviceEnrollmentConfigs += $details | Where-Object {$_.deviceEnrollmentConfigurationType -eq 'windows10EnrollmentCompletionPageConfiguration'} | Select-Object DisplayName, Description,blockDeviceSetupRetryByUser, allowDeviceUseOnInstallFailure, installProgressTimeoutInMinutes, allowNonBlockingAppInstallation, installQualityUpdates, allowDeviceResetOnInstallFailure, disableUserStatusTrackingAfterFirstUser,showInstallationProgress,trackInstallProgressForAutopilotOnly,allowLogCollectionOnInstallFailure, @{l="MobileApps";e={$_.selectedMobileAppIds | ForEach-Object {(invoke-mggraphrequest -uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($_)?`$select=displayName").DisplayName -join ","}}}
		$WindowsHelloConfig += $details |Where-Object{$_.deviceEnrollmentConfigurationType -eq 'windowsHelloForBusiness'}| Select-Object DisplayName, Description,state,pinMinimumLength, pinMaximumLength, enhancedBiometricsState,enhancedSignInSecurity,unlockWithBiometricsEnabled,pinExpirationInDays,pinSpecialCharactersUsage
		$DeviceEnrollmentLimits += $details | Where-Object {$_.deviceEnrollmentConfigurationType -eq 'limit'} | Select-Object DisplayName, Description, limit
		$uri = $response.'@odata.nextLink'		
	} while ($uri)


$Uri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$top=999"
$AutoPilotdevices = @()
$details = @()
do {
		$response = Invoke-MgGraphRequest -Uri $uri
		$details = $response.value | ForEach-Object {[PSCustomObject]$_} 
		$AutoPilotdevices += $details 
		$uri = $response.'@odata.nextLink'		
	} while ($uri)

$AutoPilotdeviceSummary = [PSCustomObject]($AutoPilotdevices | Group-Object enrollmentstate | Select-Object Name, Count | Where-Object Name | ForEach-Object -Begin {$obj = [ordered]@{}} -Process {$obj.$($_.Name) = $_.Count} -End {$obj})

$message = "Creating HTML Report..."
Write-Log -logtext $message -logpath $logpath
New-BaloonNotification -title "Information" -message $message

# Create HTML table elements
if ($TenantBasicDetail) {
	$TenantSummary = ($TenantBasicDetail | ConvertTo-Html -As List -Fragment -PreContent "<h2>Intune Summary</h2>") -replace "`n", "<br>"
}

if($RoleDefSummary){
	$RoleDefSummary = ($RoleDefSummary | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Role Definition/Assignment Summary</h2>" ) -replace "`n", "<br>"
}

If($CASPolicyDetail){
	$CASPolicyDetail = ($CASPolicyDetail | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Conditional Access Policy Summary</h2>")  -replace "`n", "<br>"
}

if($deviceSummary){
	$deviceOSSummary = $deviceSummary | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Device Summary</h2>"
}

if ($allConfigurationProfiles) {
	$allConfigurationProfileSummary = ($allConfigurationProfiles | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Configuration Profiles</h2>")
}

if ($deviceConfigScripts) {
	$deviceConfigScriptSummary = $deviceConfigScripts | Select-Object displayName, fileName, description, runAsAccount, createdDateTime, lastModifiedDateTime | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Device Configuration Scripts Summary</h2>"
}

if ($deployedApps) {
	$deployedAppSummary = $deployedApps | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Deployed App Summary</h2>"
}

if ($AppProtectionPolicies) {
	$AppProtectionPolicySummary = $AppProtectionPolicies | ConvertTo-Html -As Table -Fragment -PreContent "<h2>App proection policy Summary</h2>"
}

if ($AppConfigurationPolicies) {
	$AppConfigPolicySummary = $AppConfigurationPolicies | ConvertTo-Html -As Table -Fragment -PreContent "<h2>App Configuration policy Summary</h2>"
}

if ($DeviceCompliancePolicies) {
	$DeviceCompliancePolicySummary = $DeviceCompliancePolicies | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Device Compliance policy Summary</h2>"
}

if ($CompliancePolicySettingStateSummary ) {
	$CompliancePolicySettingStateSummary  = $CompliancePolicySettingStateSummary  | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Device Compliance Policy Setting State Summary</h2>"
}

if ($SeurityBaselineTemplates ) {
	$SeurityBaselineTemplateSummary  = $SeurityBaselineTemplates  | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Security Baseline Template Summary</h2>"
}

if ($DeviceEnrollmentConfigs ) {
	$DeviceEnrollmentConfigSummary  = $DeviceEnrollmentConfigs  | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Device Enrollment Configuration Summary</h2>"
}

if ($DeviceEnrollmentLimits ) {
	$DeviceEnrollmentLimitSummary  = $DeviceEnrollmentLimits  | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Device Enrollment limits Summary</h2>"
}

if ($WindowsHelloConfig ) {
	$WindowsHelloConfigSummary  = $WindowsHelloConfig  | ConvertTo-Html -As List -Fragment -PreContent "<h2>Windows Hello for Business Configuration Summary</h2>"
}

if($AutoPilotdeviceSummary){
	$AutoPilotdeviceSummary = $AutoPilotdeviceSummary | ConvertTo-Html -As List -Fragment -PreContent "<h2>Autopilot Device Summary</h2>"
}

if($WindowsFeatureUpdateSummary){
	$WindowsFeatureUpdateSummary = $WindowsFeatureUpdateSummary | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Windows Feature Update Summary</h2>"
}

If($WindowsUpdateRingSummary){
	$WindowsUpdateRingSummary = $WindowsUpdateRingSummary | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Windows Update Ring Summary</h2>"
}

$ReportRaw = ConvertTo-HTML -Body "$TenantSummary $RoleDefSummary $CASPolicyDetail $deviceOSSummary $WindowsFeatureUpdateSummary $WindowsUpdateRingSummary $AutoPilotdeviceSummary $allConfigurationProfileSummary $deviceConfigScriptSummary $deployedAppSummary $AppProtectionPolicySummary $AppConfigPolicySummary $DeviceCompliancePolicySummary $CompliancePolicySettingStateSummary $SeurityBaselineTemplateSummary $DeviceEnrollmentConfigSummary $DeviceEnrollmentLimitSummary $WindowsHelloConfigSummary" -Head $header -Title "Report on Entra ID: $($TenantBasicDetail.Displayname)" -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date) $CopyRightInfo </p>"

# To preseve HTMLformatting in description
$ReportRaw = [System.Web.HttpUtility]::HtmlDecode($ReportRaw)

$ReportRaw | Out-File $ReportPath
Invoke-item $ReportPath
