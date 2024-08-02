<#  
    Author : Nitish Kumar (nitish@nitishkumar.net)
    Performs Entra ID Assessment
    version 1.0 | 17/07/2024 Initial version
    version 1.1 | 19/07/2024 Error handling improvements
    version 1.2 | 28/07/2024 Application details performance improvements

    Disclaimer: This script is designed to only read data from the entra id and should not cause any problems or change configurations but author do not claim to be responsible for any issues. Do due dilligence before running in the production environment
#>

<#
.SYNOPSIS
	Get-EntraIDDetails.ps1 - Perform Entra ID assessment and generate a HTML report.
.DESCRIPTION
	Script to get important details of Entra ID
.NOTES
	This would need a number of permissions, which would involve the Global admin permissions for the first time but all these permissions are READ permissions (except two) and would not make change in curnt configuration. The script is NOT using any POST or PATCH methods with API so it would not change anything in the environment
.LINK
	https://nitishkumar.net
.EXAMPLE
	.\Get-EntraIDDetails.ps1	
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
		SelectionMode = 'MultiExtended'
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

function Get-SensitiveApps {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, mandatory = $false)][array]$Sensitivepermissions = ("User.Read.All", "User.ReadWrite.All", "Mail.ReadWrite", "Files.ReadWrite.All", "Calendars.ReadWrite", "Mail.Send", "User.Export.All", "Directory.Read.All", "Exchange.ManageAsApp", "Directory.ReadWrite.All", "Sites.ReadWrite.All", "Application.ReadWrite.All", "Group.ReadWrite.All", "ServicePrincipalEndPoint.ReadWrite.All", "GroupMember.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All")
    )

    # Populate a set of hash tables with permissions used for different Office 365 management functions
    $GraphApp = (invoke-MgGraphRequest -uri "https://graph.microsoft.com/v1.0/serviceprincipals?`$filter=appid eq '00000003-0000-0000-c000-000000000000'").value
    $GraphRoles = @{}
    ForEach ($Role in $GraphApp.AppRoles) { $GraphRoles.Add([string]$Role.Id, [string]$Role.Value) }

    $ExoPermissions = @{}
    $ExoApp = (invoke-MgGraphRequest -uri "https://graph.microsoft.com/v1.0/serviceprincipals?`$filter=appid eq '00000002-0000-0ff1-ce00-000000000000'").value
    ForEach ($Role in $ExoApp.AppRoles) { $ExoPermissions.Add([string]$Role.Id, [string]$Role.Value) }

    $O365Permissions = @{}
    $O365API = (invoke-MgGraphRequest -uri "https://graph.microsoft.com/v1.0/serviceprincipals?`$filter=DisplayName eq 'Office 365 Management APIs'").value
    ForEach ($Role in $O365API.AppRoles) { $O365Permissions.Add([string]$Role.Id, [string]$Role.Value) }

    $AzureADPermissions = @{}
    $AzureAD = (invoke-MgGraphRequest -uri "https://graph.microsoft.com/v1.0/serviceprincipals?`$filter=DisplayName eq 'Windows Azure Active Directory'").value
    ForEach ($Role in $AzureAD.AppRoles) { $AzureADPermissions.Add([string]$Role.Id, [string]$Role.Value) }

    $TeamsPermissions = @{}
    $TeamsApp = (invoke-MgGraphRequest -uri "https://graph.microsoft.com/v1.0/serviceprincipals?`$filter=DisplayName eq 'Skype and Teams Tenant Admin API'").value
    ForEach ($Role in $TeamsApp.AppRoles) { $TeamsPermissions.Add([string]$Role.Id, [string]$Role.Value) }

    $RightsManagementPermissions = @{}
    $RightsManagementApp = (invoke-MgGraphRequest -uri "https://graph.microsoft.com/v1.0/serviceprincipals?`$filter=DisplayName eq 'Microsoft Rights Management Services'").value
    ForEach ($Role in $RightsManagementApp.AppRoles) { $RightsManagementPermissions.Add([string]$Role.Id, [string]$Role.Value) }

    $Appdetails = @()
    $sps = @()
    $managedidentities = @()
    $appcreds = @()
    $approles = @()

    $Sensitivepermissions = ("User.Read.All", "User.ReadWrite.All", "Mail.ReadWrite", "Files.ReadWrite.All", "Calendars.ReadWrite", "Mail.Send", "User.Export.All", "Directory.Read.All", "Exchange.ManageAsApp", "Directory.ReadWrite.All", "Sites.ReadWrite.All", "Application.ReadWrite.All", "Group.ReadWrite.All", "ServicePrincipalEndPoint.ReadWrite.All", "GroupMember.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All")

    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=tags/any(t:t+eq+'WindowsAzureActiveDirectoryIntegratedApp')&`$top=999&`$select=id,appid,displayname,createdDateTime,accountEnabled,servicePrincipalType,signInAudience,appRoleAssignmentRequired,appOwnerOrganizationId"
	
    do {
        $response = Invoke-MgGraphRequest -Uri $uri
        $apps = $response.value
        $SPs += $apps
        $uri = $response.'@odata.nextLink'
		
    } while ($uri)
		
    $Uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=ServicePrincipalType eq 'ManagedIdentity'&`$top=999&`$select=id,appid,displayname,createdDateTime,accountEnabled,servicePrincipalType,signInAudience,appRoleAssignmentRequired,appOwnerOrganizationId"
	
    do {
        $response = Invoke-MgGraphRequest -Uri $uri
        $apps = $response.value
        $managedidentities += $apps
        $uri = $response.'@odata.nextLink'
		
    } while ($uri)

    $AllApps = $SPs + $managedidentities

    $Uri = "https://graph.microsoft.com/v1.0/applications?`$select=appid,passwordCredentials,keycredentials&`$top=999"
    do {
        $response = Invoke-MgGraphRequest -Uri $uri
        $apps = $response.value
        $appcreds += $apps
        $uri = $response.'@odata.nextLink'
		
    } while ($uri)    

    $Uri = "https://graph.microsoft.com/v1.0/serviceprincipals?`$top=999&`$expand=appRoleAssignments&`$select=appId,appRoleAssignments"
    do {
        $response = Invoke-MgGraphRequest -Uri $uri
        $apps = $response.value
        $approles += $apps
        $uri = $response.'@odata.nextLink'		
    } while ($uri)    

    $i = 0
    $count = $AllApps.count

    ForEach ($app in $AllApps) {
        $i++        
        Write-Progress -Activity "Processing $($app.displayName)" -Status "$i of $count completed" -PercentComplete ($i * 100 / $count)        

        $Roles = $null			
        $Roles = $approles | Where-Object { $_.appid -eq $app.appid }

        [array]$Permission = $Null
        $spermissions = $null

        if (($Roles.count) -gt 0) {            
            ForEach ($Approle in $Roles.appRoleAssignments) {
                Switch ($AppRole.ResourceDisplayName) {
                    "Microsoft Graph" { 
                        $Permission += $GraphRoles[$AppRole.AppRoleId] 
                    }
                    "Office 365 Exchange Online" {
                        $Permission += $ExoPermissions[$AppRole.AppRoleId] 
                    }
                    "Office 365 Management APIs" {
                        $Permission += $O365Permissions[$AppRole.AppRoleId]
                    }
                    "Windows Azure Active Directory" {
                        $Permission += $AzureADPermissions[$AppRole.AppRoleId] 
                    }
                    "Skype and Teams Tenant Admin API" {
                        $Permission += $TeamsPermissions[$AppRole.AppRoleId] 
                    }
                    "Microsoft Rights Management Services" {
                        $Permission += $RightsManagementPermissions[$AppRole.AppRoleId] 
                    }
                }
            }            

            if ($Permission) {
                $spermissions = (compare-object -ReferenceObject ($Permission | Where-Object { $_ }) -DifferenceObject $Sensitivepermissions -IncludeEqual | Where-Object { $_.SideIndicator -eq "==" }).inputobject                
            }            
        }
        
        $secrets = @()        
        $secrets = $appcreds | Where-Object { $_.appid -eq $app.appid }
        $passwords = $secrets.passwordcredentials | ForEach-Object { [pscustomobject]@{displayname = $_.displayname; startdatetime = $_.startdatetime; enddatetime = $_.enddatetime } }
        $certs = $secrets.keycredentials | ForEach-Object { [pscustomobject]@{displayname = $_.displayname; startdatetime = $_.startdatetime; enddatetime = $_.enddatetime; usage = $_.usage; type = $_.type; customKeyIdentifier = $_.customKeyIdentifier } }
        
        $temp = [pscustomobject]@{
            id                        = $app.id
            displayName               = $app.displayName
            createdDateTime           = $app.createdDateTime
            enabled                   = $app.accountEnabled
            servicePrincipalType      = $app.servicePrincipalType
            permissions               = $permission -join ","
            sensitivepermissions      = $spermissions -join ","
            secretdisplayname         = $passwords.displayname -join ","
            secretstartdate           = $passwords.startdatetime -join ","
            secretenddate             = $passwords.enddatetime -join ","
            certdisplayname           = $certs.displayname -join ","
            certthumbprint            = $certs.customKeyIdentifier -join ","
            certstartdate             = $certs.startdatetime -join ","
            certenddate               = $certs.enddatetime -join ","
            certusage                 = $certs.usage -join ","
            certtype                  = $certs.type -join ","
            signInAudience            = $app.signInAudience
            appRoleAssignmentRequired = $app.appRoleAssignmentRequired
            appOwnerOrganizationId    = $app.appOwnerOrganizationId
        }

        
        $Appdetails += $temp			
    }

    return $Appdetails
}

$logpath = "c:\temp\EntraIDDReport_$(get-date -Uformat "%Y%m%d-%H%M%S").txt"

#Import PowerShell Module, install if not already installed
if (get-module -List Az.Accounts) {
	Import-Module Az.Accounts
}
Else {
	Write-Output "Installing the module Az.Accounts as current user scope"
	try {
		Set-PSRepository PSGallery -InstallationPolicy Trusted
		Install-Module -Name Az.Accounts -Scope CurrentUser -Confirm:$False -Force		
	}
	catch {
		Write-Output "Could not load the necessary module Az.Accounts, so can not proceed."
		exit
	}	
}

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
$logopath = "https://raw.githubusercontent.com/laymanstake/laymanstake/master/images/logo.png"
$ReportPath = "c:\temp\EntraIDReport_$(get-date -Uformat "%Y%m%d-%H%M%S").html"
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

$selectscopes = Get-PermSelection -permissions @('IdentityProvider.Read.All', 'Directory.Read.All', 'OnPremDirectorySynchronization.Read.All', 'Application.Read.All', 'RoleManagement.Read.All', 'AccessReview.Read.All', 'Policy.Read.All', 'SecurityEvents.Read.All', 'Directory.ReadWrite.All', 'Policy.ReadWrite.AuthenticationMethod')

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

$message = "Microsoft Graph connection done"
Write-Log -logtext $message -logpath $logpath
New-BaloonNotification -title "Information" -message $message

$ConnectionDetail = Get-MgContext | Select-Object Account, TenantId, Environment, Scopes

if ($ConnectionDetail.scopes -contains "Directory.Read.All" -OR $ConnectionDetail.scopes -contains "Directory.ReadWrite.All") {
	try {
		$ServicePlans = ((Invoke-mgGraphRequest -Uri "https://graph.microsoft.com/v1.0/subscribedSkus?`$select=skuPartNumber,skuId,prepaidUnits,consumedUnits,servicePlans").value | Where-Object { $_.ServicePlans.ProvisioningStatus -eq "Success" }).ServicePlans.ServicePlanName
	}
	catch {
		$message = "Service Plan details: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}

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

# Get app ID for Entra ID Connected registered app
if ($ConnectionDetail.scopes -contains "Directory.Read.All" -OR $ConnectionDetail.scopes -contains "Directory.ReadWrite.All" -OR $ConnectionDetail.scopes -contains "Application.Read.All") {
	try {
		$app = ((Invoke-MgGraphRequest -uri "https://graph.microsoft.com/v1.0/applications").value | Where-Object { $_.displayName -eq "Tenant Schema Extension App" }) | ForEach-Object { [pscustomobject]@{id = $_.id; appid = $_.appid } }
	}
	catch {
		$message = "Directory Extensions Details: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}

	if ($app) {
		try {
			$DirectoryExtensions = (invoke-mggraphrequest -uri "https://graph.microsoft.com/v1.0/applications/$($app.id)/extensionProperties?`$select=name").value.name | ForEach-Object { $_.replace("extension_" + $app.appid.replace("-", "") + "_", "") }
			$message = "Directory extensions identified: $($DirectoryExtensions -join ",")"
			Write-Log -logtext $message -logpath $logpath
		}
		catch {
			$message = "Directory Extensions Details: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
			Write-Log -logtext $message -logpath $logpath		
		}
	}	
}

# On-Premise configuration
if ($ConnectionDetail.scopes -contains "OnPremDirectorySynchronization.Read.All") {
	try {
		$OnPremConfigDetails = (Invoke-mgGraphRequest -Uri "https://graph.microsoft.com/v1.0/directory/onPremisesSynchronization").value.features | ForEach-Object { [pscustomobject]@{PasswordHashSync = $_.passwordSyncEnabled; passwordWritebackEnabled = $_.passwordWritebackEnabled; cloudPasswordPolicyForPasswordSyncedUsersEnabled = $_.cloudPasswordPolicyForPasswordSyncedUsersEnabled; userWritebackEnabled = $_.userWritebackEnabled; groupWriteBackEnabled = $_.groupWriteBackEnabled; deviceWritebackEnabled = $_.deviceWritebackEnabled; unifiedGroupWritebackEnabled = $_.unifiedGroupWritebackEnabled; directoryExtensionsEnabled = $_.directoryExtensionsEnabled; synchronizeUpnForManagedUsersEnabled = $_.synchronizeUpnForManagedUsersEnabled } }
	}
	catch {
		$message = "Onprem config Details: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}
	$PHSEnabled = $OnPremConfigDetails.PasswordHashSync
}
# Pass through authentication details
if ($ConnectionDetail.scopes -contains "Directory.ReadWrite.All") {
	try {
		$PTAAgentDetail = (Invoke-mgGraphRequest -Uri "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/authentication/agentGroups?`$expand=agents").value.Agents | ForEach-Object { [PSCustomObject]@{machinename = $_.machinename; externalIp = $_.externalIp; status = $_.status; supportedPublishingTypes = $_.supportedPublishingTypes -join "," } }
	}
	catch {
		$message = "PTA Agent Details: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}
	$PTAEnabled = $PTAAgentDetail.machinename.count -ge 1
}

if ($ConnectionDetail.scopes -contains "IdentityProvider.Read.All") {
	try {
		$IdentityProviders = (invoke-MgGraphRequest -uri "https://graph.microsoft.com/v1.0/identityProviders?`$select=name").value.values -join ","
	}
	catch {
		$message = "Identity Details: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}
}

if ($ConnectionDetail.scopes -contains "Policy.Read.All") {
	try {
		$SecurityDefaults = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/policies/identitySecurityDefaultsEnforcementPolicy")["isEnabled"]
	}
	catch {
		$message = "Security defaults: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}
}

if ($ConnectionDetail.scopes -contains "Directory.Read.All" -OR $ConnectionDetail.scopes -contains "Directory.ReadWrite.All") {
	try {
		$TenantBasicDetail = (Invoke-mgGraphRequest -Uri "https://graph.microsoft.com/v1.0/organization").value | ForEach-Object { [pscustomobject]@{DisplayName = $_.displayName; createdDateTime = $_.createdDateTime; countryLetterCode = $_.countryLetterCode; TenantID = $_.Id; OnPremisesSyncEnabled = $_.OnPremisesSyncEnabled; OnPremisesLastSyncDateTime = $_.OnPremisesLastSyncDateTime; TenantType = $_.TenantType; EntraID = $EntraLicense; Domain = (($_.VerifiedDomains | Where-Object { $_.Name -notlike "*.Onmicrosoft.com" }) | ForEach-Object { "$($_.Type):$($_.Name)" } ) -join "`n"; SecurityDefaults = $SecurityDefaults ; PTAEnbled = $PTAEnabled; PHSEnabled = $PHSEnabled; passwordWritebackEnabled = $OnPremConfigDetails.passwordWritebackEnabled; DirectoryExtensions = ($DirectoryExtensions -join ","); groupWriteBackEnabled = $OnPremConfigDetails.groupWriteBackEnabled; IdentityProviders = $IdentityProviders; cloudPasswordPolicyForPasswordSyncedUsersEnabled = $OnPremConfigDetails.cloudPasswordPolicyForPasswordSyncedUsersEnabled } }
		$message = "Tenant basic details done"
		Write-Log -logtext $message -logpath $logpath
	}
	catch {
		$message = "Tenant basic Details: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}
}

if ($TenantBasicDetail.OnPremisesSyncEnabled) {
	$message = "Connecting to Az module as OnPrem Sync is enabled"
	Write-Log -logtext $message -logpath $logpath
	New-BaloonNotification -title "Information" -message $message

	if (Get-AzAccessToken -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) {
		try {
			$null = Disconnect-AzAccount
			Connect-AzAccount -AccountId $ConnectionDetail.Account -TenantId $ConnectionDetail.TenantId -Scope CurrentUser -ErrorAction Stop -WarningAction Ignore
		}
		catch {
			$message = $Error[0].exception.message
			Write-Log -logtext $message -logpath $logpath
			Write-Output "Unable to login to Az Accounts"
		}
	}
	else {
		try {
			Connect-AzAccount -AccountId $ConnectionDetail.Account -TenantId $ConnectionDetail.TenantId -Scope CurrentUser -ErrorAction Stop  -WarningAction Ignore
		}
		catch {
			$message = $Error[0].exception.message
			Write-Log -logtext $message -logpath $logpath
			Write-Output "Unable to login to Az Accounts"
		}
	}

	# Keeping Az token for using later on
	$null = Update-AzConfig -DisplayBreakingChangeWarning $false 
	if ((get-module -List Az.Accounts).version.major -ge 3) {
		$encryptedToken = (Get-AzAccessToken -AsSecureString -ErrorAction Stop).token
		$azToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($encryptedToken))
	}
	else {
		$azToken = (Get-AzAccessToken -ErrorAction Stop).token
	}

	$message = "Connection to Az module completed."
	Write-Log -logtext $message -logpath $logpath
	
	# Find latest available Entra ID connect version
	try {
		$VersionHistory = Invoke-RestMethod "https://raw.githubusercontent.com/MicrosoftDocs/entra-docs/main/docs/identity/hybrid/connect/reference-connect-version-history.md"
	}
	catch {
		$message = $error[0].exception.message
		Write-Log -logtext $message -logpath $logpath		
	}

	$LatestVersion = $VersionHistory -split "`n" | Where-Object { $_ -match "^## [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" } | ForEach-Object { $_ -replace "## " } | Sort-Object | Select-Object -Last 1
	if ($LatestVersion -notmatch "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$") {
		Write-Output "Unable to determine latest version of Azure AD Connect"
	}
	$LatestVersion = $LatestVersion.ToString()

	$message = "Latest version for Entra ID connect found from GitHub as $LatestVersion."
	Write-Log -logtext $message -logpath $logpath
	
	# Check if the Azure API to for Entra ID connect health accessible
	try {
		$PremiumCheck = Invoke-RestMethod -Uri 'https://management.azure.com/providers/Microsoft.ADHybridHealthService/services/GetServices/PremiumCheck?serviceType=AadSyncService&skipCount=0&takeCount=50&api-version=2014-01-01' -Headers @{'Authorization' = "Bearer $azToken" }
	}
	catch {
		$message = "API accessibility: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}

	if ($PremiumCheck.PSObject.Properties.Count -ge 1) {
		try {
			$EntraIDConnectDetails = (Invoke-RestMethod -Uri "https://management.azure.com/providers/Microsoft.ADHybridHealthService/services/$($PremiumCheck.value[0].serviceName)/servicemembers?api-version=2014-01-01" -Headers @{'Authorization' = "Bearer $azToken" }).value | ForEach-Object { [pscustomobject]@{machinename = $_.machinename; Enabled = -Not($_.disabled); version = (Invoke-RestMethod -Uri "https://management.azure.com/providers/Microsoft.ADHybridHealthService/services/$($PremiumCheck.value[0].serviceName)/servicemembers/$($_.serviceMemberId)/serviceconfiguration?api-version=2014-01-01" -Headers @{'Authorization' = "Bearer $azToken" }).version; LatestVersionAvailable = $LatestVersion; staging = ($_.monitoringConfigurationsComputed | Where-Object { $_.key -eq "StagingMode" }).value; createdDate = [DateTime]::Parse($_.createdDate).ToString("yyyy-MM-dd HH:mm:ss"); lastReboot = [DateTime]::Parse($_.lastreboot).ToString("yyyy-MM-dd HH:mm:ss"); OsName = $_.Osname } }
			$message = "Entra ID connect servers found: $(if($EntraIDConnectDetails){$EntraIDConnectDetails.machinename -join ","})."
			Write-Log -logtext $message -logpath $logpath
			New-BaloonNotification -title "Information" -message $message
		}
		catch {
			$message = "Entra ID connect Details: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
			Write-Log -logtext $message -logpath $logpath		
		}
	}
}

if ($EntraLicense -ne "Entra ID Free") {
	# Password protection details	
	if ($ConnectionDetail.scopes -contains "Directory.Read.All" -OR $ConnectionDetail.scopes -contains "Directory.ReadWrite.All") {
		$PasswordProtectionDetails = [PSCustomObject]@{}
		try {
			((Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groupSettings").value | Where-Object { $_.displayName -eq "Password Rule Settings" }).values | Where-Object { $_ } | ForEach-Object { $PasswordProtectionDetails | Add-Member -NotePropertyName $_.Name -NotePropertyValue (($_.value -split "\t") -join "`n") }
			$message = "Entra ID password protection details done."
			Write-Log -logtext $message -logpath $logpath
		}
		catch {
			$message = "Entra ID password protection Details: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
			Write-Log -logtext $message -logpath $logpath		
		}		
	}
}
if ($ConnectionDetail.scopes -contains "Policy.ReadWrite.AuthenticationMethod") {
	try {
		$EnabledAuthMethods = (Invoke-mgGraphRequest -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy").authenticationMethodConfigurations | ForEach-Object { [pscustomobject]@{AuthMethodType = $_.Id; State = $_.state } }
	}
	catch {
		$message = "Entra ID enabled auth methods Details: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}
}

if ($ConnectionDetail.scopes -contains "Directory.Read.All" -OR $ConnectionDetail.scopes -contains "Directory.ReadWrite.All" -OR $ConnectionDetail.scopes -contains "RoleManagement.Read.All") {
	$MonitoredPriviledgedRoles = ("Global Administrator", "Global Reader", "Security Administrator", "Privileged Authentication Administrator", "User Administrator")
	try {
		$ActivatedRoles = (Invoke-mgGraphRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles").value | ForEach-Object { [pscustomobject]@{Id = $_.Id; DisplayName = $_.displayName } }
	}
	catch {
		$message = "Entra ID activated role Details: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}

	$RoleDetail = ForEach ($privilegedRole in $MonitoredPriviledgedRoles) {	
		$RoleID = ($ActivatedRoles | Where-Object { $_.DisplayName -eq $privilegedRole }).Id	
		If ($privilegedRole -in $ActivatedRoles.DisplayName) {
			$name = $privilegedRole
			try {
				$Count = (Invoke-mgGraphRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$RoleID/members" -Headers @{ "ConsistencyLevel" = "eventual" }).value.displayname.count
			}
			catch {
				$message = "Entra ID priviledged role Details: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
				Write-Log -logtext $message -logpath $logpath		
			}		
		}
		else {
			$name = $privilegedRole
			$count = "Role not activated"
		}

		[PSCustomObject]@{		
			Name  = $Name
			Count = $Count
		}
	}

	$message = "Entra ID admin roles details done."
	Write-Log -logtext $message -logpath $logpath

	# RBAC roles details
	try {
		$Roles = ((Invoke-mggraphRequest -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions").value | ForEach-Object { [pscustomobject]@{id = $_.id; isBuiltIn = $_.isBuiltIn; displayName = $_.displayName; Enabled = $_.isEnabled; rolePermissions = ($_.rolePermissions.allowedResourceActions -join "`n") } })
		$RBACRoles = $Roles | Where-Object { $_.isBuiltIn -eq $false }
		$message = "Entra ID RBAC roles details done."
		Write-Log -logtext $message -logpath $logpath
	}
	catch {
		$message = "Entra ID RBAC role Details: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}	
}

if ($EntraLicense -ne "Entra ID Free" -AND $ConnectionDetail.scopes -contains "RoleManagement.Read.All") {
	# PIM Roles
	try {
		$ActivePIMAssignments = (invoke-mggraphRequest -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules?`$expand=principal").value | ForEach-Object { $roledef = $_.RoleDefinitionId; [pscustomobject]@{RoleName = ($Roles | Where-Object { $_.id -eq $roledef }).displayName; PrincipalName = $_.Principal.displayName; PrincipalType = ($_.Principal."@odata.type").replace("`#microsoft.graph.", ""); state = $_.assignmenttype; membership = $_.memberType; StartTime = $_.scheduleInfo.StartDateTime; EndTime = $_.scheduleInfo.expiration.enddatetime; type = $_.scheduleInfo.expiration.type; directoryScopeId = $_.directoryScopeId } } 
	}
	catch {
		$message = "Entra ID active PIM assignment Details: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}

	try {
		$ElligiblePIMAssignments = (invoke-mggraphRequest -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$expand=principal").value | ForEach-Object { $roledef = $_.RoleDefinitionId; [pscustomobject]@{RoleName = ($Roles | Where-Object { $_.id -eq $roledef }).displayName; PrincipalName = $_.Principal.displayName; PrincipalType = ($_.Principal."@odata.type").replace("`#microsoft.graph.", ""); state = $_.assignmenttype; membership = $_.memberType; StartTime = $_.scheduleInfo.StartDateTime; EndTime = $_.scheduleInfo.expiration.enddatetime; type = $_.scheduleInfo.expiration.type; directoryScopeId = $_.directoryScopeId } } 
	}
	catch {
		$message = "Entra ID elligible PIM assignment Details: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}

	$PIMRoles = $ActivePIMAssignments + $ElligiblePIMAssignments

	$message = "Entra ID Priviledged identity management details done."
	Write-Log -logtext $message -logpath $logpath
}

if ($EntraLicense -eq "Entra ID P2" -AND $ConnectionDetail.scopes -contains "AccessReview.Read.All") {
	try {
		$Accessreviews = (invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions").value | ForEach-Object { [pscustomobject]@{AccessReviewName = $_.displayName; status = $_.status; scope = if ($_.instanceEnumerationScope.query) { (invoke-mggraphrequest -uri $_.instanceEnumerationScope.query).displayName -join "," } else { (Invoke-MgGraphRequest -uri $_.scope.resourceScopes.query).DisplayName -join "," }; createdDateTime = $_.createdDateTime; lastModifiedDateTime = $_.lastModifiedDateTime; descriptionForReviewers = $_.descriptionForReviewers; descriptionForAdmins = $_.descriptionForAdmins } }
		$message = "Entra ID access review details done."
		Write-Log -logtext $message -logpath $logpath
	}
	catch {
		$message = "Entra ID access review Details: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}	
}

if ($ConnectionDetail.scopes -contains "Directory.Read.All" -OR $ConnectionDetail.scopes -contains "Directory.ReadWrite.All") {
	# License summary 
	try {
		$LicenseDetail = (Invoke-mgGraphRequest -Uri "https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuPartNumber,skuId,prepaidUnits,consumedUnits,servicePlans").value | ForEach-Object { [pscustomobject]@{Skuid = $_.skuId; skuPartNumber = $_.skuPartNumber; activeUnits = $_.prepaidUnits["enabled"]; consumedUnits = $_.consumedUnits; availableUnits = ($_.prepaidUnits["enabled"] - $_.consumedUnits) } }
		$message = "License summary done."
		Write-Log -logtext $message -logpath $logpath
	}
	catch {
		$message = "Entra ID license summary: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}
}

if ($ConnectionDetail.scopes -contains "Policy.Read.All") {
	try {
		$CASPolicyDetail = (Invoke-mgGraphRequest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" ).value | ForEach-Object { [pscustomobject]@{DisplayName = $_.displayName; State = $_.state; createdDateTime = $_.createdDateTime; modifiedDateTime = $_.modifiedDateTime; locations = $_.conditions.locations.includeLocations -join "`n"; platforms = $_.conditions.platforms.includeplatforms -join "`n" ; clientapplicationtypes = $_.conditions.clientAppTypes -join "`n" } }
		$message = "Conditional access policies summary done."
		Write-Log -logtext $message -logpath $logpath
	}
	catch {
		$message = "Entra ID CAS policy summary: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}	

	try {
		$PasswordLessDetails = (invoke-MgGraphRequest -uri "https://graph.microsoft.com/beta/policies/authenticationmethodspolicy/authenticationMethodConfigurations/MicrosoftAuthenticator").includetargets | ForEach-Object { [pscustomobject]@{authenticationMode = if ($_.authenticationMode -eq "any" -OR $_.authenticationMode -eq "deviceBasedPush") { "Passwordless" } else { "Password Based" }; id = $_.id; isRegistrationRequired = $_.isRegistrationRequired; targetType = $_.targetType } }
		$message = "Passwordless Auth details summary done."
		Write-Log -logtext $message -logpath $logpath

	}
	catch {
		$message = "Entra ID passwordless config: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}
	
	# Collaberation settings
	try {
		$Collabsettings = (invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy") | ForEach-Object { [pscustomobject]@{AppRegistrationForAll = $_.defaultUserRolePermissions.allowedToCreateApps; allowedToReadOtherUsers = $_.defaultUserRolePermissions.allowedToReadOtherUsers; allowedToCreateSecurityGroups = $_.defaultUserRolePermissions.allowedToCreateSecurityGroups; AllowGuestInvitesFrom = $_.allowInvitesFrom; allowedToUseSSPR = $_.allowedToUseSSPR; allowEmailVerifiedUsersToJoinOrganization = $_.allowEmailVerifiedUsersToJoinOrganization; blockMsolPowerShell = $_.blockMsolPowerShell; allowedToCreateTenants = $_.defaultUserRolePermissions.allowedToCreateTenants } }
		$message = "Collaberation details summary done."
		Write-Log -logtext $message -logpath $logpath
	}
	catch {
		$message = "Entra ID collaberation details: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}	
}


if ($ConnectionDetail.scopes -contains "SecurityEvents.Read.All") {
	# Identtity Secure score recommendations
	try {
		$Controls = (invoke-mggraphRequest -Uri "https://graph.microsoft.com/v1.0/Security/secureScoreControlProfiles?`$filter=controlCategory eq 'Identity'").value | ForEach-Object { [pscustomobject]@{controlCategory = $_.controlCategory; id = $_.id; title = $_.title; service = $_.service; userImpact = $_.userImpact; threats = ($_.threats -join ","); actionType = $_.actionType; remediation = $_.remediation; maxScore = $_.maxScore; deprecated = $_.deprecated } }
	}
	catch {
		$message = "Entra ID secure score controls: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}

	try {
		$Scores = (invoke-mggraphRequest -Uri "https://graph.microsoft.com/v1.0/Security/secureScores").value | ForEach-Object { [pscustomobject]@{createdDateTime = $_.createdDateTime; currentScore = $_.currentScore; maxScore = $_.maxScore; controlScores = $_.controlScores; licensedUserCount = $_.licensedUserCount; activeUserCount = $_.activeUserCount } } 
	}
	catch {
		$message = "Entra ID secure score details: " + $error[0].exception.message + " : " + ($error[0].errordetails.message -split "`n")[0] 
		Write-Log -logtext $message -logpath $logpath		
	}

	$SecureScoreReport = @()

	if ($scores) {
		$latestScore = $scores[0] 
		foreach ($control in $latestScore.controlScores | Where-Object { $_.controlCategory -eq "Identity" }) {
			$controlProfile = $Controls | Where-Object { $_.id -contains $control.controlname }				
		
			$SecureScoreReport += [PSCustomObject]@{
				ControlCategory      = $control.ControlCategory
				Title                = $controlProfile.title
				description          = $control.description
				Threats              = $controlprofile.threats
				scoreInPercentage    = $control.scoreInPercentage
				Score                = "$([int]$control.score) / $([int]$controlProfile.maxScore)"
				UserImpact           = $controlProfile.userImpact
				actionType           = $controlProfile.actionType
				remediation          = $controlProfile.remediation			
				implementationStatus = $control.implementationStatus
				lastSynced           = $control.lastSynced
			}		
		}
	}
}

$threshold = 30 # number of days after which cert/secret would be expired
$apps = @()
$expiringsecrets = @()
$expiringcerts  = @()
$sensitiveapps = @()

if ($ConnectionDetail.scopes -contains "Directory.Read.All") {
	$apps = Get-SensitiveApps 

	$expiringsecrets = $apps | Where-Object { $_.secretenddate } | Where-Object { (($_.secretenddate -split "`n") | ForEach-Object { [datetime]$_ } | Measure-Object -Maximum).maximum -lt (get-date).Adddays($threshold) }
	$expiringcerts = $apps | Where-Object { $_.certenddate } | Where-Object { [datetime](($_.certenddate -split "`n") | ForEach-Object { [datetime]$_ } | Measure-Object -Maximum).maximum -lt (get-date).Adddays($threshold) }
	$sensitiveapps = $apps | Where-Object { $_.sensitivepermissions }
}

$message = "Creating HTML Report..."
Write-Log -logtext $message -logpath $logpath
New-BaloonNotification -title "Information" -message $message

# Create HTML table elements
if ($EnabledAuthMethods) {
	$EnabledAuthSummary = ($EnabledAuthMethods | Sort-Object State -Descending | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Auth Methods Summary : $($TenantBasicDetail.DisplayName)</h2>")
}

if ($RoleDetail) {
	$RoleSummary = ($RoleDetail | Sort-Object Count | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Priviledged Entra Role Summary: $($TenantBasicDetail.DisplayName)</h2>")
}

if ($TenantBasicDetail) {
	$TenantSummary = ($TenantBasicDetail | ConvertTo-Html -As List -Fragment -PreContent "<h2>Entra Summary: $forest</h2>") -replace "`n", "<br>"
}

if ($EntraIDConnectDetails) {
	$EntraIDConnectSummary = $EntraIDConnectDetails | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Entra ID connect agents Summary: $($TenantBasicDetail.DisplayName)</h2>"
}

if ($PTAEnabled) {
	$PTAAgentSummary = $PTAAgentDetail | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Pass through agents Summary: $($TenantBasicDetail.DisplayName)</h2>"
}

If ($RBACRoles) {
	$RBACRolesSummary = ($RBACRoles | ConvertTo-Html -As Table -Fragment -PreContent "<h2>RBAC Roles Summary: $($TenantBasicDetail.DisplayName)</h2>") -replace "`n", "<br>"
}

If ($PIMRoles) {
	$PIMRolesSummary = ($PIMRoles | Sort-Object RoleName, PrincipalType, type | ConvertTo-Html -As Table -Fragment -PreContent "<h2>PIM Roles Summary: $($TenantBasicDetail.DisplayName)</h2>") -replace "`n", "<br>"
}

if ($Accessreviews) {
	$AccessreviewSummary = ($Accessreviews | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Access Review Summary: $($TenantBasicDetail.DisplayName)</h2>") -replace "`n", "<br>"
}

if ($PasswordProtectionDetails.PSObject.Properties.Count -ge 1) {
	$PasswordProtectionSummary = ($PasswordProtectionDetails | ConvertTo-Html -As List -Fragment -PreContent "<h2>Password Protection Summary: $($TenantBasicDetail.DisplayName)</h2>") -replace "`n", "<br>"
}

if ($CASPolicyDetail) {
	$CASSummary = ($CASPolicyDetail | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Conditional Access Policy Summary: $($TenantBasicDetail.DisplayName)</h2>") -replace "`n", "<br>"
}

if ($PasswordLessDetails) {
	$PasswordLessSummary = $PasswordLessDetails | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Passwordless Auth mode Summary: $($TenantBasicDetail.DisplayName)</h2>"
}

If ($Collabsettings) {
	$CollabsettingsSummary = $Collabsettings | ConvertTo-Html -As List -Fragment -PreContent "<h2>Collaberation settings Summary: $($TenantBasicDetail.DisplayName)</h2>"
}

If ($LicenseDetail) {
	$LicenseSummary = $LicenseDetail | ConvertTo-Html -As Table -Fragment -PreContent "<h2>License Summary: $($TenantBasicDetail.DisplayName)</h2>"
}
If ($SecureScoreReport) {
	$SecureScoreReportSummary = $SecureScoreReport | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Identity - Secure Scores Summary: $($TenantBasicDetail.DisplayName)</h2>"
}

if ($expiringsecrets) {
	$expiringsecretSummary = ($expiringsecrets | select-object displayName, createdDateTime, enabled, servicePrincipalType, secretdisplayname, secretstartdate, secretenddate	 | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Apps - Expiring secrets Summary: $($TenantBasicDetail.DisplayName)</h2>")  -replace "`n", "<br>"
}

if ($expiringcerts) {
	$expiringcertSummary = ($expiringcerts | select-object displayName, createdDateTime, enabled, servicePrincipalType, certdisplayname, certthumbprint, certstartdate, certenddate, certusage, certtype | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Apps - Expiring certificate Summary: $($TenantBasicDetail.DisplayName)</h2>")  -replace "`n", "<br>"
}

if ($sensitiveapps) {
	$sensitiveappSummary = ($sensitiveapps | select-object displayName, createdDateTime, enabled, servicePrincipalType, permissions, sensitivepermissions | ConvertTo-Html -As Table -Fragment -PreContent "<h2>sensitive apps Summary: $($TenantBasicDetail.DisplayName)</h2>")  -replace "`n", "<br>"
}

$ReportRaw = ConvertTo-HTML -Body "$TenantSummary $CollabsettingsSummary $EntraIDConnectSummary $PasswordLessSummary $PTAAgentSummary $LicenseSummary $RoleSummary $RBACRolesSummary $PIMRolesSummary $AccessreviewSummary $PasswordProtectionSummary $EnabledAuthSummary $CASSummary $SecureScoreReportSummary $expiringsecretSummary $expiringcertSummary $sensitiveappsummary" -Head $header -Title "Report on Entra ID: $($TenantBasicDetail.Displayname)" -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date) $CopyRightInfo </p>"

# To preseve HTMLformatting in description
$ReportRaw = [System.Web.HttpUtility]::HtmlDecode($ReportRaw)

$ReportRaw | Out-File $ReportPath
Invoke-item $ReportPath
