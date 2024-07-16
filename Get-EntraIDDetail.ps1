<#
.SYNOPSIS
	Script to get important details of Entra ID
.DESCRIPTION
	Script to get important details of Entra ID
.NOTES
	This would need a number of permissions, which would involve the Global admin permissions for the first time but all these permissions are READ permissions and would not make change in curnt configuration
.LINK
	https://nitishkumar.net
.EXAMPLE
	Test-MyTestFunction -Verbose
	
#>

#Import PowerShell Module, install if not already installed
if (get-module -List Microsoft.Graph.Authentication) {
	Import-Module Microsoft.Graph.Authentication
}
Else {
	Write-Output "Installing the module Microsoft.Graph.Authentication as current user scope"
	try {
		Install-Module -Name Microsoft.graph.authentication -Scope CurrentUser -AllowClobber
		Import-Module Microsoft.Graph.Authentication	
	}
	catch {
		Write-Output "Could not load the necessary module Microsoft.Graph.Authentication, so can not proceed."
	}	
}

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
All permissions reference
Ref: https://learn.microsoft.com/en-us/graph/permissions-reference
#>

$requiredscopes = @(
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

if (Get-MgContext) {	
	# Disconnect current connection before starting
	Disconnect-MGGraph
	Connect-MGGraph -NoWelcome -scopes $requiredscopes

}
else {
	# Connect with tenant if no existing connection
	Connect-MGGraph -NoWelcome -scopes $requiredscopes
}

$ConnectionDetail = Get-MgContext | Select-Object Account, TenantId, Environment, @{l = "Scopes"; e = { $_.Scopes -join "," } }
$ServicePlans = ((Invoke-mgGraphRequest -Uri "https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuPartNumber,skuId,prepaidUnits,consumedUnits,servicePlans").value | Where-Object { $_.ServicePlans.ProvisioningStatus -eq "Success" }).ServicePlans.ServicePlanName

If ($ServicePlans -contains "AAD_Premium_P2") {
	$EntraLicense = "Entra ID P2"
}
elseif ($ServicePlans -contains "AAD_Premium") {
	$EntraLicense = "Entra ID P1"
}
else {
	$EntraLicense = "Entra ID Free"
}

# On-Premise configuration
$OnPremConfigDetails = (Invoke-mgGraphRequest -Uri "https://graph.microsoft.com/v1.0/directory/onPremisesSynchronization").value.features | ForEach-Object { [pscustomobject]@{PasswordHashSync = $_.passwordSyncEnabled; passwordWritebackEnabled = $_.passwordWritebackEnabled; cloudPasswordPolicyForPasswordSyncedUsersEnabled = $_.cloudPasswordPolicyForPasswordSyncedUsersEnabled; userWritebackEnabled = $_.userWritebackEnabled; groupWriteBackEnabled = $_.groupWriteBackEnabled; deviceWritebackEnabled = $_.deviceWritebackEnabled; unifiedGroupWritebackEnabled = $_.unifiedGroupWritebackEnabled; directoryExtensionsEnabled = $_.directoryExtensionsEnabled; synchronizeUpnForManagedUsersEnabled = $_.synchronizeUpnForManagedUsersEnabled } }

# Pass through authentication details
$PTAAgentDetail = (Invoke-mgGraphRequest -Uri "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/authentication/agentGroups?`$expand=agents").value.Agents | ForEach-Object { [PSCustomObject]@{machinename = $_.machinename; externalIp = $_.externalIp; status = $_.status; supportedPublishingTypes = $_.supportedPublishingTypes -join "," } }
$PTAEnabled = $PTAAgentDetail.machinename.count -ge 1
$PHSEnabled = $OnPremConfigDetails.PasswordHashSync

# Password protection details
$PasswordProtectionDetails = [PSCustomObject]@{}
((Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/settings").value | Where-Object { $_.displayName -eq "Password Rule Settings" }).values | ForEach-Object { $PasswordProtectionDetails | Add-Member -NotePropertyName $_.Name -NotePropertyValue $_.value }

# Get app ID for Entra ID Connected registered app
$app = ((Invoke-MgGraphRequest -uri "https://graph.microsoft.com/v1.0/applications").value | Where-Object { $_.displayName -eq "Tenant Schema Extension App" }) | ForEach-Object { [pscustomobject]@{id = $_.id; appid = $_.appid } }
$DirectoryExtensions = (invoke-mggraphrequest -uri "https://graph.microsoft.com/v1.0/applications/$($app.id)/extensionProperties?`$select=name").value.name | ForEach-Object { $_.replace("extension_" + $app.appid.replace("-", "") + "_", "") }

$TenantBasicDetail = (Invoke-mgGraphRequest -Uri "https://graph.microsoft.com/v1.0/organization").value | ForEach-Object { [pscustomobject]@{DisplayName = $_.displayName; createdDateTime = $_.createdDateTime; countryLetterCode = $_.countryLetterCode; TenantID = $_.Id; OnPremisesSyncEnabled = $_.OnPremisesSyncEnabled; OnPremisesLastSyncDateTime = $_.OnPremisesLastSyncDateTime; TenantType = $_.TenantType; EntraID = $EntraLicense; Domain = (($_.VerifiedDomains | Where-Object { $_.Name -notlike "*.Onmicrosoft.com" }) | ForEach-Object { "$($_.Type):$($_.Name)" } ) -join "``n"; SecurityDefaults = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/policies/identitySecurityDefaultsEnforcementPolicy")["isEnabled"] ; PTAEnbled = $PTAEnabled; PHSEnabled = $PHSEnabled; passwordWritebackEnabled = $OnPremConfigDetails.passwordWritebackEnabled; DirectoryExtensions = ($DirectoryExtensions -join ","); groupWriteBackEnabled = $OnPremConfigDetails.groupWriteBackEnabled } }
$EnabledAuthMethods = (Invoke-mgGraphRequest -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy").authenticationMethodConfigurations | ForEach-Object { [pscustomobject]@{AuthMethodType = $_.Id; State = $_.state } }

$MonitoredPriviledgedRoles = ("Global Administrator", "Global Reader", "Security Administrator", "Privileged Authentication Administrator", "User Administrator")
$ActivatedRoles = (Invoke-mgGraphRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles").value | ForEach-Object { [pscustomobject]@{Id = $_.Id; DisplayName = $_.displayName } }

$RoleDetail = ForEach ($privilegedRole in $MonitoredPriviledgedRoles) {	
	$RoleID = ($ActivatedRoles | Where-Object { $_.DisplayName -eq $privilegedRole }).Id	
	If ($privilegedRole -in $ActivatedRoles.DisplayName) {
		$name = $privilegedRole
		$Count = (Invoke-mgGraphRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$RoleID/members" -Headers @{ "ConsistencyLevel" = "eventual" }).value.displayname.count
		
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

# RBAC roles details
$Roles = ((Invoke-mggraphRequest -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions").value | ForEach-Object { [pscustomobject]@{id = $_.id; isBuiltIn = $_.isBuiltIn; displayName = $_.displayName; Enabled = $_.isEnabled; rolePermissions = ($_.rolePermissions.allowedResourceActions -join "`n") } })
$RBACRoles = $Roles | Where-Object { $_.isBuiltIn -eq $false }

# PIM Roles
$ActivePIMAssignments = (invoke-mggraphRequest -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules?`$expand=principal").value | ForEach-Object { $roledef = $_.RoleDefinitionId; [pscustomobject]@{RoleName = ($Roles | Where-Object { $_.id -eq $roledef }).displayName; PrincipalName = $_.Principal.displayName; PrincipalType = ($_.Principal."@odata.type").replace("`#microsoft.graph.", ""); state = $_.assignmenttype; membership = $_.memberType; StartTime = $_.scheduleInfo.StartDateTime; EndTime = $_.scheduleInfo.expiration.enddatetime; type = $_.scheduleInfo.expiration.type; directoryScopeId = $_.directoryScopeId } } 
$ElligiblePIMAssignments = (invoke-mggraphRequest -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$expand=principal").value | ForEach-Object { $roledef = $_.RoleDefinitionId; [pscustomobject]@{RoleName = ($Roles | Where-Object { $_.id -eq $roledef }).displayName; PrincipalName = $_.Principal.displayName; PrincipalType = ($_.Principal."@odata.type").replace("`#microsoft.graph.", ""); state = $_.assignmenttype; membership = $_.memberType; StartTime = $_.scheduleInfo.StartDateTime; EndTime = $_.scheduleInfo.expiration.enddatetime; type = $_.scheduleInfo.expiration.type; directoryScopeId = $_.directoryScopeId } } 
$PIMRoles = $ActivePIMAssignments + $ElligiblePIMAssignments

$Accessreviews = (invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions").value | ForEach-Object { [pscustomobject]@{AccessReviewName = $_.displayName; status = $_.status; scope = if ($_.instanceEnumerationScope.query) { (invoke-mggraphrequest -uri $_.instanceEnumerationScope.query).displayName -join "," } else { (Invoke-MgGraphRequest -uri $_.scope.resourceScopes.query).DisplayName -join "," }; createdDateTime = $_.createdDateTime; lastModifiedDateTime = $_.lastModifiedDateTime; descriptionForReviewers = $_.descriptionForReviewers; descriptionForAdmins = $_.descriptionForAdmins } }

# License summary 
$LicenseDetail = (Invoke-mgGraphRequest -Uri "https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuPartNumber,skuId,prepaidUnits,consumedUnits,servicePlans").value | ForEach-Object { [pscustomobject]@{Skuid = $_.skuId; skuPartNumber = $_.skuPartNumber; activeUnits = $_.prepaidUnits["enabled"]; consumedUnits = $_.consumedUnits; availableUnits = ($_.prepaidUnits["enabled"] - $_.consumedUnits) } }
$CASPolicyDetail = (Invoke-mgGraphRequest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" ).value | ForEach-Object { [pscustomobject]@{DisplayName = $_.displayName; State = $_.state; createdDateTime = $_.createdDateTime; modifiedDateTime = $_.modifiedDateTime } }

# Collaberation settings
$Collabsettings = (invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/policies/authorizationPolicy/authorizationPolicy").defaultUserRolePermissions

# Identtity Secure score recommendations
$Controls = (invoke-mggraphRequest -Uri "https://graph.microsoft.com/v1.0/Security/secureScoreControlProfiles?`$filter=controlCategory eq 'Identity'").value | ForEach-Object { [pscustomobject]@{controlCategory = $_.controlCategory; id = $_.id; title = $_.title; service = $_.service; userImpact = $_.userImpact; threats = ($_.threats -join ","); actionType = $_.actionType; remediation = $_.remediation; maxScore = $_.maxScore; deprecated = $_.deprecated } }
$Scores = (invoke-mggraphRequest -Uri "https://graph.microsoft.com/v1.0/Security/secureScores").value | ForEach-Object { [pscustomobject]@{createdDateTime = $_.createdDateTime; currentScore = $_.currentScore; maxScore = $_.maxScore; controlScores = $_.controlScores; licensedUserCount = $_.licensedUserCount; activeUserCount = $_.activeUserCount } } 

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

# Create HTML table elements
$EnabledAuthSummary = ($EnabledAuthMethods | Sort-Object State -Descending | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Auth Methods Summary : $($TenantBasicDetail.DisplayName)</h2>")
$RoleSummary = ($RoleDetail | Sort-Object Count | ConvertTo-Html -As Table  -Fragment -PreContent "<h2>Priviledged Entra Role Summary: $($TenantBasicDetail.DisplayName)</h2>")
$TenantSummary = ($TenantBasicDetail | ConvertTo-Html -As List -Fragment -PreContent "<h2>Entra Summary: $forest</h2>") -replace "`n", "<br>"

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

if ($PasswordProtectionDetails) {
	$PasswordProtectionSummary = ($PasswordProtectionDetails | ConvertTo-Html -As List -Fragment -PreContent "<h2>Password Protection Summary: $($TenantBasicDetail.DisplayName)</h2>") -replace "`n", "<br>"
}

$LicenseSummary = $LicenseDetail | ConvertTo-Html -As Table -Fragment -PreContent "<h2>License Summary: $($TenantBasicDetail.DisplayName)</h2>"
$CASSummary = $CASPolicyDetail | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Conditional Access Policy Summary: $($TenantBasicDetail.DisplayName)</h2>"
$SecureScoreReportSummary = $SecureScoreReport | ConvertTo-Html -As Table -Fragment -PreContent "<h2>Identity - Secure Scores Summary: $($TenantBasicDetail.DisplayName)</h2>"
$ReportRaw = ConvertTo-HTML -Body "$TenantSummary $PTAAgentSummary $LicenseSummary $RoleSummary $RBACRolesSummary $PIMRolesSummary $AccessreviewSummary $PasswordProtectionSummary $EnabledAuthSummary $CASSummary $SecureScoreReportSummary" -Head $header -Title "Report on Entra ID: $($TenantBasicDetail.Displayname)" -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date) $CopyRightInfo </p>"

# To preseve HTMLformatting in description
$ReportRaw = [System.Web.HttpUtility]::HtmlDecode($ReportRaw)

$ReportRaw | Out-File $ReportPath
Invoke-item $ReportPath
